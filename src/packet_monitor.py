import logging
import threading
import time
import ipaddress
from typing import Any, Optional, List, Tuple, Callable, FrozenSet

from src.types import BridgeName, EntryType, IPv4Address, MACAddress, NodeID, OFPort, SnoopOrigin
from src.config import Config
from src.models import InstanceStore, IPEntryStore, IPEntry, InstanceInfo, _entry_key, is_snoopable
from src.netlink import NetlinkInfo, PeerTracker
from src.ovs_manager import OVSManager
from src.of_manager import OFManager
from src.logging_util import DEBUG_ARP_REPLY, NO_DEDUP_ATTR
from src.packet_monitor_arp import (
    build_arp_packet as build_arp_packet_bytes,
    build_arp_reply_packet as build_arp_reply_packet_bytes,
)

try:
    from scapy.all import Ether, ARP, UDP, BOOTP, DHCP, Dot1Q, sniff, sendp
except ImportError:
    sniff = None
    sendp = None
    Dot1Q = None

class PacketMonitor:
    """Scapy ARP/DHCP snooping on multiple bridges."""

    def __init__(
        self,
        instances: InstanceStore,
        entries: IPEntryStore,
        log: logging.Logger,
        ovs_manager: OVSManager,
        of_manager: OFManager,
        config: Config,
        node_id: Optional[NodeID] = None,
        peer_tracker: Optional[PeerTracker] = None,
        netlink: Optional[NetlinkInfo] = None,
        get_local_vlans: Optional[Callable[[], FrozenSet[int]]] = None,
        is_local_migration_confirmed: Optional[Callable[[MACAddress], bool]] = None,
        on_owner_change: Optional[
            Callable[[IPv4Address, BridgeName, Optional[int], Optional[NodeID], Optional[NodeID]], None]
        ] = None,
    ) -> None:
        self.config = config
        self._peer_tracker = peer_tracker
        self.bridges = config.bridges
        self.instances = instances
        self.entries = entries
        self.log = log
        self.ovs_manager = ovs_manager
        self.of_manager = of_manager
        self.snoop_bridge = config.snoop_bridge
        self.node_id: NodeID = node_id or NodeID("")
        self._flood_min_interval = config.flood_min_interval
        # Parse exclude subnets
        self._exclude_nets: list[Any] = []
        for cidr in config.exclude_subnets:
            try:
                self._exclude_nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                log.warning("invalid exclude-subnet %s, ignoring", cidr)
        self._stop = threading.Event()
        # Tracking sets for one-time logging
        self._skipped_host_local: set[tuple[str, str]] = set()
        self._skipped_tap_mac: set[str] = set()
        self._skipped_bridge_mac: set[str] = set()
        self._last_update_per_ip: dict[str, float] = {}
        # ARP flood detection (per-bridge 1s window)
        self._arp_flood_window: dict[str, float] = {}
        self._arp_flood_count: dict[str, int] = {}
        self._arp_flood_sources: dict[str, dict[str, int]] = {}
        # Shared netlink helper
        self._netlink = netlink or NetlinkInfo(self.bridges, config)
        self._last_snoop_time: float = 0.0  # for snoop-silence watchdog
        self._get_local_vlans = get_local_vlans
        self._is_local_migration_confirmed = is_local_migration_confirmed
        self._on_owner_change = on_owner_change
        self._arp_reply_attempt_count: int = 0
        self._arp_reply_sent_count: int = 0
        self._arp_reply_failed_count: int = 0
        self._arp_reply_skipped_count: int = 0
        self._arp_reinject_sent_count: int = 0
        self._arp_reinject_failed_count: int = 0
        self._arp_mac_mismatch_count: int = 0
        self._migration_local_refused_count: int = 0
        self._migration_local_confirmed_count: int = 0

    def _emit_owner_change(
        self,
        ip: IPv4Address,
        bridge: BridgeName,
        vlan: Optional[int],
        old_owner: Optional[NodeID],
        new_owner: Optional[NodeID],
    ) -> None:
        """Call ownership-change callback if owner changed."""
        if self._on_owner_change is None:
            return
        if old_owner == new_owner:
            return
        self._on_owner_change(ip, bridge, vlan, old_owner, new_owner)

    def get_last_snoop_time(self) -> float:
        """Last time any snoop updated/created an entry; 0 if never (for watchdog)."""
        return self._last_snoop_time

    def arp_counters(self) -> dict[str, int]:
        """Return ARP reply and reinject counters.

        Args:
            None.

        Returns:
            Counter mapping for reply/reinject operations.
        """
        return {
            "reply_attempt": self._arp_reply_attempt_count,
            "reply_sent": self._arp_reply_sent_count,
            "reply_failed": self._arp_reply_failed_count,
            "reply_skipped": self._arp_reply_skipped_count,
            "reinject_sent": self._arp_reinject_sent_count,
            "reinject_failed": self._arp_reinject_failed_count,
            "mac_mismatch": self._arp_mac_mismatch_count,
        }

    def migration_counters(self) -> dict[str, int]:
        """Return migration decision counters from local snoop path.

        Args:
            None.

        Returns:
            Counter mapping for local migration checks.
        """
        return {
            "local_refused": self._migration_local_refused_count,
            "local_confirmed": self._migration_local_confirmed_count,
        }

    def stop(self) -> None:
        self._stop.set()

    def inject_config_ips(self) -> None:
        """Feed LXC config IPs (net0: ip=...) into snoop store as origin=proxmox."""
        for mac, info in self.instances.items():
            if info.ip is None:
                continue
            self._update_snoop_entry(
                mac, info.ip, info.bridge, info.type, "proxmox", info.vlan, info
            )

    def _resolve_in_port(
        self,
        bridge: BridgeName,
        reply_node: Optional[NodeID],
        log_ip: Optional[IPv4Address] = None,
        vlan: Optional[int] = None,
    ) -> tuple[Optional[str], str]:
        """Resolve OVS in_port for ARP reply: VXLAN port for remote, patch port for local.

        Args:
            bridge: target bridge
            reply_node: node where target IP lives
            log_ip: IP for warning messages
            vlan: VLAN for local lookup (patch port tag)

        Returns:
            (in_port, port_name); in_port None = skip send
        """
        if reply_node and reply_node != self.node_id:
            node_map = self.ovs_manager.get_bridge_node_to_ofport(bridge)
            if reply_node in node_map:
                return node_map[reply_node]
            if self.config.arp_reply_local_fallback:
                self.log.warning(
                    "arp reply for %s: no VXLAN port for node=%s on %s, would use LOCAL (skip, breaks FDB)",
                    log_ip, reply_node, bridge,
                )
                return None, "LOCAL"
            self.log.warning(
                "arp reply for %s: no VXLAN port for node=%s on %s, skipping",
                log_ip, reply_node, bridge,
            )
            return None, ""
        # Local: use patch port to local bridge if known, else skip (LOCAL breaks FDB)
        bridges_with_ips = self._netlink.get_bridge_names_with_ips()
        local_map = self.ovs_manager.get_bridge_vlan_to_local_port(self.bridges, bridges_with_ips)
        br_map = local_map.get(str(bridge), {})
        ofport, port_name = br_map.get(vlan) or br_map.get(None) or (None, "LOCAL")
        if not ofport and br_map:
            # untagged request: use any patch port so FDB still gets updated
            first_vlan = min((k for k in br_map if k is not None), default=None) or next(iter(br_map))
            ofport, port_name = br_map[first_vlan]
        if ofport:
            return ofport, port_name
        return None, "LOCAL"

    def _build_arp_packet(
        self,
        op: int,
        src_mac: str,
        src_ip: str,
        dst_mac: str,
        dst_ip: str,
        vlan: Optional[int],
    ) -> bytes:
        """Build ARP packet bytes (op 1=request, 2=reply)."""
        return build_arp_packet_bytes(Ether, Dot1Q, ARP, op, src_mac, src_ip, dst_mac, dst_ip, vlan)

    def _build_arp_reply_packet(
        self,
        pkt: Any,
        reply_mac: MACAddress,
        requested_ip: IPv4Address,
        reply_vlan: Optional[int],
    ) -> tuple[bytes, Optional[int]]:
        """Build ARP reply packet bytes from request pkt; return (raw_bytes, vlan_id)."""
        return build_arp_reply_packet_bytes(Ether, Dot1Q, ARP, pkt, reply_mac, requested_ip, reply_vlan)

    @staticmethod
    def _parse_ipv4(raw_ip: Any) -> Optional[IPv4Address]:
        """Parse raw IPv4 text and return normalized IPv4Address."""
        if raw_ip is None:
            return None
        ip_s = str(raw_ip).strip()
        if not ip_s:
            return None
        try:
            return IPv4Address(str(ipaddress.IPv4Address(ip_s)))
        except ValueError:
            return None

    def _get_arp_reply_entry(
        self, requested_ip: IPv4Address, bridge: BridgeName, req_vlan: Optional[int]
    ) -> Optional[IPEntry]:
        """Lookup any active entry for (ip, bridge); reply is sent on req_vlan regardless of snooped vlan."""
        now = time.time()
        return self.entries.get_any_active_for_bridge_ip(
            requested_ip, bridge, now, self.config.mesh_ttl
        )

    def _do_arp_reply(self, pkt: Any, bridge: BridgeName, label: str) -> bool:
        """Send ARP reply for who-has in pkt; return True if sent."""
        if ARP not in pkt or pkt[ARP].op != 1 or not getattr(pkt[ARP], "pdst", None) or Ether not in pkt:
            return False
        requested_ip = self._parse_ipv4(getattr(pkt[ARP], "pdst", None))
        if not requested_ip:
            return False
        req_vlan: Optional[int] = None
        if Dot1Q and Dot1Q in pkt:
            try:
                req_vlan = int(pkt[Dot1Q].vlan)
            except (AttributeError, TypeError, ValueError):
                pass
        reply_entry = self._get_arp_reply_entry(requested_ip, bridge, req_vlan)
        if not reply_entry:
            self._arp_reply_skipped_count += 1
            return False
        entry_vlan_norm = None if (reply_entry.vlan is None or reply_entry.vlan == 0) else int(reply_entry.vlan)
        is_local = reply_entry.node is not None and reply_entry.node == self.node_id
        # No learned vlan -> visible on all vlans (strict_vlan only for IPs with a vlan)
        if entry_vlan_norm is None:
            match_vlan = None
            reply_vlan = req_vlan
        elif is_local:
            match_vlan = entry_vlan_norm
            reply_vlan = req_vlan
        else:
            rv = self.config.arp_reply_remote_vlan
            # Default remote behaviour: use remote vlan when set, else entry vlan.
            match_vlan = rv if rv is not None else entry_vlan_norm
            reply_vlan = rv if rv is not None else req_vlan
            # Optional localization: if this vlan is local, treat like local (use entry vlan).
            if self.config.arp_reply_localize_vlan and self._get_local_vlans is not None:
                try:
                    local_vlans = self._get_local_vlans()
                except Exception:
                    local_vlans = frozenset()
                # Guard invalid callback result.
                try:
                    is_local_vlan = entry_vlan_norm in local_vlans
                except TypeError:
                    is_local_vlan = False
                if is_local_vlan:
                    match_vlan = entry_vlan_norm
                    reply_vlan = req_vlan
        if self.config.arp_reply_strict_vlan:
            allow = (match_vlan is None) or (req_vlan == match_vlan) or (
                req_vlan is None and (match_vlan is None or self.config.arp_reply_no_vlan)
            )
        else:
            allow = True
        if not allow:
            if self.config.debug_flags & DEBUG_ARP_REPLY:
                self.log.debug(
                    "arp reply who-has %s on %s: skip, vlan mismatch request_vlan=%s expected_match=%s (local=%s)",
                    requested_ip,
                    bridge,
                    req_vlan,
                    match_vlan,
                    is_local,
                    extra={NO_DEDUP_ATTR: True},
                )
            self._arp_reply_skipped_count += 1
            return False
        reply_mac = reply_entry.mac
        raw_bytes, vid = self._build_arp_reply_packet(pkt, reply_mac, requested_ip, reply_vlan)
        in_port, port_name = self._resolve_in_port(
            bridge, reply_entry.node, requested_ip, reply_vlan
        )
        if not in_port:
            if port_name == "LOCAL":
                self.log.debug(
                    "arp reply who-has %s on %s: local bridge IP, skip (do not send with LOCAL port)",
                    requested_ip, bridge,
                    extra={"no_dedup": True},
                )
            self._arp_reply_skipped_count += 1
            return False
        reg = self.config.arp_reply_set_register
        actions = "output:NORMAL"
        if reg:
            actions = f"load:{reg}->NXM_NX_REG0[]," + actions
        self._arp_reply_attempt_count += 1
        ok = self.of_manager.send_packet_out(
            bridge, raw_bytes, in_port=OFPort(in_port), actions=actions, timeout=1,
        )
        if ok:
            self._arp_reply_sent_count += 1
        else:
            self._arp_reply_failed_count += 1
        if ok and (self.config.debug_flags & DEBUG_ARP_REPLY):
            self.log.debug(
                "arp reply sent who-has %s => %s on %s reply_vlan=%s in_port=%s %s (%s) request_vlan=%s",
                requested_ip, reply_mac, bridge, vid, in_port, port_name, label, req_vlan,
                extra={NO_DEDUP_ATTR: True},
            )
        return ok

    def _send_arp_reply_fast(self, pkt: Any, bridge: BridgeName) -> bool:
        """ARP fast path: reply immediately before snoop processing."""
        if not self.config.arp_reply:
            return False
        return self._do_arp_reply(pkt, bridge, "fast path")

    def _build_arp_request_packet(
        self,
        local_mac: MACAddress,
        local_ip: IPv4Address,
        remote_mac: MACAddress,
        remote_ip: IPv4Address,
        vlan: Optional[int] = None,
    ) -> bytes:
        """Build ARP request (who-has) packet bytes for refresh."""
        return self._build_arp_packet(1, local_mac, local_ip, remote_mac, remote_ip, vlan)

    def send_arp_refresh_request(
        self,
        local_mac: MACAddress,
        local_ip: IPv4Address,
        remote_mac: MACAddress,
        remote_ip: IPv4Address,
        bridge: BridgeName,
        remote_node: Optional[NodeID],
        vlan: Optional[int] = None,
    ) -> bool:
        """Send ARP request via correct OVS port (same path as ARP reply)."""
        raw_bytes = self._build_arp_request_packet(local_mac, local_ip, remote_mac, remote_ip, vlan)
        in_port, port_name = self._resolve_in_port(bridge, remote_node, remote_ip, vlan=vlan)
        vlan_str = str(vlan) if vlan is not None else "-"
        if not in_port:
            if port_name == "LOCAL":
                self.log.debug(
                    "arp-refresh who-has %s => %s on %s vlan=%s in_port=LOCAL (LOCAL) - local bridge IP, skip",
                    remote_ip, remote_mac, bridge, vlan_str,
                )
            return False
        ok = self.of_manager.send_packet_out(
            bridge, raw_bytes, in_port=OFPort(in_port), actions="output:NORMAL", timeout=1,
        )
        if ok:
            self.log.debug(
                "arp-refresh who-has %s => %s on %s vlan=%s in_port=%s (%s)",
                remote_ip, remote_mac, bridge, vlan_str, in_port, port_name,
            )
        return ok

    def _parse_packet_info(
        self, pkt: Any, bridge: BridgeName
    ) -> Optional[tuple[MACAddress, IPv4Address, SnoopOrigin, Optional[int]]]:
        """Extract MAC, IP, protocol type and VLAN from packet.

        Args:
            pkt: incoming packet
            bridge: bridge name (for logging)

        Returns:
            (mac, ip, ptype, vlan_id) tuple or None if packet should be ignored
        """
        mac: Optional[MACAddress] = None
        ip: Optional[IPv4Address] = None
        ptype: Optional[SnoopOrigin] = None
        vlan_id: Optional[int] = None
        if Dot1Q and Dot1Q in pkt:
            try:
                vlan_id = int(pkt[Dot1Q].vlan)
            except (AttributeError, TypeError, ValueError):
                pass
        if ARP in pkt and pkt[ARP].op in (1, 2):
            arp = pkt[ARP]
            # Only Ethernet/IPv4 ARP (hwtype=1, ptype=0x0800)
            if arp.hwtype != 1 or arp.ptype != 0x0800:
                return None
            ptype = "arp"
            raw_mac = (pkt[Ether].src if Ether in pkt else arp.hwsrc) or ""
            mac = MACAddress(raw_mac) if raw_mac else None
            # Ether.src must match ARP.hwsrc (proxy ARP / spoofing guard)
            hwsrc = str(getattr(arp, "hwsrc", "") or "").strip().lower()
            if mac and hwsrc and mac.lower() != hwsrc:
                self._arp_mac_mismatch_count += 1
                self.log.info(
                    "arp mac mismatch bridge=%s ether=%s hwsrc=%s (skip)",
                    bridge, mac, hwsrc,
                )
                return None
            psrc = str(getattr(arp, "psrc", None) or "").strip()
            # Skip ARP probes (psrc=0.0.0.0) and broadcast source
            if psrc and psrc not in ("0.0.0.0", "255.255.255.255"):
                ip = self._parse_ipv4(psrc)
        elif BOOTP in pkt and UDP in pkt and pkt[UDP].dport in (67, 68):
            ptype = "dhcp"
            mac = self._parse_bootp_chaddr(pkt[BOOTP])
            if not mac and Ether in pkt:
                raw_mac = pkt[Ether].src or ""
                mac = MACAddress(raw_mac) if raw_mac else None
            yiaddr = getattr(pkt[BOOTP], "yiaddr", None)
            ciaddr = getattr(pkt[BOOTP], "ciaddr", None)
            if yiaddr and str(yiaddr) != "0.0.0.0":
                ip = self._parse_ipv4(yiaddr)
            elif ciaddr and str(ciaddr) != "0.0.0.0":
                ip = self._parse_ipv4(ciaddr)
        if not mac or not ip or not ptype:
            return None
        return mac, ip, ptype, vlan_id

    def _parse_bootp_chaddr(self, bootp_pkt: Any) -> Optional[MACAddress]:
        """Parse BOOTP chaddr and return client MAC.

        Args:
            bootp_pkt: Scapy BOOTP packet.

        Returns:
            Client MAC from chaddr or None.
        """
        # Only Ethernet (htype=1): other types use different address formats
        if getattr(bootp_pkt, "htype", 1) != 1:
            return None
        raw_chaddr = getattr(bootp_pkt, "chaddr", None)
        if not raw_chaddr:
            return None
        mac_bytes: Optional[bytes] = None
        if isinstance(raw_chaddr, (bytes, bytearray)):
            if len(raw_chaddr) < 6:
                return None
            mac_bytes = bytes(raw_chaddr[:6])
        elif isinstance(raw_chaddr, str):
            chaddr = raw_chaddr.strip().lower()
            if ":" in chaddr:
                parts = chaddr.split(":")
                if len(parts) < 6:
                    return None
                try:
                    mac_bytes = bytes(int(part, 16) for part in parts[:6])
                except ValueError:
                    return None
        if not mac_bytes:
            return None
        return MACAddress(":".join(f"{byte:02x}" for byte in mac_bytes))

    def _check_arp_flood(self, bridge: BridgeName, mac: MACAddress) -> None:
        """Track ARP rate per bridge; log warning + top source MACs when over threshold.

        Args:
            bridge: bridge name
            mac: source MAC of this ARP packet
        """
        threshold = self.config.arp_flood_threshold
        if threshold <= 0:
            return
        now = time.time()
        br = str(bridge)
        if br not in self._arp_flood_window:
            self._arp_flood_window[br] = now
            self._arp_flood_count[br] = 0
            self._arp_flood_sources[br] = {}
        self._arp_flood_count[br] += 1
        m = mac.lower()
        self._arp_flood_sources[br][m] = self._arp_flood_sources[br].get(m, 0) + 1
        if now - self._arp_flood_window[br] < 1.0:
            return
        count = self._arp_flood_count[br]
        if count >= threshold:
            top = sorted(
                self._arp_flood_sources[br].items(),
                key=lambda x: -x[1],
            )[:3]
            top_str = ", ".join(f"{m}({c})" for m, c in top)
            self.log.warning(
                "ARP flood on %s: %d pkt/s (threshold %d); top sources: %s",
                bridge, count, threshold, top_str,
            )
        self._arp_flood_window[br] = now
        self._arp_flood_count[br] = 0
        self._arp_flood_sources[br] = {}

    def _is_valid_snoop(self, mac: MACAddress, ip: IPv4Address, bridge: BridgeName) -> bool:
        """Validate whether packet should be snooped.

        Args:
            mac: source MAC
            ip: source IP
            bridge: bridge name

        Returns:
            True if packet is valid for snooping
        """
        # Skip tap/veth interface MACs
        if self._netlink.is_tap_mac(mac):
            if mac.lower() not in self._skipped_tap_mac:
                self._skipped_tap_mac.add(mac.lower())
                self.log.info("skipping tap/veth interface mac=%s ip=%s", mac, ip)
            return False
        # IP must be in snooped bridge subnet
        if not self._netlink.ip_in_bridge_subnets(ip):
            self.log.warning("reject ip=%s mac=%s bridge=%s (not in any snooped bridge subnet)", ip, mac, bridge)
            return False
        # Skip excluded subnets
        try:
            ip_obj = ipaddress.ip_address(ip)
            for net in self._exclude_nets:
                if ip_obj in net:
                    return False
        except ValueError:
            pass
        return True

    def _classify_entry(
        self, mac: MACAddress, ip: IPv4Address, instance: Optional[InstanceInfo]
    ) -> Optional[EntryType]:
        """Classify snooped packet as bridge/VM/LXC/foreign.

        Args:
            mac: source MAC
            ip: source IP
            instance: instance info if MAC is VM/LXC

        Returns:
            "bridge" when netlink-verified local bridge MAC on its own IP,
            instance type when MAC is a local VM/LXC,
            "foreign" for any other MAC on our bridge subnet (tracked locally, not meshed),
            or None when packet should be skipped.
        """
        # Strict bridge: our bridge MAC bound to its own bridge IP.
        if self._netlink.is_bridge_mac(mac):
            if self._netlink.bridge_mac_for_ip(ip) == mac.lower():
                return "bridge"
            if mac.lower() not in self._skipped_bridge_mac:
                self._skipped_bridge_mac.add(mac.lower())
                self.log.debug("skip bridge mac=%s for non-bridge ip=%s", mac, ip)
            return None
        if instance:
            return instance.type or "vm"
        if not self.snoop_bridge:
            return None
        if self._netlink.is_host_local(ip):
            if not getattr(self.config, "snoop_host_local", False):
                key = (mac, ip)
                if key not in self._skipped_host_local:
                    self._skipped_host_local.add(key)
                    self.log.info("skipping host-local address %s mac=%s", ip, mac)
                return None
        # Non-bridge MAC impersonating a bridge IP: drop.
        expected_mac = self._netlink.bridge_mac_for_ip(ip)
        if expected_mac is not None and mac.lower() != expected_mac:
            if mac.lower() not in self._skipped_bridge_mac:
                self._skipped_bridge_mac.add(mac.lower())
                self.log.info(
                    "skip non-bridge mac=%s ip=%s (bridge mac=%s)", mac, ip, expected_mac,
                )
            return None
        # not classified otherwise
        return "foreign"

    def _log_local_migration_denied(
        self,
        entry_type: EntryType,
        ip: IPv4Address,
        mac: MACAddress,
        bridge: BridgeName,
        vlan_id: Optional[int],
        current_node: Optional[NodeID],
        local_node: Optional[NodeID],
    ) -> None:
        """Log denied local migration with severity by entry type.

        Args:
            entry_type: Classified entry type ("bridge", "qemu", "lxc", etc.).
            ip: Candidate IP for ownership takeover.
            mac: Candidate MAC for ownership takeover.
            bridge: Bridge name for the snooped packet.
            vlan_id: VLAN id (None for untagged).
            current_node: Current owner node id.
            local_node: Local node id attempting claim.
        """
        msg = (
            "ALERT migration denied ip=%s mac=%s bridge=%s vlan=%s "
            "current_node=%s local_node=%s reason=local_confirm_failed"
        )
        log_fn = self.log.error if is_snoopable(entry_type) else self.log.warning
        log_fn(msg, ip, mac, bridge, vlan_id, current_node, local_node)

    def _update_snoop_entry(
        self,
        mac: MACAddress,
        ip: IPv4Address,
        bridge: BridgeName,
        entry_type: EntryType,
        ptype: SnoopOrigin,
        vlan_id: Optional[int],
        instance: Optional[InstanceInfo],
    ) -> None:
        """Update or create IP entry in store (keyed by ip, bridge, vlan)."""
        now = time.time()
        vlan_n = (None if vlan_id is None or vlan_id == 0 else vlan_id)
        # VLAN allow/block filter (0 = untagged)
        vlan_for_filter = vlan_n if vlan_n is not None else 0
        if self.config.snoop_vlan_set is not None and vlan_for_filter not in self.config.snoop_vlan_set:
            return
        if vlan_for_filter in self.config.no_snoop_vlan_set:
            return
        # One snooped VLAN per (ip, bridge); don't overwrite remote when seen on local vlan
        ttl = self.config.mesh_ttl
        node = NodeID(self.node_id) if self.node_id else None
        for _key, e in self.entries.get_entries_for_bridge_ip(ip, bridge):
            if not e.is_active(now, ttl):
                continue
            key_vlan = _key[2]
            if key_vlan != vlan_n:
                if e.node != NodeID(self.node_id):
                    # Confirmed local migration can bypass this early return.
                    if (
                        instance is not None
                        and e.mac == mac
                        and self.config.verify_local_migration
                        and self._is_local_migration_confirmed is not None
                    ):
                        if self._is_local_migration_confirmed(mac):
                            self._migration_local_confirmed_count += 1
                            try:
                                self.entries.update(_key, expired=now)
                            except KeyError:
                                pass
                            self.log.info(
                                "snoop ip=%s mac=%s bridge=%s vlan=%s confirmed local claim from remote node=%s old_vlan=%s",
                                ip,
                                mac,
                                bridge,
                                vlan_n,
                                e.node,
                                key_vlan,
                            )
                            continue
                        self._log_local_migration_denied(entry_type, ip, mac, bridge, vlan_n, e.node, node)
                        self._migration_local_refused_count += 1
                        return
                    self.log.info(
                        "snoop ip=%s mac=%s bridge=%s vlan=%s kept remote node=%s (cannot claim as local)",
                        ip,
                        mac,
                        bridge,
                        key_vlan,
                        e.node,
                    )
                    return  # remote VM on our vlan, don't overwrite
                return  # we already have this IP on another vlan
        cur = self.entries.get(ip, bridge, vlan_n)
        changed = cur is None or cur.mac != mac
        rate_key = f"{ip}|{bridge}|{vlan_n}"
        last_ts = self._last_update_per_ip.get(rate_key, 0)
        if not changed and (now - last_ts) < self._flood_min_interval:
            return
        if changed:
            self._last_update_per_ip[rate_key] = now
        origins = list(cur.snoop_origin) if cur and cur.snoop_origin else []
        if ptype and ptype not in origins:
            origins.append(ptype)
            origins.sort()
        # Local snoop: claim node=self (create or VM moved to us)
        if changed:
            if cur is not None and cur.mac != mac:
                self.log.warning("same ipv4 %s mac %s -> %s, overwriting", ip, cur.mac, mac)
            if cur is not None and cur.node is not None and node is not None and cur.node != node:
                self.log.warning(
                    "IP %s node ownership changed %s -> %s bridge=%s vlan=%s",
                    ip,
                    cur.node,
                    node,
                    bridge,
                    vlan_n,
                )
                self._emit_owner_change(ip, bridge, vlan_n, cur.node, node)
            entry = IPEntry(
                ipv4=ip,
                mac=mac,
                bridge=bridge,
                type=entry_type,
                last_seen=now,
                snoop_origin=origins,
                node=node,
                vmid=instance.vmid if instance else (cur.vmid if cur else None),
                vlan=vlan_n,
            )
            self.entries.set(entry)
            self._last_snoop_time = now
            self.log.debug(
                "db ip %s local ipv4=%s mac=%s bridge=%s vlan=%s type=%s",
                "added" if cur is None else "updated", ip, mac, bridge, vlan_n, entry_type,
            )
            if is_snoopable(entry_type) or cur is None:
                self.log.info(
                    "snooped ipv4=%s mac=%s bridge=%s vlan=%s type=%s origin=%s",
                    ip, mac, bridge, vlan_n, entry_type, origins,
                )
        else:
            had_expired = cur.expired is not None
            self._last_update_per_ip[rate_key] = now
            takeover_sec = max(0.0, float(self.config.snoop_takeover_sec or 0.0))
            takeover_allowed = cur.can_owner_change(now, node, takeover_sec)
            if cur.node is not None and cur.node != NodeID(self.node_id):
                # Bridge is netlink-verified local; reassert ownership
                # immediately -- a remote owner here means stale/wrong mesh
                # state that must be corrected, not a legit migration.
                if entry_type == "bridge":
                    self.log.warning(
                        "ALERT bridge reclaim ip=%s mac=%s bridge=%s vlan=%s "
                        "from=%s local=%s reason=bridge_cannot_migrate",
                        ip, mac, bridge, vlan_n, cur.node, self.node_id,
                    )
                    takeover_allowed = True
                # Remote-owned bridge (authoritative via mesh): hands off,
                # bridges don't migrate so nothing for us to reclaim here.
                elif cur.type == "bridge":
                    self.log.debug(
                        "recv ip=%s kept remote bridge node=%s mac=%s",
                        ip, cur.node, mac,
                    )
                    self._last_snoop_time = now
                    return
                # VM/LXC/foreign: confirm MAC is local before takeover.
                elif self.config.verify_local_migration and self._is_local_migration_confirmed is not None:
                    if self._is_local_migration_confirmed(mac):
                        self._migration_local_confirmed_count += 1
                        takeover_allowed = True
                    else:
                        self._log_local_migration_denied(
                            entry_type, ip, mac, bridge, vlan_n, cur.node, node
                        )
                        self._migration_local_refused_count += 1
                        self._last_snoop_time = now
                        return
                elif not takeover_allowed:
                    self.log.debug("recv ip=%s kept remote node=%s", ip, cur.node)
                    self._last_snoop_time = now
                    return
            # keep origin node on refresh; don't overwrite remote with self
            update_kw: dict[str, Any] = {
                "last_seen": now,
                "type": entry_type,
                "expired": None,
                "snoop_origin": origins if (cur and origins != cur.snoop_origin) else (cur.snoop_origin if cur else None),
                "vmid": instance.vmid if instance else (cur.vmid if cur else None),
            }
            if cur.node is None or cur.node == NodeID(self.node_id):
                update_kw["node"] = node
            elif takeover_allowed:
                self.log.warning(
                    "ip %s node ownership %s -> %s bridge=%s vlan=%s",
                    ip,
                    cur.node,
                    node,
                    bridge,
                    vlan_n,
                )
                update_kw["node"] = node
                self._emit_owner_change(ip, bridge, vlan_n, cur.node, node)
            self._last_snoop_time = now
            try:
                self.entries.update(_entry_key(cur), **update_kw)
            except KeyError:
                # entry was removed (e.g. expiry cleanup); re-add as new
                entry = IPEntry(
                    ipv4=ip,
                    mac=mac,
                    bridge=bridge,
                    type=entry_type,
                    last_seen=now,
                    snoop_origin=origins,
                    node=node,
                    vmid=instance.vmid if instance else (cur.vmid if cur else None),
                    vlan=vlan_n,
                )
                self.entries.set(entry)
            if had_expired:
                self.log.info(
                    "snooped ipv4=%s mac=%s bridge=%s vlan=%s type=%s origin=%s (re-seen after expiry)",
                    ip, mac, bridge, vlan_n, entry_type, origins,
                )

    def _send_arp_reply(
        self, pkt: Any, bridge: BridgeName, already_sent: bool
    ) -> None:
        """Send ARP reply (slow path) or reinject unknown ARP."""
        if not self.config.arp_reply and not self.config.arp_reinject:
            return
        if ARP not in pkt or pkt[ARP].op != 1 or not hasattr(pkt[ARP], "pdst") or not pkt[ARP].pdst:
            return
        requested_ip = self._parse_ipv4(getattr(pkt[ARP], "pdst", None))
        if not requested_ip:
            return
        req_vlan: Optional[int] = None
        if Dot1Q and Dot1Q in pkt:
            try:
                req_vlan = int(pkt[Dot1Q].vlan)
            except (AttributeError, TypeError, ValueError):
                pass
        found = self._get_arp_reply_entry(requested_ip, bridge, req_vlan)
        if not already_sent and self.config.arp_reply and found and Ether in pkt:
            self._do_arp_reply(pkt, bridge, "slow path")
            return
        # Reinject unknown ARP so it floods
        if self.config.arp_reinject and not found:
            self.log.debug(
                "arp reinject who-has %s bridge=%s vlan=%s (unknown, flood)",
                requested_ip, bridge, req_vlan if req_vlan is not None else "-",
            )
            try:
                raw_orig = bytes(pkt)
                self.of_manager.send_packet_out_async(
                    bridge, raw_orig, in_port=OFPort("LOCAL"), actions="output:NORMAL"
                )
                self._arp_reinject_sent_count += 1
            except Exception as e:
                self._arp_reinject_failed_count += 1
                self.log.debug("arp reinject failed: %s", e)

    def _handle_packet(self, pkt: Any, bridge: BridgeName) -> None:
        """Map ARP/DHCP to IP->MAC on this bridge; update entries."""
        if not pkt:
            return
        try:
            self._handle_packet_impl(pkt, bridge)
        except Exception as e:
            if not self._stop.is_set():
                self.log.debug("packet handle %s: %s", bridge, e)

    def _handle_packet_impl(self, pkt: Any, bridge: BridgeName) -> None:
        """Inner packet handling; may raise on malformed packets."""
        # Fast path: reply to ARP immediately
        arp_replied = self._send_arp_reply_fast(pkt, bridge)
        # Parse packet
        parsed = self._parse_packet_info(pkt, bridge)
        if not parsed:
            try:
                mac_raw = (pkt[Ether].src if Ether in pkt and hasattr(pkt[Ether], "src") else None) or "?"
                ptype_raw = "arp?" if ARP in pkt else ("dhcp?" if BOOTP in pkt else "other")
            except Exception:
                mac_raw, ptype_raw = "?", "?"
            self.log.debug(
                "recv bridge=%s mac=%s ip=? type=%s vlan=- (no parsed)",
                bridge, mac_raw if isinstance(mac_raw, str) else str(mac_raw), ptype_raw,
            )
            return
        mac, ip, ptype, vlan_id = parsed
        self.log.debug(
            "recv bridge=%s mac=%s ip=%s type=%s vlan=%s",
            bridge, mac, ip, ptype, vlan_id if vlan_id is not None else "-",
        )
        if ptype == "arp":
            self._check_arp_flood(bridge, mac)
        # Track for ARP refresh (conversation: source MAC -> target IP)
        if (
            ptype == "arp"
            and self._peer_tracker
            and self.config.arp_refresh
            and ARP in pkt
            and getattr(pkt[ARP], "pdst", None)
        ):
            peer_ip = self._parse_ipv4(getattr(pkt[ARP], "pdst", None))
            if peer_ip:
                self._peer_tracker.track(mac, peer_ip)
        # Validate
        if not self._is_valid_snoop(mac, ip, bridge):
            return
        # Classify
        instance = self.instances.get(mac)
        entry_type = self._classify_entry(mac, ip, instance)
        if not entry_type:
            return
        # VLAN from packet, then instance, then existing entry (mirror often strips Dot1Q)
        if vlan_id is None and instance:
            vlan_id = instance.vlan
        if vlan_id is None:
            vlan_id = self.entries.get_known_vlan(ip, bridge)
        # Update store
        self._update_snoop_entry(mac, ip, bridge, entry_type, ptype, vlan_id, instance)
        # ARP reply slow path / reinject
        self._send_arp_reply(pkt, bridge, arp_replied)

    def _sniff_loop(self, iface: str) -> None:
        """Run Scapy sniff on one bridge (filter ARP/DHCP); timeout so stop is checked."""
        if not sniff:
            self.log.warning("Scapy not available; PacketMonitor disabled")
            return
        self.log.info("PacketMonitor sniffing on %s", iface)
        bpf = "arp or (udp and (port 67 or port 68))"
        while not self._stop.is_set():
            try:
                sniff(
                    iface=iface,
                    filter=bpf,
                    prn=lambda p, br=iface: self._handle_packet(p, br),
                    stop_filter=lambda _: self._stop.is_set(),
                    store=False,
                    timeout=3,
                )
            except Exception as e:
                if not self._stop.is_set():
                    self.log.warning("PacketMonitor %s: %s", iface, e)
            time.sleep(0.2)

    def start(self) -> list[threading.Thread]:
        """Start one sniff thread per bridge. Return list of threads."""
        self._last_snoop_time = time.time()  # grace so snoop-silence watchdog does not fire at start
        threads = []
        for br in self.bridges:
            t = threading.Thread(target=self._sniff_loop, args=(br,), daemon=True)
            t.start()
            threads.append(t)
        return threads


from src.arp_refresher import ArpRefresher
