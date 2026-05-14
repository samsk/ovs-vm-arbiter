import asyncio
import logging
import re
import time
from typing import Callable, Dict, List, Optional, Set, Tuple, AbstractSet

from src.types import BridgeName, IPv4Address, MACAddress, OFPort, OVSCookie
from src.ovs_cmd import OVSCommand
from src.packet_out import PacketOutRequest, AsyncPacketSender
from src.flow_registry import FlowRegistry
from src.models import normalize_vlan


_ResponderKey = Tuple[BridgeName, IPv4Address, MACAddress, Optional[int]]


def _norm_responder_key(
    br: object, ip: object, mac: object, vlan: Optional[int] = None
) -> _ResponderKey:
    """Canonical key: (bridge, ip, mac, vlan). vlan None = match any vlan."""
    return (
        BridgeName(str(br)),
        IPv4Address(str(ip)),
        MACAddress(str(mac)),
        vlan,
    )


def _responder_sort_key(k: _ResponderKey) -> tuple:
    """Sort key for responder keys (bridge, ip, mac, vlan)."""
    br, ip, mac, vlan = k
    return (br, ip, mac, vlan if vlan is not None else -1)


def compute_desired_responders(
    entries: "IPEntryStore",  # type: ignore
    active_ttl: float,
    bridges: list[BridgeName],
    node_id: Optional[str] = None,
    arp_reply_local: bool = False,
    arp_responder_reply_local: bool = False,
    arp_reply_strict_vlan: bool = True,
    arp_reply_no_vlan: bool = True,
    arp_reply_remote_vlan: Optional[int] = None,
    for_responder: bool = False,
    local_vlans: Optional[AbstractSet[int]] = None,
    arp_reply_localize_vlan: bool = False,
    passive_bridges: AbstractSet[str] = frozenset(),
) -> Set[_ResponderKey]:
    """Compute desired ARP responder set from IP entry store.

    Passive-bridge **entry.bridge** (legacy): still map flows to the single active bridge
    (`bridges[0]`). Normalized snoop stores **IPEntry.bridge** as that active bridge.
    All snooped entries get responder keys (filtered only by reply_local). Then:
    - strict=False: one key per (br, ip, mac) with vlan=None (match any request vlan).
    - strict=True: per entry add (br, ip, mac, match_vlan); if arp_reply_no_vlan and not for_responder
      also add (br, ip, mac, None) for untagged. Remote entries: use arp_reply_remote_vlan when set.
    """
    import time as _t
    now = _t.time()
    active = entries.get_active(now, active_ttl, node_id=None)
    reply_local_ok = arp_reply_local and arp_responder_reply_local
    no_vlan_ok = arp_reply_no_vlan and not for_responder  # responder ignores no_vlan
    desired: Set[_ResponderKey] = set()
    per_br_ip: Dict[Tuple[BridgeName, IPv4Address], MACAddress] = {}
    active_bridge_list = [BridgeName(str(bridges[0]))] if bridges else []
    for _key, entry in active.items():
        if not entry.bridge:
            continue
        is_local = (
            node_id is None
            or (entry.node is not None and str(entry.node) == node_id)
        )
        if node_id is not None and is_local and not reply_local_ok:
            continue
        ip = entry.ipv4
        entry_br = entry.bridge
        mac = entry.mac
        if str(entry_br) in passive_bridges:
            if not active_bridge_list:
                continue
            target_bridges = active_bridge_list
        elif entry_br in bridges:
            target_bridges = [entry_br]
        else:
            target_bridges = list(bridges)
        for br in target_bridges:
            br_n = BridgeName(str(br))
            ip_n = IPv4Address(str(ip))
            mac_n = MACAddress(str(mac))
            entry_vlan = normalize_vlan(entry.vlan)
            if arp_reply_strict_vlan:
                if is_local:
                    vlan_n = entry_vlan
                    if vlan_n is not None:
                        desired.add(_norm_responder_key(br_n, ip_n, mac_n, vlan_n))
                        if no_vlan_ok:
                            desired.add(_norm_responder_key(br_n, ip_n, mac_n, None))
                    else:
                        desired.add(_norm_responder_key(br_n, ip_n, mac_n, None))
                else:
                    # remote: no entry vlan -> match any (None); else use remote_vlan when set,
                    # optionally localized when vlan is present on this node.
                    if entry_vlan is None:
                        desired.add(_norm_responder_key(br_n, ip_n, mac_n, None))
                    else:
                        use_entry_vlan = (
                            arp_reply_localize_vlan
                            and local_vlans is not None
                            and entry_vlan in local_vlans
                        )
                        if use_entry_vlan:
                            desired.add(_norm_responder_key(br_n, ip_n, mac_n, entry_vlan))
                        else:
                            rv = arp_reply_remote_vlan
                            if rv is not None:
                                desired.add(_norm_responder_key(br_n, ip_n, mac_n, rv))
                            else:
                                desired.add(_norm_responder_key(br_n, ip_n, mac_n, entry_vlan))
            else:
                key = (br_n, ip_n)
                if key not in per_br_ip:
                    per_br_ip[key] = mac_n
    if not arp_reply_strict_vlan:
        for (br_n, ip_n), mac_n in per_br_ip.items():
            desired.add(_norm_responder_key(br_n, ip_n, mac_n, None))
    return desired


class OFManager:
    """Central module for all ovs-ofctl calls: packet-out, add-flow, del-flows."""

    # Flow specs base: (match_suffix, name). Actions = output:LOCAL [,action]; action from of_action/of_arp_action/of_dhcp_action.
    # output:LOCAL = copy to host for snooping; action "no" = no extra action.
    FLOW_SPECS_BASE: list[tuple[str, str]] = [
        ("arp", "arp"),
        ("udp,tp_dst=67", "udp67"),
        ("udp,tp_dst=68", "udp68"),
    ]

    def __init__(
        self,
        registry: "FlowRegistry",
        bridges: list[BridgeName],
        log: logging.Logger,
        of_table: int = 0,
        of_priority: int = 999,
        of_action: str = "NORMAL",
        of_arp_action: Optional[str] = None,
        of_dhcp_action: Optional[str] = None,
        arp_responder_priority: int = 1001,
        arp_responder_mirror: bool = True,
        arp_responder_forward_normal: bool = False,
        arp_responder_vlan_register: Optional[int] = None,
    ) -> None:
        self.registry = registry
        self.bridges = bridges
        self.log = log
        self.of_table = of_table
        self.of_priority = of_priority
        self.arp_responder_priority = arp_responder_priority
        self.arp_responder_mirror = arp_responder_mirror
        self.arp_responder_forward_normal = arp_responder_forward_normal
        self.arp_responder_vlan_register = arp_responder_vlan_register
        # (br, ip, mac) -> priority; one priority per key, reuse when removed
        self._arp_responder_installed: Dict[_ResponderKey, int] = {}
        # learning: out_port we used per key; if port changes, we re-add flow
        self._arp_responder_out_port: Dict[_ResponderKey, Optional[OFPort]] = {}
        self._arp_responder_priority_max: int = arp_responder_priority + 2000
        self._arp_sync_ok_count: int = 0
        self._arp_sync_error_count: int = 0
        self._arp_sync_added_count: int = 0
        self._arp_sync_removed_count: int = 0

        def action_for(match: str, name: str) -> str:
            if match == "arp":
                act = of_arp_action if of_arp_action is not None else of_action
            elif "udp" in match:
                act = of_dhcp_action if of_dhcp_action is not None else of_action
            else:
                act = of_action
            # no / drop = no extra action (output:LOCAL only)
            if not act or act == "no" or act.strip().lower() == "drop":
                return "output:LOCAL"
            return f"output:LOCAL,{act}"

        self._flow_specs = [
            (m, action_for(m, n), n) for m, n in self.FLOW_SPECS_BASE
        ]
        self._cookie: Optional[OVSCookie] = None
        self._async_sender: Optional[AsyncPacketSender] = None

    def set_async_sender(self, sender: AsyncPacketSender) -> None:
        """Set async packet sender for non-blocking packet-out."""
        self._async_sender = sender

    def send_packet_out(
        self,
        bridge: BridgeName,
        packet_bytes: bytes,
        in_port: OFPort = OFPort("LOCAL"),
        actions: str = "output:NORMAL",
        timeout: int = 2,
    ) -> bool:
        """Send packet-out to bridge; returns True on success."""
        spec_port = "LOCAL" if in_port == "65534" else in_port
        spec = f"in_port={spec_port},packet={packet_bytes.hex()},actions={actions}"
        ok, _ = OVSCommand.run_ofctl("packet-out", bridge, spec, timeout=timeout)
        if ok:
            self.log.debug("packet-out sent bridge=%s in_port=%s len=%d", bridge, in_port, len(packet_bytes))
        return ok

    def send_packet_out_async(
        self,
        bridge: BridgeName,
        packet_bytes: bytes,
        in_port: OFPort = OFPort("LOCAL"),
        actions: str = "output:NORMAL",
    ) -> bool:
        """Queue packet-out for async sending; returns False if queue full or no sender."""
        if not self._async_sender:
            return self.send_packet_out(bridge, packet_bytes, in_port, actions)
        return self._async_sender.enqueue(PacketOutRequest(bridge, packet_bytes, in_port, actions))

    def _cookie_spec(self) -> Optional[OVSCookie]:
        """Get cached or fetch cookie from registry."""
        c = self._cookie or self.registry.get_cookie()
        if c:
            self._cookie = c
        return c

    def _add_flow(
        self,
        bridge: BridgeName,
        table: int,
        priority: int,
        match: str,
        actions: str,
        label: str,
    ) -> bool:
        """Add flow; return True on success."""
        cookie = self._cookie_spec()
        if not cookie:
            return False
        spec = f"cookie={cookie},table={table},priority={priority},{match},actions={actions}"
        ok, err = OVSCommand.run_ofctl("add-flow", bridge, spec)
        if ok:
            self.log.info("flow %s added on %s", label, bridge)
        else:
            self.log.warning("add-flow %s on %s failed: %s", label, bridge, err)
        return ok

    def _del_flow(
        self,
        bridge: BridgeName,
        table: int,
        match: str,
        priority: Optional[int] = None,
    ) -> bool:
        """Delete flows by cookie+table+match. Returns True if ok. Priority omitted (not supported by all ovs-ofctl)."""
        cookie = self._cookie_spec()
        if not cookie:
            return False
        # cookie+table+match only; priority not used (older ovs-ofctl reject "priority" in del-flows)
        spec = f"cookie={cookie}/0xffffffff,table={table},{match}"
        ok, out = OVSCommand.run_ofctl("del-flows", bridge, spec)
        if not ok:
            self.log.warning("del-flows failed on %s: %s", bridge, out)
        return ok

    def _del_cookie_flows(self, bridge: BridgeName, cookie: OVSCookie) -> None:
        """Delete all flows with given cookie from bridge."""
        OVSCommand.run_ofctl("del-flows", bridge, f"cookie={cookie}/0xffffffff")

    def _flow_exists(
        self,
        bridge: BridgeName,
        table: int,
        priority: int,
        match: str,
        actions: str,
    ) -> bool:
        """Return True if a flow matching table,priority,match,actions exists (any cookie)."""
        # dump-flows only filters by table+match (priority/actions not supported)
        spec = f"table={table},{match}"
        ok, out = OVSCommand.run_ofctl("dump-flows", bridge, spec)
        if not ok or not out:
            return False
        needle = f"priority={priority},{match}"
        actions_needle = f"actions={actions}"
        return needle in out and actions_needle in out

    def _add_one_flow(
        self,
        bridge: BridgeName,
        match: str,
        actions: str,
        name: str,
    ) -> bool:
        """Add single flow; return True if added successfully."""
        return self._add_flow(bridge, self.of_table, self.of_priority, match, actions, name)

    def ensure_flows(self) -> None:
        """Add flows in configured table/priority; mirror to LOCAL (del our cookie then add)."""
        cookie = self._cookie_spec()
        if not cookie:
            self.log.warning("OFManager: no cookie")
            return
        t, p = self.of_table, self.of_priority
        for br in self.bridges:
            self._del_cookie_flows(br, cookie)
            for match, actions, name in self._flow_specs:
                if self._flow_exists(br, t, p, match, actions):
                    self.log.debug("flow %s already present on %s, skip add", name, br)
                    continue
                self._add_one_flow(br, match, actions, name)

    def _restore_missing_flows(self, bridges: list[BridgeName]) -> int:
        """Add only missing flows on given bridges (no del). Return count added."""
        cookie = self._cookie_spec()
        if not cookie:
            return 0
        t, p = self.of_table, self.of_priority
        added = 0
        for br in bridges:
            for match, actions, name in self._flow_specs:
                if not self._flow_exists(br, t, p, match, actions):
                    if self._add_one_flow(br, match, actions, name):
                        added += 1
        return added

    @staticmethod
    def _parse_flow_count(out: str) -> int:
        """Count flow lines (with actions=) in dump-flows output."""
        return sum(1 for line in (out or "").splitlines() if "actions=" in line)

    def _count_cookie_flows(self, bridge: BridgeName, cookie: OVSCookie) -> int:
        """Return number of flows with given cookie on bridge (sync)."""
        ok, out = OVSCommand.run_ofctl("dump-flows", bridge, f"cookie={cookie}/0xffffffff")
        return self._parse_flow_count(out) if ok else 0

    async def _count_cookie_flows_async(self, bridge: BridgeName, cookie: OVSCookie) -> int:
        """Return number of flows with given cookie on bridge (async)."""
        ok, out = await OVSCommand.run_ofctl_async(
            "dump-flows", bridge, f"cookie={cookie}/0xffffffff"
        )
        return self._parse_flow_count(out) if ok else 0

    async def verify_and_restore_flows(self) -> bool:
        """Check our flows exist; add only missing flows, warn only when we add."""
        cookie = self._cookie_spec()
        if not cookie:
            return True
        expected = len(self._flow_specs)
        counts = await asyncio.gather(
            *[self._count_cookie_flows_async(br, cookie) for br in self.bridges]
        )
        missing = [br for br, n in zip(self.bridges, counts) if n < expected]
        if not missing:
            return True
        loop = asyncio.get_running_loop()
        added = await loop.run_in_executor(
            None, lambda: self._restore_missing_flows(missing)
        )
        if added > 0:
            self.log.warning(
                "OpenFlow: flows missing on %s (expected %d), re-added %d flow(s)",
                missing, expected, added,
            )
        return False

    def _arp_responder_match(self, ip: IPv4Address, vlan: Optional[int] = None) -> str:
        """Build OpenFlow match for ARP who-has; vlan None = any vlan. Use vlan_tci or REG match."""
        base = f"arp,arp_op=1,arp_tpa={ip}"
        if vlan is None:
            return base
        reg = self.arp_responder_vlan_register
        if reg is not None and 0 <= reg <= 7:
            return f"{base},NXM_NX_REG{reg}[]=0x{vlan & 0xFFF:x}"
        tci = 0x1000 | (vlan & 0xFFF)
        return f"{base},vlan_tci=0x{tci:04x}/0x1fff"

    def _mac_to_load_hex(self, mac: MACAddress) -> str:
        """MAC to hex for load action (no colons)."""
        try:
            raw = str(mac).replace(":", "").lower()
            if len(raw) != 12 or not all(c in "0123456789abcdef" for c in raw):
                raise ValueError("invalid MAC")
            return "0x" + raw
        except (ValueError, TypeError) as e:
            self.log.warning("invalid MAC for load: %s (%s)", mac, e)
            raise

    def _ip_to_load_hex(self, ip: IPv4Address) -> str:
        """IPv4 to 32-bit hex for load action (IPv4Address is NewType str)."""
        import ipaddress
        try:
            addr = ipaddress.IPv4Address(ip)
            return hex(int(addr) & 0xFFFFFFFF)
        except (ValueError, TypeError) as e:
            self.log.warning("invalid IPv4 for load: %s (%s)", ip, e)
            raise

    def _port_to_load_hex(self, port: int) -> str:
        """Port number to hex for load action."""
        return hex(port)

    def _arp_responder_learn_action(
        self, mac: MACAddress, out_port: OFPort, learn_table: int, learn_priority: int = 100
    ) -> str:
        """Build learn() action: creates flow so packets to response MAC go to node port.
        NXM_OF_ETH_DST in learn() requires colon MAC.
        Output to constant port requires load->REG, output:REG (using REG2)."""
        mac_str = str(mac).lower()
        try:
            port_num = int(str(out_port))
        except (ValueError, TypeError):
            raise ValueError(f"invalid OF port for learn: {out_port}")
        port_hex = self._port_to_load_hex(port_num)
        return (
            f"learn(table={learn_table},idle_timeout=300,priority={learn_priority},"
            f"NXM_OF_ETH_DST[]={mac_str},load:{port_hex}->NXM_NX_REG2[],output:NXM_NX_REG2[])"
        )

    def _arp_responder_actions(
        self,
        mac: MACAddress,
        ip: IPv4Address,
        mirror_local: bool,
        out_port: Optional[OFPort] = None,
    ) -> str:
        """Build OpenFlow actions: reply on clone to IN_PORT; original (request) to LOCAL when mirror.

        Reply always goes to IN_PORT (requester). When mirror_local, send original request to LOCAL
        so snooping sees it; we do clone(reply_actions),output:LOCAL so request is delivered to host.
        """
        mac_hex = self._mac_to_load_hex(mac)
        ip_hex = self._ip_to_load_hex(ip)
        reply_actions: List[str] = []
        if out_port:
            reply_actions.append(
                self._arp_responder_learn_action(mac, out_port, self.of_table)
            )
        reply_actions.extend([
            "move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[]",
            f"mod_dl_src:{mac}",
            "load:0x2->NXM_OF_ARP_OP[]",
            "move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[]",
            "move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[]",
            f"load:{mac_hex}->NXM_NX_ARP_SHA[]",
            f"load:{ip_hex}->NXM_OF_ARP_SPA[]",
            "IN_PORT",
        ])
        reply_str = ",".join(reply_actions)
        if self.arp_responder_forward_normal:
            reply_str = "clone(output:NORMAL)," + reply_str
        # Send request to LOCAL first, then clone does reply to IN_PORT (so LOCAL always gets request)
        if mirror_local:
            out = f"clone(output:LOCAL),clone({reply_str})"
        else:
            out = reply_str
        return out

    def _add_arp_responder_flow(
        self,
        bridge: BridgeName,
        ip: IPv4Address,
        mac: MACAddress,
        priority: int,
        out_port: Optional[OFPort] = None,
        vlan: Optional[int] = None,
    ) -> bool:
        """Add one ARP responder flow. vlan None = match any vlan."""
        match = self._arp_responder_match(ip, vlan)
        actions = self._arp_responder_actions(
            mac, ip, self.arp_responder_mirror, out_port=out_port
        )
        label = f"arp-responder {ip} @ {mac}" + (f" vlan={vlan}" if vlan is not None else "")
        return self._add_flow(bridge, self.of_table, priority, match, actions, label)

    def _arp_responder_match_legacy_dl_vlan(self, ip: IPv4Address, vlan: int) -> str:
        """Legacy match string (dl_vlan) for deleting old flows."""
        base = f"arp,arp_op=1,arp_tpa={ip}"
        return f"{base},dl_vlan={vlan}"

    def _del_arp_responder_flow(
        self,
        bridge: BridgeName,
        ip: IPv4Address,
        priority: int,
        vlan: Optional[int] = None,
    ) -> bool:
        """Delete one OFS ARP responder flow; vlan_tci or REG match; legacy dl_vlan only when not using REG."""
        match = self._arp_responder_match(ip, vlan)
        if self._del_flow(bridge, self.of_table, match, priority=priority):
            return True
        if vlan is not None and self.arp_responder_vlan_register is None:
            legacy = self._arp_responder_match_legacy_dl_vlan(ip, vlan)
            return self._del_flow(bridge, self.of_table, legacy, priority=priority)
        return False

    def sync_arp_responder_flows(
        self,
        entries: Optional["IPEntryStore"] = None,  # type: ignore
        active_ttl: Optional[float] = None,
        node_id: Optional[str] = None,
        arp_reply_local: bool = False,
        arp_responder_reply_local: bool = False,
        arp_reply_strict_vlan: bool = True,
        arp_reply_no_vlan: bool = True,
        desired: Optional[Set[_ResponderKey]] = None,
        get_learning_port: Optional[
            Callable[[BridgeName, IPv4Address], Optional[OFPort]]
        ] = None,
    ) -> tuple[int, int]:
        """Reconcile ARP responder flows with desired set.

        If desired is None, compute from entries/active_ttl/args. get_learning_port(br, ip)
        returns OF port for that (br, ip) so reply is sent there for FDB learning.

        Returns:
            (added, removed) flow counts.
        """
        if desired is None:
            desired = compute_desired_responders(
                entries, active_ttl, self.bridges,
                node_id=node_id,
                arp_reply_local=arp_reply_local,
                arp_responder_reply_local=arp_responder_reply_local,
                arp_reply_strict_vlan=arp_reply_strict_vlan,
                arp_reply_no_vlan=arp_reply_no_vlan,
            )

        installed_keys = set(self._arp_responder_installed)
        to_remove = installed_keys - desired
        to_update: Set[_ResponderKey] = set()
        if get_learning_port:
            for key in desired & installed_keys:
                br, ip, mac, _vlan = key
                current_port = get_learning_port(br, ip)
                prev_port = self._arp_responder_out_port.get(key)
                if prev_port != current_port:
                    to_update.add(key)
        to_remove |= to_update
        to_add = (desired - installed_keys) | to_update

        removed = 0
        for key in list(to_remove):
            br, ip, mac, vlan = key
            prio = self._arp_responder_installed.get(key)
            if prio is None:
                continue
            self.log.info(
                "arp-responder remove: %s %s mac=%s prio=%s%s",
                br, ip, mac, prio, " (port changed)" if key in to_update else "",
            )
            if self._del_arp_responder_flow(br, ip, prio, vlan=vlan):
                del self._arp_responder_installed[key]
                self._arp_responder_out_port.pop(key, None)
                removed += 1

        used = set(self._arp_responder_installed.values())
        available = sorted(
            p for p in range(self.arp_responder_priority, self._arp_responder_priority_max)
            if p not in used
        )
        added = 0
        try:
            for key in sorted(to_add, key=_responder_sort_key):
                br, ip, mac, vlan = key
                if br not in self.bridges:
                    continue
                if not available:
                    self.log.warning("arp-responder: no free priority slot, skip add %s %s", ip, mac)
                    continue
                prio = available.pop(0)
                out_port = get_learning_port(br, ip) if get_learning_port else None
                self.log.info(
                    "arp-responder add: %s %s mac=%s prio=%s vlan=%s%s",
                    br, ip, mac, prio, vlan if vlan is not None else "-", f" out_port={out_port}" if out_port else "",
                )
                try:
                    if self._add_arp_responder_flow(br, ip, mac, prio, out_port=out_port, vlan=vlan):
                        self._arp_responder_installed[key] = prio
                        self._arp_responder_out_port[key] = out_port
                        added += 1
                except (ValueError, TypeError) as e:
                    self.log.warning("skip arp-responder add %s %s: %s", ip, mac, e)
            if added or removed:
                self.log.info(
                    "arp-responder sync: added=%d removed=%d (total=%d)",
                    added, removed, len(self._arp_responder_installed),
                )
            self._arp_sync_ok_count += 1
            self._arp_sync_added_count += added
            self._arp_sync_removed_count += removed
            return added, removed
        except Exception:
            self._arp_sync_error_count += 1
            raise

    def arp_responder_flow_count(self) -> int:
        """Return number of installed responder flows.

        Args:
            None.

        Returns:
            Current responder flow count.
        """
        return len(self._arp_responder_installed)

    def arp_responder_flows_by_bridge(self) -> dict[str, int]:
        """Return responder flow count grouped by bridge.

        Args:
            None.

        Returns:
            Mapping bridge name -> flow count.
        """
        out: dict[str, int] = {}
        for bridge, _ip, _mac, _vlan in self._arp_responder_installed.keys():
            key = str(bridge)
            out[key] = out.get(key, 0) + 1
        return out

    def arp_responder_sync_counts(self) -> dict[str, int]:
        """Return ARP responder sync counters.

        Args:
            None.

        Returns:
            Dict with keys: ok, error, added, removed.
        """
        return {
            "ok": self._arp_sync_ok_count,
            "error": self._arp_sync_error_count,
            "added": self._arp_sync_added_count,
            "removed": self._arp_sync_removed_count,
        }

    def get_installed_arp_responders(
        self,
    ) -> List[Tuple[BridgeName, IPv4Address, Optional[int], MACAddress, int, Optional[int]]]:
        """Query OVS for installed ARP responder flows; return (br, ip, vlan, mac, prio, learn_ofport) per flow."""
        cookie = self._cookie_spec()
        if not cookie:
            return []
        prio_min = self.arp_responder_priority
        prio_max = self._arp_responder_priority_max
        spec = f"cookie={cookie}/0xffffffff"
        result: List[Tuple[BridgeName, IPv4Address, Optional[int], MACAddress, int, Optional[int]]] = []
        prio_re = re.compile(r"priority=(\d+),(?:[^,]+,)*arp")
        arp_tpa_re = re.compile(r"arp_tpa=([\d.]+)")
        vlan_tci_re = re.compile(r"vlan_tci=0x([0-9a-fA-F]+)/0x[0-9a-fA-F]+")
        dl_vlan_re = re.compile(r"dl_vlan=(\d+)")
        reg_vlan_re = re.compile(r"NXM_NX_REG\d+\[\]=0x([0-9a-fA-F]+)")
        mod_dl_src_re = re.compile(r"mod_dl_src:([0-9a-f:]+)", re.I)
        learn_reg2_re = re.compile(r"load:0x([0-9a-fA-F]+)->NXM_NX_REG2\[\]")
        for br in self.bridges:
            ok, out = OVSCommand.run_ofctl("dump-flows", str(br), spec)
            if not ok or not out:
                continue
            for line in out.splitlines():
                if "actions=" not in line or ",arp," not in line and "arp,arp_op" not in line:
                    continue
                m_prio = prio_re.search(line)
                if not m_prio:
                    continue
                prio = int(m_prio.group(1))
                if prio < prio_min or prio >= prio_max:
                    continue
                m_ip = arp_tpa_re.search(line)
                m_mac = mod_dl_src_re.search(line)
                if not m_ip or not m_mac:
                    continue
                ip_str, mac_str = m_ip.group(1), m_mac.group(1)
                vlan: Optional[int] = None
                m_tci = vlan_tci_re.search(line)
                if m_tci:
                    vlan = int(m_tci.group(1), 16) & 0xFFF
                else:
                    m_dl = dl_vlan_re.search(line)
                    if m_dl:
                        vlan = int(m_dl.group(1))
                    else:
                        m_reg = reg_vlan_re.search(line)
                        if m_reg:
                            try:
                                vlan = int(m_reg.group(1), 16) & 0xFFF
                            except ValueError:
                                pass
                learn_ofport: Optional[int] = None
                if "learn(" in line:
                    m_learn = learn_reg2_re.search(line)
                    if m_learn:
                        try:
                            learn_ofport = int(m_learn.group(1), 16)
                        except ValueError:
                            pass
                result.append(
                    (
                        BridgeName(str(br)),
                        IPv4Address(ip_str),
                        vlan,
                        MACAddress(mac_str),
                        prio,
                        learn_ofport,
                    )
                )
        return result

    def del_flows(self) -> None:
        """Remove all flows with our cookie."""
        cookie = self._cookie_spec()
        if not cookie:
            return
        for br in self.bridges:
            self._del_cookie_flows(br, cookie)
        self._arp_responder_installed.clear()
        self._arp_responder_out_port.clear()