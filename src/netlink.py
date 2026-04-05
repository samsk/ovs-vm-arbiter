# Netlink cache: typed results only (no raw links/addrs to traverse)
from __future__ import annotations

import ipaddress
import socket
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Optional

from src.types import IPRoute, MACAddress, IPv4Address, RT_SCOPE_HOST
from src.ttl_cache import TTLCache
from src.config import Config


@dataclass(frozen=True)
class LinkInfo:
    """Single link from get_links (internal / tests)."""

    index: int
    name: str
    mac: str


@dataclass(frozen=True)
class AddrInfo:
    """Single IPv4 addr from get_addr (internal / tests)."""

    index: int
    addr: str
    prefixlen: int
    scope: int


@dataclass(frozen=True)
class IfaceIP:
    """One IPv4 on an interface: addr, scope, mac. Typed result only."""

    addr: str
    scope: int
    mac: str


def _is_bridge_iface_name(name: str) -> bool:
    """True if name looks like a bridge (vmbr*, br-*, br*)."""
    return name.startswith("vmbr") or name.startswith("br-") or (
        name.startswith("br") and name[2:3].isdigit()
    )


def _compute_state(
    bridges: set[str],
    links_list: list[LinkInfo],
    addrs_list: list[AddrInfo],
) -> "NetlinkState":
    """Build NetlinkState from link/addr lists. No raw data in result."""
    bridge_idx = {l.index for l in links_list if l.name in bridges}
    self_macs = {l.mac for l in links_list if l.name in bridges and l.mac}
    self_ips = {a.addr for a in addrs_list if a.index in bridge_idx}
    tap_macs = {
        l.mac for l in links_list
        if l.mac and (l.name.startswith("tap") or l.name.startswith("veth"))
    }
    host_local = {(a.addr, a.prefixlen) for a in addrs_list if a.scope == RT_SCOPE_HOST}
    bridge_subnets = []
    for a in addrs_list:
        if a.index not in bridge_idx:
            continue
        try:
            bridge_subnets.append(ipaddress.ip_network(f"{a.addr}/{a.prefixlen}", strict=False))
        except ValueError:
            pass
    idx_to_mac = {l.index: l.mac for l in links_list if l.name in bridges and l.mac}
    bridge_identity = {a.addr: idx_to_mac[a.index] for a in addrs_list if a.index in idx_to_mac}
    all_bridge_idx = {l.index for l in links_list if _is_bridge_iface_name(l.name)}
    idx_to_mac_all = {l.index: l.mac for l in links_list if l.index in all_bridge_idx and l.mac}
    for a in addrs_list:
        if a.index in idx_to_mac_all and a.addr not in bridge_identity:
            bridge_identity[a.addr] = idx_to_mac_all[a.index]
    all_bridge_macs = {l.mac for l in links_list if l.mac and _is_bridge_iface_name(l.name)}

    idx_to_link = {l.index: l for l in links_list}
    iface_ips: dict[str, list[IfaceIP]] = {}
    for a in addrs_list:
        link = idx_to_link.get(a.index)
        if link:
            iface_ips.setdefault(link.name, []).append(
                IfaceIP(addr=a.addr, scope=a.scope, mac=link.mac)
            )
    bridge_names_with_ips = frozenset(
        name for name in iface_ips if _is_bridge_iface_name(name)
    )

    return NetlinkState(
        self_macs=self_macs,
        self_ips=self_ips,
        tap_macs=tap_macs,
        host_local=host_local,
        bridge_subnets=bridge_subnets,
        bridge_identity=bridge_identity,
        all_bridge_macs=all_bridge_macs,
        bridge_names_with_ips=bridge_names_with_ips,
        iface_ips=iface_ips,
    )


def build_netlink_state_for_test(
    bridges: list[str],
    links: list[LinkInfo],
    addrs: list[AddrInfo],
) -> "NetlinkState":
    """Build NetlinkState from links/addrs (tests). Returns typed state only."""
    return _compute_state(set(bridges), links, addrs)


@dataclass
class NetlinkState:
    """Cached netlink results only. No raw links/addrs."""

    self_macs: set[str]
    self_ips: set[str]
    tap_macs: set[str]
    host_local: set[tuple[str, int]]
    bridge_subnets: list[Any]
    bridge_identity: dict[str, str]
    all_bridge_macs: set[str]
    bridge_names_with_ips: frozenset[str]
    iface_ips: dict[str, list[IfaceIP]]


def _empty_netlink_state() -> NetlinkState:
    return NetlinkState(
        set(), set(), set(), set(), [], {}, set(),
        frozenset(), {},
    )


class NetlinkInfo:
    """Cached netlink queries. Exposes only typed results."""

    def __init__(self, bridges: list[str], config: Optional[Config] = None) -> None:
        self._bridges = set(bridges)
        self._config = config
        bridge_ttl = config.bridge_subnets_cache_ttl if config else 60.0
        self._cache: TTLCache[NetlinkState] = TTLCache(
            bridge_ttl, self._fetch_state, _empty_netlink_state()
        )

    def _fetch_state(self) -> NetlinkState:
        if not IPRoute:
            return _empty_netlink_state()
        links_list: list[LinkInfo] = []
        addrs_list: list[AddrInfo] = []
        try:
            ipr = IPRoute()
            for link in ipr.get_links():
                idx = link.get("index")
                if idx is None:
                    continue
                name = link.get_attr("IFLA_IFNAME") or ""
                hw = link.get_attr("IFLA_ADDRESS")
                mac = str(hw).lower() if hw else ""
                links_list.append(LinkInfo(index=idx, name=name, mac=mac))
            for msg in ipr.get_addr():
                if msg.get("family", 0) != 2:
                    continue
                idx = msg.get("index")
                if idx is None:
                    continue
                addr = msg.get_attr("IFA_ADDRESS")
                if not addr:
                    continue
                addrs_list.append(
                    AddrInfo(
                        index=idx,
                        addr=addr,
                        prefixlen=msg.get("prefixlen", 32),
                        scope=msg.get("scope", 0),
                    )
                )
            ipr.close()
        except Exception:
            return _empty_netlink_state()
        return _compute_state(self._bridges, links_list, addrs_list)

    def _state(self) -> NetlinkState:
        return self._cache.get()

    def is_self(self, mac: MACAddress, ip: IPv4Address) -> bool:
        s = self._state()
        return mac.lower() in s.self_macs or ip in s.self_ips

    def is_tap_mac(self, mac: MACAddress) -> bool:
        return mac.lower() in self._state().tap_macs

    def is_host_local(self, ip: IPv4Address) -> bool:
        if ip.startswith("127.") or ip == "0.0.0.0":
            return True
        s = self._state()
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for addr_str, prefixlen in s.host_local:
            try:
                net = ipaddress.ip_network(f"{addr_str}/{prefixlen}", strict=False)
                if ip_obj in net:
                    return True
            except ValueError:
                continue
        return False

    def ip_in_bridge_subnets(self, ip: IPv4Address) -> bool:
        s = self._state()
        if not s.bridge_subnets:
            return True
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(ip_obj in net for net in s.bridge_subnets)

    def bridge_mac_for_ip(self, ip: IPv4Address) -> Optional[str]:
        return self._state().bridge_identity.get(ip)

    def is_bridge_mac(self, mac: MACAddress) -> bool:
        return mac.lower() in self._state().all_bridge_macs

    def get_bridge_names_with_ips(self) -> set[str]:
        """Bridge-like iface names that have at least one IPv4."""
        return set(self._state().bridge_names_with_ips)

    def get_ips_per_interface(self, iface_names: set[str]) -> dict[str, list[tuple[str, str]]]:
        """iface_name -> [(ip, mac), ...] for IPv4."""
        s = self._state()
        return {
            n: [(i.addr, i.mac) for i in s.iface_ips.get(n, [])]
            for n in iface_names
        }

    def get_iface_ips(self, ifaces: list[str]) -> list[tuple[str, str, int, str]]:
        """(name, addr, scope, mac) for given ifaces."""
        s = self._state()
        want = set(ifaces)
        return [
            (n, i.addr, i.scope, i.mac)
            for n in want
            for i in s.iface_ips.get(n, [])
        ]

    def invalidate_kernel_arp(
        self,
        ip: IPv4Address,
        bridge: Optional[str] = None,
        mac: Optional[MACAddress] = None,
    ) -> bool:
        """Delete IPv4 neighbor entry from kernel ARP table.

        Args:
            ip: IPv4 address to invalidate.
            bridge: Optional interface name constraint.
            mac: Optional MAC constraint for safety.

        Returns:
            True when at least one matching entry is deleted.
        """
        if not IPRoute:
            return False
        deleted = False
        try:
            ipr = IPRoute()
            if bridge:
                ifindices = ipr.link_lookup(ifname=str(bridge))
            else:
                ifindices = []
                for br in sorted(self._bridges):
                    ifindices.extend(ipr.link_lookup(ifname=str(br)))
            if not ifindices:
                ipr.close()
                return False
            for ifindex in ifindices:
                try:
                    neighs = ipr.get_neighbours(
                        dst=str(ip),
                        ifindex=ifindex,
                        family=socket.AF_INET,
                    )
                except Exception:
                    continue
                for neigh in neighs:
                    lladdr = neigh.get_attr("NDA_LLADDR")
                    if mac is not None and lladdr and str(lladdr).lower() != str(mac).lower():
                        continue
                    try:
                        ipr.neigh("del", dst=str(ip), ifindex=ifindex, family=socket.AF_INET)
                        deleted = True
                    except Exception:
                        continue
            ipr.close()
        except Exception:
            return False
        return deleted


class PeerTracker:
    """Track VM-to-VM conversations for ARP refresh."""

    def __init__(self, peer_timeout: float, peer_limit: int, global_limit: int) -> None:
        import threading
        self._timeout = peer_timeout
        self._peer_limit = peer_limit
        self._global_limit = global_limit
        self._by_mac: dict[MACAddress, OrderedDict[IPv4Address, float]] = {}
        self._lock = threading.Lock()

    def track(self, local_mac: MACAddress, remote_ip: IPv4Address) -> None:
        import time
        now = time.time()
        with self._lock:
            total = sum(len(od) for od in self._by_mac.values())
            if local_mac not in self._by_mac:
                self._by_mac[local_mac] = OrderedDict()
            od = self._by_mac[local_mac]
            if remote_ip in od:
                od.move_to_end(remote_ip)
                od[remote_ip] = now
                return
            while total >= self._global_limit:
                evicted = False
                for mac in list(self._by_mac.keys()):
                    o = self._by_mac[mac]
                    if o:
                        o.popitem(last=False)
                        total -= 1
                        evicted = True
                        break
                if not evicted:
                    return
            while len(od) >= self._peer_limit:
                od.popitem(last=False)
                total -= 1
            od[remote_ip] = now
            total += 1

    def cleanup(self) -> None:
        import time
        cutoff = time.time() - self._timeout
        with self._lock:
            for od in self._by_mac.values():
                to_del = [ip for ip, ts in od.items() if ts < cutoff]
                for ip in to_del:
                    del od[ip]

    def get_active_peers_with_ttl(self) -> list[tuple[MACAddress, IPv4Address, float]]:
        with self._lock:
            out: list[tuple[MACAddress, IPv4Address, float]] = []
            for local_mac, od in self._by_mac.items():
                for remote_ip, last_seen in od.items():
                    out.append((local_mac, remote_ip, last_seen))
            return out

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            out = [
                {"local_mac": lm, "remote_ip": ri, "last_seen": ls}
                for lm, od in self._by_mac.items()
                for ri, ls in od.items()
            ]
            return {"peers": out}

    def load_from_dict(self, data: dict[str, Any]) -> None:
        for p in data.get("peers") or []:
            lm, ri = p.get("local_mac"), p.get("remote_ip")
            if not lm or not ri:
                continue
            try:
                self.track(MACAddress(lm), IPv4Address(ri))
            except (ValueError, TypeError):
                pass
