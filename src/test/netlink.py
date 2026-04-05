"""Complete tests for src.netlink (typed results only)."""
import time
from unittest.mock import patch
from src.netlink import (
    NetlinkInfo,
    NetlinkState,
    LinkInfo,
    AddrInfo,
    IfaceIP,
    RT_SCOPE_HOST,
    build_netlink_state_for_test,
    _empty_netlink_state,
)
from src.types import MACAddress, IPv4Address
from src.test import _test_assert


def test_link_info_addr_info() -> None:
    """LinkInfo and AddrInfo are frozen and have expected fields."""
    l = LinkInfo(1, "eth0", "aa:bb:cc:dd:ee:ff")
    _test_assert(l.index == 1 and l.name == "eth0" and l.mac == "aa:bb:cc:dd:ee:ff", "LinkInfo")
    a = AddrInfo(1, "10.0.0.1", 24, 0)
    _test_assert(a.addr == "10.0.0.1" and a.prefixlen == 24 and a.scope == 0, "AddrInfo")


def test_iface_ip() -> None:
    """IfaceIP is typed result for one IP on an interface."""
    i = IfaceIP(addr="192.168.1.1", scope=0, mac="aa:bb:cc:dd:ee:ff")
    _test_assert(i.addr == "192.168.1.1" and i.mac == "aa:bb:cc:dd:ee:ff", "IfaceIP")


def test_build_netlink_state_for_test_self() -> None:
    """build_netlink_state_for_test: self_macs and self_ips for monitored bridges only."""
    links = [LinkInfo(1, "vmbr0", "aa:bb:cc:dd:ee:01"), LinkInfo(2, "eth0", "00:11:22:33:44:55")]
    addrs = [AddrInfo(1, "10.0.0.1", 24, 0)]
    state = build_netlink_state_for_test(["vmbr0"], links, addrs)
    _test_assert("aa:bb:cc:dd:ee:01" in state.self_macs and "10.0.0.1" in state.self_ips, "bridge included")
    _test_assert("00:11:22:33:44:55" not in state.self_macs, "non-bridge MAC excluded")


def test_build_netlink_state_for_test_tap_macs() -> None:
    """build_netlink_state_for_test: tap_macs only tap/veth."""
    links = [LinkInfo(1, "tap100", "tap:mac:01"), LinkInfo(2, "veth0", "ve:th:02"), LinkInfo(3, "eth0", "eth:03")]
    state = build_netlink_state_for_test([], links, [])
    _test_assert("tap:mac:01" in state.tap_macs and "ve:th:02" in state.tap_macs, "tap and veth")
    _test_assert("eth:03" not in state.tap_macs, "eth excluded")


def test_build_netlink_state_for_test_host_local() -> None:
    """build_netlink_state_for_test: host_local only scope=RT_SCOPE_HOST."""
    addrs = [AddrInfo(1, "10.0.0.1", 24, 0), AddrInfo(2, "192.168.2.1", 24, RT_SCOPE_HOST)]
    state = build_netlink_state_for_test([], [], addrs)
    _test_assert(("192.168.2.1", 24) in state.host_local, "host scope included")
    _test_assert(("10.0.0.1", 24) not in state.host_local, "global excluded")


def test_build_netlink_state_for_test_bridge_identity() -> None:
    """build_netlink_state_for_test: bridge_identity IP -> MAC."""
    links = [LinkInfo(1, "vmbr0", "aa:bb:cc:dd:ee:ff")]
    addrs = [AddrInfo(1, "10.0.0.5", 24, 0)]
    state = build_netlink_state_for_test(["vmbr0"], links, addrs)
    _test_assert(state.bridge_identity.get("10.0.0.5") == "aa:bb:cc:dd:ee:ff", "IP -> MAC")


def test_build_netlink_state_for_test_iface_ips() -> None:
    """build_netlink_state_for_test: iface_ips is name -> list[IfaceIP]."""
    links = [LinkInfo(1, "vmbr0", "mac:01"), LinkInfo(2, "eth0", "mac:02")]
    addrs = [AddrInfo(1, "10.0.0.1", 24, 0), AddrInfo(2, "192.168.1.1", 24, 0)]
    state = build_netlink_state_for_test([], links, addrs)
    _test_assert("vmbr0" in state.iface_ips and len(state.iface_ips["vmbr0"]) == 1, "vmbr0 one IP")
    _test_assert(state.iface_ips["vmbr0"][0].addr == "10.0.0.1" and state.iface_ips["vmbr0"][0].mac == "mac:01", "IfaceIP")
    _test_assert(state.iface_ips["eth0"][0].addr == "192.168.1.1", "eth0 IP")


def test_build_netlink_state_for_test_bridge_names_with_ips() -> None:
    """build_netlink_state_for_test: bridge_names_with_ips only bridge-like ifaces that have IPs."""
    links = [LinkInfo(1, "vmbr0", "m1"), LinkInfo(2, "vmbr00", "m2"), LinkInfo(3, "eth0", "m3")]
    addrs = [AddrInfo(1, "10.0.0.1", 24, 0), AddrInfo(2, "192.168.12.1", 24, 0)]
    state = build_netlink_state_for_test([], links, addrs)
    _test_assert("vmbr0" in state.bridge_names_with_ips and "vmbr00" in state.bridge_names_with_ips, "bridges with IPs")
    _test_assert("eth0" not in state.bridge_names_with_ips, "eth0 not bridge-like")


def test_netlink_info_is_self() -> None:
    """NetlinkInfo.is_self: True for bridge MAC or IP."""
    ni = NetlinkInfo(["vmbr0"], None)
    state = build_netlink_state_for_test(
        ["vmbr0"],
        [LinkInfo(1, "vmbr0", "aa:bb:cc:dd:ee:ff")],
        [AddrInfo(1, "10.0.0.5", 24, 0)],
    )
    ni._cache._cache = state
    ni._cache._cache_ts = time.time()
    _test_assert(ni.is_self(MACAddress("aa:bb:cc:dd:ee:ff"), IPv4Address("10.0.0.5")), "MAC and IP")
    _test_assert(ni.is_self(MACAddress("other"), IPv4Address("10.0.0.5")), "IP only")
    _test_assert(not ni.is_self(MACAddress("other"), IPv4Address("192.168.1.1")), "neither")


def test_netlink_info_is_tap_mac() -> None:
    """NetlinkInfo.is_tap_mac: True for tap/veth MACs."""
    ni = NetlinkInfo([], None)
    state = build_netlink_state_for_test([], [LinkInfo(1, "tap100", "tap:mac:01")], [])
    ni._cache._cache = state
    ni._cache._cache_ts = time.time()
    _test_assert(ni.is_tap_mac(MACAddress("tap:mac:01")), "tap")
    _test_assert(not ni.is_tap_mac(MACAddress("aa:bb:cc:dd:ee:ff")), "other")


def test_netlink_info_is_host_local() -> None:
    """NetlinkInfo.is_host_local: 127.x, 0.0.0.0, or scope=host."""
    ni = NetlinkInfo([], None)
    addrs = [AddrInfo(1, "192.168.2.1", 24, RT_SCOPE_HOST)]
    state = build_netlink_state_for_test([], [], addrs)
    ni._cache._cache = state
    ni._cache._cache_ts = time.time()
    _test_assert(ni.is_host_local(IPv4Address("127.0.0.1")), "loopback")
    _test_assert(ni.is_host_local(IPv4Address("192.168.2.1")), "scope host")
    _test_assert(not ni.is_host_local(IPv4Address("10.0.0.1")), "global")


def test_netlink_info_ip_in_bridge_subnets() -> None:
    """NetlinkInfo.ip_in_bridge_subnets: True if in any bridge subnet or no subnets."""
    ni = NetlinkInfo(["vmbr0"], None)
    state = build_netlink_state_for_test(
        ["vmbr0"],
        [LinkInfo(1, "vmbr0", "m")],
        [AddrInfo(1, "10.0.0.0", 24, 0)],
    )
    ni._cache._cache = state
    ni._cache._cache_ts = time.time()
    _test_assert(ni.ip_in_bridge_subnets(IPv4Address("10.0.0.1")), "in subnet")
    _test_assert(not ni.ip_in_bridge_subnets(IPv4Address("192.168.1.1")), "outside")
    ni2 = NetlinkInfo([], None)
    ni2._cache._cache = _empty()
    ni2._cache._cache_ts = time.time()
    _test_assert(ni2.ip_in_bridge_subnets(IPv4Address("1.2.3.4")), "no subnets -> True")


def _empty() -> NetlinkState:
    return _empty_netlink_state()


def test_netlink_info_bridge_mac_for_ip() -> None:
    """NetlinkInfo.bridge_mac_for_ip: MAC for IP on bridge, None otherwise."""
    ni = NetlinkInfo(["vmbr0"], None)
    state = build_netlink_state_for_test(
        ["vmbr0"],
        [LinkInfo(1, "vmbr0", "aa:bb:cc:dd:ee:ff")],
        [AddrInfo(1, "10.0.0.5", 24, 0)],
    )
    ni._cache._cache = state
    ni._cache._cache_ts = time.time()
    _test_assert(ni.bridge_mac_for_ip(IPv4Address("10.0.0.5")) == "aa:bb:cc:dd:ee:ff", "found")
    _test_assert(ni.bridge_mac_for_ip(IPv4Address("192.168.1.1")) is None, "unknown")


def test_netlink_info_is_bridge_mac() -> None:
    """NetlinkInfo.is_bridge_mac: True for any bridge iface MAC."""
    ni = NetlinkInfo(["vmbr0"], None)
    state = build_netlink_state_for_test(
        ["vmbr0"],
        [LinkInfo(1, "vmbr0", "aa:bb:cc:dd:ee:ff")],
        [AddrInfo(1, "10.0.0.5", 24, 0)],
    )
    ni._cache._cache = state
    ni._cache._cache_ts = time.time()
    _test_assert(ni.is_bridge_mac(MACAddress("aa:bb:cc:dd:ee:ff")), "bridge MAC")
    _test_assert(not ni.is_bridge_mac(MACAddress("00:00:00:00:00:01")), "other")


def test_netlink_info_get_bridge_names_with_ips() -> None:
    """NetlinkInfo.get_bridge_names_with_ips: set of bridge-like names with IPs."""
    ni = NetlinkInfo([], None)
    links = [LinkInfo(1, "vmbr00", "m")]
    addrs = [AddrInfo(1, "192.168.12.1", 24, 0)]
    state = build_netlink_state_for_test([], links, addrs)
    ni._cache._cache = state
    ni._cache._cache_ts = time.time()
    out = ni.get_bridge_names_with_ips()
    _test_assert(out == {"vmbr00"}, "single bridge")
    _test_assert(isinstance(out, set), "returns set")


def test_netlink_info_get_ips_per_interface() -> None:
    """NetlinkInfo.get_ips_per_interface: name -> [(ip, mac), ...]."""
    ni = NetlinkInfo([], None)
    links = [LinkInfo(1, "vmbr0", "mac:01"), LinkInfo(2, "eth0", "mac:02")]
    addrs = [AddrInfo(1, "10.0.0.1", 24, 0), AddrInfo(2, "192.168.1.1", 24, 0)]
    state = build_netlink_state_for_test([], links, addrs)
    ni._cache._cache = state
    ni._cache._cache_ts = time.time()
    out = ni.get_ips_per_interface({"vmbr0", "eth0"})
    _test_assert(out["vmbr0"] == [("10.0.0.1", "mac:01")], "vmbr0")
    _test_assert(out["eth0"] == [("192.168.1.1", "mac:02")], "eth0")
    out_empty = ni.get_ips_per_interface(set())
    _test_assert(out_empty == {}, "empty want")


def test_netlink_info_get_iface_ips() -> None:
    """NetlinkInfo.get_iface_ips: (name, addr, scope, mac) for ifaces."""
    ni = NetlinkInfo([], None)
    links = [LinkInfo(1, "vmbr0", "mac:01"), LinkInfo(2, "eth0", "mac:02")]
    addrs = [AddrInfo(1, "10.0.0.1", 24, 0), AddrInfo(2, "192.168.1.1", 24, 0)]
    state = build_netlink_state_for_test([], links, addrs)
    ni._cache._cache = state
    ni._cache._cache_ts = time.time()
    out = ni.get_iface_ips(["vmbr0", "eth0"])
    _test_assert(len(out) == 2, "two rows")
    by_name = {name: (addr, scope, mac) for name, addr, scope, mac in out}
    _test_assert(by_name["vmbr0"] == ("10.0.0.1", 0, "mac:01"), "vmbr0")
    _test_assert(by_name["eth0"] == ("192.168.1.1", 0, "mac:02"), "eth0")
    _test_assert(ni.get_iface_ips([]) == [], "empty list")


def test_netlink_state_has_no_raw_lists() -> None:
    """NetlinkState has no links/addrs; only typed result fields."""
    state = build_netlink_state_for_test([], [LinkInfo(1, "eth0", "m")], [AddrInfo(1, "10.0.0.1", 24, 0)])
    _test_assert(not hasattr(state, "links"), "no links")
    _test_assert(not hasattr(state, "addrs"), "no addrs")
    _test_assert(hasattr(state, "iface_ips") and isinstance(state.iface_ips, dict), "iface_ips present")
    _test_assert(hasattr(state, "bridge_names_with_ips"), "bridge_names_with_ips present")


def test_peer_tracker_track_and_get() -> None:
    """PeerTracker: track and get_active_peers_with_ttl."""
    from src.netlink import PeerTracker
    pt = PeerTracker(peer_timeout=10.0, peer_limit=5, global_limit=20)
    pt.track(MACAddress("aa:bb:cc:dd:ee:ff"), IPv4Address("10.0.0.2"))
    peers = pt.get_active_peers_with_ttl()
    _test_assert(len(peers) == 1, "one peer")
    _test_assert(peers[0][0] == MACAddress("aa:bb:cc:dd:ee:ff") and peers[0][1] == IPv4Address("10.0.0.2"), "peer content")


def test_peer_tracker_to_dict_load_from_dict() -> None:
    """PeerTracker: to_dict and load_from_dict roundtrip."""
    from src.netlink import PeerTracker
    pt = PeerTracker(peer_timeout=10.0, peer_limit=5, global_limit=20)
    pt.track(MACAddress("aa:bb:cc:dd:ee:ff"), IPv4Address("10.0.0.2"))
    d = pt.to_dict()
    _test_assert("peers" in d and len(d["peers"]) == 1, "to_dict")
    pt2 = PeerTracker(peer_timeout=10.0, peer_limit=5, global_limit=20)
    pt2.load_from_dict(d)
    peers = pt2.get_active_peers_with_ttl()
    _test_assert(len(peers) == 1 and str(peers[0][1]) == "10.0.0.2", "load_from_dict")


def test_invalidate_kernel_arp_deletes_matching_neigh() -> None:
    """invalidate_kernel_arp deletes matching neighbor."""
    ni = NetlinkInfo(["vmbr0"], None)

    class _NeighMsg:
        def __init__(self, lladdr: str) -> None:
            self._lladdr = lladdr

        def get_attr(self, name: str) -> str | None:
            if name == "NDA_LLADDR":
                return self._lladdr
            return None

    class _IPR:
        def __init__(self) -> None:
            self.deleted = False

        def link_lookup(self, ifname: str) -> list[int]:
            return [10] if ifname == "vmbr0" else []

        def get_neighbours(self, dst: str, ifindex: int, family: int) -> list[_NeighMsg]:
            _test_assert(dst == "10.0.0.20" and ifindex == 10, "neigh lookup")
            return [_NeighMsg("aa:bb:cc:dd:ee:20")]

        def neigh(self, action: str, dst: str, ifindex: int, family: int) -> None:
            _test_assert(action == "del" and dst == "10.0.0.20" and ifindex == 10, "neigh del args")
            self.deleted = True

        def close(self) -> None:
            return None

    fake = _IPR()
    with patch("src.netlink.IPRoute", return_value=fake):
        ok = ni.invalidate_kernel_arp(
            IPv4Address("10.0.0.20"),
            bridge="vmbr0",
            mac=MACAddress("aa:bb:cc:dd:ee:20"),
        )
    _test_assert(ok and fake.deleted, "deleted matching neigh")
