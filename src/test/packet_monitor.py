"""Tests for src.packet_monitor."""
from __future__ import annotations

import logging
import time
from typing import Optional, Callable
from unittest.mock import MagicMock, patch
from src.types import MACAddress, IPv4Address, BridgeName, InterfaceName, NodeID, OFPort, VMID
from src.models import InstanceInfo, InstanceStore, IPEntryStore, IPEntry
from src.config import Config
from src.packet_monitor import PacketMonitor, ArpRefresher
from src.logging_util import DEBUG_ARP_REPLY
from src.test import _test_assert

try:
    from scapy.all import Ether, ARP, Dot1Q, UDP, BOOTP
except ImportError:
    Ether = ARP = Dot1Q = UDP = BOOTP = None  # type: ignore[misc, assignment]


def test_packet_monitor_inject_config_ips() -> None:
    """PacketMonitor.inject_config_ips feeds LXC config IPs into store (IP-centric)."""
    log = logging.getLogger("test")
    instances = InstanceStore()
    mac = MACAddress("aa:bb:cc:dd:ee:ff")
    ip = IPv4Address("192.168.1.1")
    instances.set(mac, InstanceInfo(vmid=VMID("100"), type="lxc", bridge=BridgeName("vmbr0"), mac=mac, ip=ip))
    entries = IPEntryStore()
    cfg = Config(bridges=["vmbr0"])
    ovs_mock = MagicMock()
    of_mock = MagicMock()
    with patch(f"src.packet_monitor.NetlinkInfo", MagicMock(return_value=MagicMock())):
        mon = PacketMonitor(instances, entries, log, ovs_mock, of_mock, cfg, node_id=NodeID("testnode"))
    mon.inject_config_ips()
    e = entries.get(ip, BridgeName("vmbr0"), None)
    _test_assert(e is not None and e.ipv4 == ip and e.mac == mac and "proxmox" in (e.snoop_origin or []), "inject_config_ips")


def test_packet_monitor_resolve_in_port() -> None:
    """PacketMonitor._resolve_in_port with mocked OVSManager."""
    log = logging.getLogger("test")
    instances = InstanceStore()
    entries = IPEntryStore()
    cfg = Config(bridges=["vmbr0"], arp_reply_local_fallback=True)
    ovs_mock = MagicMock()
    ovs_mock.get_bridge_node_to_ofport.return_value = {NodeID("n2"): (OFPort("5"), InterfaceName("vxlan1"))}
    ovs_mock.get_bridge_vlan_to_local_port.return_value = {}
    netlink_mock = MagicMock()
    netlink_mock.get_bridge_names_with_ips.return_value = set()
    of_mock = MagicMock()
    with patch(f"src.packet_monitor.NetlinkInfo", MagicMock(return_value=netlink_mock)):
        mon = PacketMonitor(instances, entries, log, ovs_mock, of_mock, cfg, node_id=NodeID("n1"))
    port, name = mon._resolve_in_port(BridgeName("vmbr0"), NodeID("n2"))
    _test_assert(port == "5" and name == "vxlan1", "resolve remote node")
    port2, _ = mon._resolve_in_port(BridgeName("vmbr0"), NodeID("n99"))
    _test_assert(port2 is None, "fallback LOCAL -> skip (do not send with LOCAL)")
    port3, _ = mon._resolve_in_port(BridgeName("vmbr0"), None)
    _test_assert(port3 is None, "local no patch port -> skip")
    ovs_mock.get_bridge_vlan_to_local_port.return_value = {"vmbr0": {99: ("3", "patch-0-00-99")}}
    port4, name4 = mon._resolve_in_port(BridgeName("vmbr0"), None, vlan=99)
    _test_assert(port4 == "3" and name4 == "patch-0-00-99", "local with patch port")
    ovs_mock.get_bridge_vlan_to_local_port.return_value = {
        "vmbr0": {10: ("5", "dpatch-0-00-10"), 99: ("40", "patch-0-00-99")},
    }
    netlink_mock.get_bridge_names_with_ips.return_value = {"vmbr00"}
    port5, name5 = mon._resolve_in_port(BridgeName("vmbr0"), None, vlan=None)
    _test_assert(port5 == "5" and name5 == "dpatch-0-00-10", "local vlan None uses first patch port")


def test_check_arp_flood() -> None:
    """PacketMonitor._check_arp_flood: no log when under threshold; warning + top MACs when over."""
    log = MagicMock(spec=logging.Logger)
    instances = InstanceStore()
    entries = IPEntryStore()
    cfg = Config(bridges=["vmbr0"], arp_flood_threshold=50)
    ovs_mock = MagicMock()
    of_mock = MagicMock()
    with patch(f"src.packet_monitor.NetlinkInfo", MagicMock(return_value=MagicMock())):
        mon = PacketMonitor(instances, entries, log, ovs_mock, of_mock, cfg, node_id=NodeID("n1"))
    bridge = BridgeName("vmbr0")
    mac = MACAddress("aa:bb:cc:dd:ee:ff")
    with patch("time.time", return_value=1000.0):
        for _ in range(50):
            mon._check_arp_flood(bridge, mac)
    _test_assert(log.warning.call_count == 0, "no warning under threshold")
    with patch("time.time", side_effect=[1000.0] * 50 + [1001.0]):
        for _ in range(51):
            mon._check_arp_flood(bridge, mac)
    _test_assert(log.warning.call_count >= 1, "warning when over threshold")
    args = log.warning.call_args[0]
    msg = args[0] if args else ""
    _test_assert("ARP flood" in msg and "pkt/s" in msg, "message has ARP flood and rate")
    _test_assert(len(args) >= 4 and args[2] >= 50, "rate at least threshold")
    _test_assert("aa:bb:cc:dd:ee:ff" in str(args[4]), "top sources MAC in message")
    cfg0 = Config(bridges=["vmbr0"], arp_flood_threshold=0)
    with patch(f"src.packet_monitor.NetlinkInfo", MagicMock(return_value=MagicMock())):
        mon0 = PacketMonitor(instances, entries, log, ovs_mock, of_mock, cfg0)
    mon0._check_arp_flood(bridge, mac)
    mon0._check_arp_flood(bridge, mac)
    _test_assert(not mon0._arp_flood_count, "no count when threshold 0")


def test_packet_monitor_arp_reply_lookup_by_ip() -> None:
    """_do_arp_reply uses IPEntryStore.get(ip, bridge) for reply MAC."""
    log = logging.getLogger("test")
    instances = InstanceStore()
    entries = IPEntryStore()
    ip = IPv4Address("10.0.0.1")
    mac = MACAddress("aa:bb:cc:dd:ee:ff")
    entries.set(IPEntry(ipv4=ip, mac=mac, bridge=BridgeName("vmbr0"), last_seen=1.0))
    cfg = Config(bridges=["vmbr0"])
    ovs_mock = MagicMock()
    ovs_mock.get_bridge_vlan_to_local_port.return_value = {}
    of_mock = MagicMock()
    of_mock.send_packet_out.return_value = True
    netlink_mock = MagicMock()
    netlink_mock.get_bridge_names_with_ips.return_value = set()
    with patch(f"src.packet_monitor.NetlinkInfo", MagicMock(return_value=netlink_mock)):
        mon = PacketMonitor(instances, entries, log, ovs_mock, of_mock, cfg, node_id=NodeID("n1"))
    from scapy.all import Ether, ARP
    pkt = Ether(src="00:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc="10.0.0.2", pdst="10.0.0.1")
    ok = mon._do_arp_reply(pkt, BridgeName("vmbr0"), "test")
    _test_assert(ok is False, "local reply skipped (no in_port)")
    _test_assert(entries.get(ip, BridgeName("vmbr0"), None).mac == mac, "store keyed by IP")


def _make_monitor(
    entries: IPEntryStore,
    bridge: str = "vmbr0",
    arp_reply: bool = True,
    resolve_port: Optional[str] = None,
    arp_reply_strict_vlan: bool = True,
    arp_reply_no_vlan: bool = True,
    arp_reply_localize_vlan: bool = True,
    debug_flags: int = 0,
    local_vlans: Optional[set[int]] = None,
) -> PacketMonitor:
    """Minimal PacketMonitor with optional _resolve_in_port returning in_port."""
    log = logging.getLogger("test")
    instances = InstanceStore()
    cfg = Config(
        bridges=[bridge],
        arp_reply=arp_reply,
        arp_reply_strict_vlan=arp_reply_strict_vlan,
        arp_reply_no_vlan=arp_reply_no_vlan,
        arp_reply_localize_vlan=arp_reply_localize_vlan,
        debug_flags=debug_flags,
    )
    ovs_mock = MagicMock()
    ovs_mock.get_bridge_vlan_to_local_port.return_value = {}
    ovs_mock.get_bridge_node_to_ofport.return_value = {}
    of_mock = MagicMock()
    of_mock.send_packet_out.return_value = True
    netlink_mock = MagicMock()
    netlink_mock.get_bridge_names_with_ips.return_value = set()
    with patch("src.packet_monitor.NetlinkInfo", MagicMock(return_value=netlink_mock)):
        get_local_vlans = (lambda: frozenset(local_vlans)) if local_vlans is not None else None
        mon = PacketMonitor(
            instances, entries, log, ovs_mock, of_mock, cfg, node_id=NodeID("n1"), peer_tracker=None, netlink=netlink_mock, get_local_vlans=get_local_vlans,
        )
    if resolve_port is not None:
        mon._resolve_in_port = lambda *args, **kwargs: (resolve_port, "patch-0")
    return mon


def test_get_arp_reply_entry_exact_and_fallbacks() -> None:
    """_get_arp_reply_entry: any active entry for (ip, bridge); reply sent on req_vlan."""
    entries = IPEntryStore()
    ip = IPv4Address("192.168.12.5")
    mac = MACAddress("aa:bb:cc:dd:ee:01")
    br = BridgeName("vmbr0")
    # last_seen recent so entry is active (mesh_ttl=990)
    now = 1000.0
    entries.set(IPEntry(ipv4=ip, mac=mac, bridge=br, vlan=12, last_seen=now - 100.0))
    mon = _make_monitor(entries)
    with patch("src.packet_monitor.time.time", return_value=now):
        e = mon._get_arp_reply_entry(ip, br, 12)
    _test_assert(e is not None and e.mac == mac and e.vlan == 12, "any active entry (vlan 12)")

    with patch("src.packet_monitor.time.time", return_value=now):
        e2 = mon._get_arp_reply_entry(ip, br, None)
    _test_assert(e2 is not None and e2.mac == mac, "untagged request finds same entry")

    entries.set(IPEntry(ipv4=ip, mac=MACAddress("aa:bb:cc:dd:ee:02"), bridge=br, vlan=None, last_seen=now - 50.0))
    with patch("src.packet_monitor.time.time", return_value=now):
        e3 = mon._get_arp_reply_entry(ip, br, None)
    _test_assert(e3 is not None, "any active entry for (ip, br)")
    with patch("src.packet_monitor.time.time", return_value=now):
        e4 = mon._get_arp_reply_entry(ip, br, 99)
    _test_assert(e4 is not None, "req vlan 99 still returns entry (reply on req vlan)")


def test_get_arp_reply_entry_negative() -> None:
    """_get_arp_reply_entry: no entry, wrong bridge, expired -> None."""
    entries = IPEntryStore()
    ip = IPv4Address("192.168.12.5")
    br0 = BridgeName("vmbr0")
    br1 = BridgeName("vmbr1")
    now = 1000.0
    entries.set(IPEntry(ipv4=ip, mac=MACAddress("aa:bb:cc:dd:ee:ff"), bridge=br0, vlan=12, last_seen=now - 100.0))
    mon = _make_monitor(entries)
    with patch("src.packet_monitor.time.time", return_value=now):
        _test_assert(mon._get_arp_reply_entry(ip, br1, 12) is None, "wrong bridge -> None")
        _test_assert(mon._get_arp_reply_entry(ip, br1, None) is None, "wrong bridge untagged -> None")
        _test_assert(
            mon._get_arp_reply_entry(IPv4Address("192.168.12.99"), br0, 12) is None,
            "unknown IP -> None",
        )
    # req vlan 99 with only vlan 12 entry: we return that entry (reply on req vlan)
    with patch("src.packet_monitor.time.time", return_value=now):
        e = mon._get_arp_reply_entry(ip, br0, 99)
    _test_assert(e is not None and e.vlan == 12, "any active entry returned; reply on req vlan")


def test_do_arp_reply_handles_all_arp_packets() -> None:
    """_do_arp_reply sends reply on request VLAN (any active entry for ip, bridge)."""
    if Ether is None or ARP is None:
        raise AssertionError("scapy required")
    entries = IPEntryStore()
    ip = IPv4Address("192.168.12.5")
    mac = MACAddress("aa:bb:cc:dd:ee:ff")
    br = BridgeName("vmbr0")
    now = 1000.0
    entries.set(IPEntry(ipv4=ip, mac=mac, bridge=br, vlan=None, last_seen=now - 100.0))
    mon = _make_monitor(entries, resolve_port="3")

    with patch("src.packet_monitor.time.time", return_value=now):
        pkt_untagged = Ether(src="00:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=1, psrc="192.168.13.183", pdst="192.168.12.5"
        )
        ok = mon._do_arp_reply(pkt_untagged, br, "test")
    _test_assert(ok is True, "untagged who-has -> reply sent")
    _test_assert(mon.of_manager.send_packet_out.called, "send_packet_out called")

    mon.of_manager.send_packet_out.reset_mock()
    entries.discard((ip, br, None))
    entries.set(IPEntry(ipv4=ip, mac=mac, bridge=br, vlan=12, last_seen=now - 50.0))

    if Dot1Q is not None:
        with patch("src.packet_monitor.time.time", return_value=now):
            pkt_tagged = Ether(src="00:00:00:00:00:02", dst="ff:ff:ff:ff:ff:ff") / Dot1Q(vlan=12) / ARP(
                op=1, psrc="192.168.13.183", pdst="192.168.12.5"
            )
            ok2 = mon._do_arp_reply(pkt_tagged, br, "test")
        _test_assert(ok2 is True, "tagged who-has vlan 12 -> reply sent")
    mon.of_manager.send_packet_out.reset_mock()
    with patch("src.packet_monitor.time.time", return_value=now):
        pkt_untagged2 = Ether(src="00:00:00:00:00:03", dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=1, psrc="192.168.13.183", pdst="192.168.12.5"
        )
        ok3 = mon._do_arp_reply(pkt_untagged2, br, "test")
    _test_assert(ok3 is True, "untagged who-has finds any active entry (reply on req vlan)")


def test_do_arp_reply_negative() -> None:
    """_do_arp_reply: no entry, not who-has, no pdst, arp_reply disabled."""
    if Ether is None or ARP is None:
        raise AssertionError("scapy required")
    entries = IPEntryStore()
    ip = IPv4Address("192.168.12.5")
    mac = MACAddress("aa:bb:cc:dd:ee:ff")
    br = BridgeName("vmbr0")
    now = 1000.0
    entries.set(IPEntry(ipv4=ip, mac=mac, bridge=br, last_seen=now - 100.0))
    mon = _make_monitor(entries, resolve_port="3")

    # no entry for requested IP
    pkt = Ether(src="00:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, psrc="192.168.13.183", pdst="192.168.12.99"
    )
    ok = mon._do_arp_reply(pkt, br, "test")
    _test_assert(ok is False, "no entry for pdst -> no reply")
    _test_assert(not mon.of_manager.send_packet_out.called, "send_packet_out not called")

    # ARP reply (op=2) not request -> ignore
    pkt_reply = Ether(src="00:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2, psrc="192.168.12.5", pdst="192.168.13.183", hwsrc=mac, hwdst="00:00:00:00:00:01"
    )
    ok2 = mon._do_arp_reply(pkt_reply, br, "test")
    _test_assert(ok2 is False, "ARP reply op=2 -> no reply sent")

    # config arp_reply=False: fast path skips
    mon_no_arp = _make_monitor(entries, resolve_port="3", arp_reply=False)
    pkt_req = Ether(src="00:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, psrc="192.168.13.183", pdst="192.168.12.5"
    )
    ok3 = mon_no_arp._send_arp_reply_fast(pkt_req, br)
    _test_assert(ok3 is False, "arp_reply disabled -> fast path False")

    # strict=True, arp_reply_no_vlan=False: untagged request for vlan=99 entry -> no reply
    entries_v99 = IPEntryStore()
    entries_v99.set(IPEntry(ipv4=ip, mac=mac, bridge=br, vlan=99, last_seen=now - 100.0))
    mon_strict_no_vlan_off = _make_monitor(
        entries_v99, resolve_port="3", arp_reply_strict_vlan=True, arp_reply_no_vlan=False,
    )
    with patch("src.packet_monitor.time.time", return_value=now):
        ok_untagged = mon_strict_no_vlan_off._do_arp_reply(pkt_req, br, "test")
    _test_assert(ok_untagged is False, "strict+no_vlan off: untagged request -> no reply")
    if Dot1Q is not None:
        pkt_v98 = Ether(src="00:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff") / Dot1Q(vlan=98) / ARP(
            op=1, psrc="192.168.13.183", pdst="192.168.12.5"
        )
        with patch("src.packet_monitor.time.time", return_value=now):
            ok_v98 = mon_strict_no_vlan_off._do_arp_reply(pkt_v98, br, "test")
        _test_assert(ok_v98 is False, "strict: vlan 98 request for vlan 99 entry -> no reply")
    mon_strict_no_vlan_on = _make_monitor(
        entries_v99, resolve_port="3", arp_reply_strict_vlan=True, arp_reply_no_vlan=True,
    )
    with patch("src.packet_monitor.time.time", return_value=now):
        ok_untagged_allow = mon_strict_no_vlan_on._do_arp_reply(pkt_req, br, "test")
    _test_assert(ok_untagged_allow is True, "strict+no_vlan on: untagged request -> reply")


def test_arp_reply_debug_flag_controls_logging() -> None:
    """DEBUG_ARP_REPLY flag enables vlan-mismatch and sent-reply debug logs."""
    if Ether is None or ARP is None:
        raise AssertionError("scapy required")
    entries = IPEntryStore()
    ip = IPv4Address("192.168.12.5")
    mac = MACAddress("aa:bb:cc:dd:ee:ff")
    br = BridgeName("vmbr0")
    now = 1000.0
    # Entry on vlan 99 so strict+no_vlan off will skip untagged with vlan mismatch
    entries.set(IPEntry(ipv4=ip, mac=mac, bridge=br, vlan=99, last_seen=now - 100.0))
    mon = _make_monitor(entries, resolve_port="3", arp_reply_strict_vlan=True, arp_reply_no_vlan=False, debug_flags=0)
    mon.log = MagicMock(spec=logging.Logger)
    pkt_req = Ether(src="00:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, psrc="192.168.13.183", pdst=str(ip)
    )
    with patch("src.packet_monitor.time.time", return_value=now):
        _ = mon._do_arp_reply(pkt_req, br, "test")
    mon.log.debug.assert_not_called()

    # With flag set, expect at least one debug() call for vlan mismatch
    mon_flag = _make_monitor(
        entries,
        resolve_port="3",
        arp_reply_strict_vlan=True,
        arp_reply_no_vlan=False,
        debug_flags=DEBUG_ARP_REPLY,
    )
    mon_flag.log = MagicMock(spec=logging.Logger)
    with patch("src.packet_monitor.time.time", return_value=now):
        _ = mon_flag._do_arp_reply(pkt_req, br, "test")
    _test_assert(mon_flag.log.debug.call_count >= 1, "DEBUG_ARP_REPLY triggers debug logs")


def test_do_arp_reply_strict_vlan_no_vlan_matrix() -> None:
    """_do_arp_reply: strict_vlan and arp_reply_no_vlan allow/deny matrix; positive and negative."""
    if Ether is None or ARP is None:
        raise AssertionError("scapy required")
    ip = IPv4Address("192.168.12.5")
    mac = MACAddress("aa:bb:cc:dd:ee:ff")
    br = BridgeName("vmbr0")
    now = 1000.0

    def make_pkt(req_vlan: Optional[int]):
        if req_vlan is None:
            return Ether(src="00:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=1, psrc="192.168.13.183", pdst="192.168.12.5"
            )
        if Dot1Q is None:
            raise AssertionError("Dot1Q required for tagged")
        return (
            Ether(src="00:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff")
            / Dot1Q(vlan=req_vlan)
            / ARP(op=1, psrc="192.168.13.183", pdst="192.168.12.5")
        )

    # --- Entry tagged (vlan 99) ---
    entries_tagged = IPEntryStore()
    entries_tagged.set(IPEntry(ipv4=ip, mac=mac, bridge=br, vlan=99, last_seen=now - 100.0))

    # strict=True, no_vlan=False: only vlan 99 request -> reply; untagged and vlan 98 -> no reply
    mon = _make_monitor(
        entries_tagged, resolve_port="3",
        arp_reply_strict_vlan=True, arp_reply_no_vlan=False,
    )
    with patch("src.packet_monitor.time.time", return_value=now):
        _test_assert(
            mon._do_arp_reply(make_pkt(99), br, "test") is True,
            "strict, no_vlan off: vlan 99 request -> reply",
        )
    mon.of_manager.send_packet_out.reset_mock()
    with patch("src.packet_monitor.time.time", return_value=now):
        _test_assert(
            mon._do_arp_reply(make_pkt(None), br, "test") is False,
            "strict, no_vlan off: untagged request -> no reply (negative)",
        )
    _test_assert(not mon.of_manager.send_packet_out.called, "send_packet_out not called after untagged")
    if Dot1Q is not None:
        with patch("src.packet_monitor.time.time", return_value=now):
            _test_assert(
                mon._do_arp_reply(make_pkt(98), br, "test") is False,
                "strict, no_vlan off: vlan 98 request -> no reply (negative)",
            )

    # strict=True, no_vlan=True: vlan 99 and untagged -> reply; vlan 98 -> no reply
    mon2 = _make_monitor(
        entries_tagged, resolve_port="3",
        arp_reply_strict_vlan=True, arp_reply_no_vlan=True,
    )
    with patch("src.packet_monitor.time.time", return_value=now):
        _test_assert(mon2._do_arp_reply(make_pkt(99), br, "test") is True, "strict+no_vlan: vlan 99 -> reply")
    mon2.of_manager.send_packet_out.reset_mock()
    with patch("src.packet_monitor.time.time", return_value=now):
        _test_assert(mon2._do_arp_reply(make_pkt(None), br, "test") is True, "strict+no_vlan: untagged -> reply")
    if Dot1Q is not None:
        mon2.of_manager.send_packet_out.reset_mock()
        with patch("src.packet_monitor.time.time", return_value=now):
            _test_assert(
                mon2._do_arp_reply(make_pkt(98), br, "test") is False,
                "strict+no_vlan: vlan 98 request -> no reply (negative)",
            )

    # strict=False: any request vlan (99, 98, untagged) -> reply
    mon3 = _make_monitor(
        entries_tagged, resolve_port="3",
        arp_reply_strict_vlan=False, arp_reply_no_vlan=False,
    )
    with patch("src.packet_monitor.time.time", return_value=now):
        _test_assert(mon3._do_arp_reply(make_pkt(99), br, "test") is True, "not strict: vlan 99 -> reply")
    with patch("src.packet_monitor.time.time", return_value=now):
        _test_assert(mon3._do_arp_reply(make_pkt(None), br, "test") is True, "not strict: untagged -> reply")
    if Dot1Q is not None:
        with patch("src.packet_monitor.time.time", return_value=now):
            _test_assert(mon3._do_arp_reply(make_pkt(98), br, "test") is True, "not strict: vlan 98 -> reply")

    # --- Entry untagged (vlan None) ---
    entries_untagged = IPEntryStore()
    entries_untagged.set(IPEntry(ipv4=ip, mac=mac, bridge=br, vlan=None, last_seen=now - 100.0))

    # strict=True: no learned vlan -> visible on all vlans (reply to any request vlan)
    mon4 = _make_monitor(
        entries_untagged, resolve_port="3",
        arp_reply_strict_vlan=True, arp_reply_no_vlan=False,
    )
    with patch("src.packet_monitor.time.time", return_value=now):
        _test_assert(
            mon4._do_arp_reply(make_pkt(None), br, "test") is True,
            "strict, untagged entry: untagged request -> reply",
        )
    if Dot1Q is not None:
        with patch("src.packet_monitor.time.time", return_value=now):
            _test_assert(
                mon4._do_arp_reply(make_pkt(99), br, "test") is True,
                "strict, no learned vlan: visible on all vlans, vlan 99 request -> reply",
            )


def test_do_arp_reply_no_learned_vlan_visible_on_all_vlans() -> None:
    """No learned vlan (bridge IP, etc.): strict_vlan still allows reply on any request vlan."""
    if Ether is None or ARP is None:
        raise AssertionError("scapy required")
    ip = IPv4Address("192.168.12.2")
    mac = MACAddress("82:51:f3:21:c9:47")
    br = BridgeName("vmbr0")
    now = 1000.0
    entries = IPEntryStore()
    entries.set(IPEntry(ipv4=ip, mac=mac, bridge=br, vlan=None, last_seen=now - 100.0))

    def make_pkt(req_vlan: Optional[int]):
        if req_vlan is None:
            return Ether(src="00:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=1, psrc="172.16.12.10", pdst="192.168.12.2"
            )
        if Dot1Q is None:
            raise AssertionError("Dot1Q required for tagged")
        return (
            Ether(src="00:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff")
            / Dot1Q(vlan=req_vlan)
            / ARP(op=1, psrc="172.16.12.10", pdst="192.168.12.2")
        )

    mon = _make_monitor(
        entries, resolve_port="3",
        arp_reply_strict_vlan=True, arp_reply_no_vlan=False,
    )
    with patch("src.packet_monitor.time.time", return_value=now):
        _test_assert(
            mon._do_arp_reply(make_pkt(None), br, "test") is True,
            "no learned vlan: untagged request -> reply",
        )
    if Dot1Q is not None:
        with patch("src.packet_monitor.time.time", return_value=now):
            _test_assert(
                mon._do_arp_reply(make_pkt(10), br, "test") is True,
                "no learned vlan: vlan 10 request -> reply (visible on all vlans)",
            )
        with patch("src.packet_monitor.time.time", return_value=now):
            _test_assert(
                mon._do_arp_reply(make_pkt(99), br, "test") is True,
                "no learned vlan: vlan 99 request -> reply (visible on all vlans)",
            )


def test_do_arp_reply_remote_localize_vlan_uses_entry_vlan() -> None:
    """Remote entry with vlan in local_vlans: strict+remote-vlan still replies (localized to entry vlan)."""
    if Ether is None or ARP is None or Dot1Q is None:
        raise AssertionError("scapy with Dot1Q required")
    ip = IPv4Address("192.168.12.20")
    mac = MACAddress("aa:bb:cc:dd:ee:20")
    br = BridgeName("vmbr0")
    now = 1000.0
    entries = IPEntryStore()
    entries.set(IPEntry(ipv4=ip, mac=mac, bridge=br, vlan=100, node=NodeID("other-node"), last_seen=now - 100.0))

    def make_pkt(req_vlan: int):
        return (
            Ether(src="00:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff")
            / Dot1Q(vlan=req_vlan)
            / ARP(op=1, psrc="172.16.12.10", pdst=str(ip))
        )

    # With remote_vlan=10 and no localization, strict vlan would block (req 100 != 10).
    mon_no_local = _make_monitor(
        entries,
        resolve_port="3",
        arp_reply_strict_vlan=True,
        arp_reply_no_vlan=False,
        arp_reply_localize_vlan=False,
        local_vlans=None,
    )
    mon_no_local.config.arp_reply_remote_vlan = 10
    with patch("src.packet_monitor.time.time", return_value=now):
        ok_no_local = mon_no_local._do_arp_reply(make_pkt(100), br, "test")
    _test_assert(ok_no_local is False, "remote, no localize: remote_vlan causes strict mismatch -> no reply")

    # With localization and vlan 100 marked local, reply should succeed.
    mon_local = _make_monitor(
        entries,
        resolve_port="3",
        arp_reply_strict_vlan=True,
        arp_reply_no_vlan=False,
        arp_reply_localize_vlan=True,
        local_vlans={100},
    )
    mon_local.config.arp_reply_remote_vlan = 10
    with patch("src.packet_monitor.time.time", return_value=now):
        ok_local = mon_local._do_arp_reply(make_pkt(100), br, "test")
    _test_assert(ok_local is True, "remote, localize: vlan 100 treated as local -> reply allowed")


def test_do_arp_reply_remote_localize_vlan_callback_exception() -> None:
    """_do_arp_reply handles local VLAN callback exception without crashing."""
    if Ether is None or ARP is None or Dot1Q is None:
        raise AssertionError("scapy with Dot1Q required")
    ip = IPv4Address("192.168.12.21")
    br = BridgeName("vmbr0")
    now = 1000.0
    entries = IPEntryStore()
    entries.set(
        IPEntry(
            ipv4=ip,
            mac=MACAddress("aa:bb:cc:dd:ee:21"),
            bridge=br,
            vlan=100,
            node=NodeID("other-node"),
            last_seen=now - 100.0,
        )
    )
    mon = _make_monitor(entries, resolve_port="3", arp_reply_strict_vlan=True, arp_reply_no_vlan=False, arp_reply_localize_vlan=True)
    mon.config.arp_reply_remote_vlan = 10
    mon._get_local_vlans = lambda: (_ for _ in ()).throw(RuntimeError("boom"))
    pkt = Ether(src="00:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff") / Dot1Q(vlan=100) / ARP(op=1, psrc="172.16.12.10", pdst=str(ip))
    with patch("src.packet_monitor.time.time", return_value=now):
        ok = mon._do_arp_reply(pkt, br, "test")
    _test_assert(ok is False, "callback error falls back to non-localized behavior")


def test_do_arp_reply_remote_localize_vlan_callback_none() -> None:
    """_do_arp_reply handles non-container local VLAN callback result safely."""
    if Ether is None or ARP is None or Dot1Q is None:
        raise AssertionError("scapy with Dot1Q required")
    ip = IPv4Address("192.168.12.22")
    br = BridgeName("vmbr0")
    now = 1000.0
    entries = IPEntryStore()
    entries.set(
        IPEntry(
            ipv4=ip,
            mac=MACAddress("aa:bb:cc:dd:ee:22"),
            bridge=br,
            vlan=100,
            node=NodeID("other-node"),
            last_seen=now - 100.0,
        )
    )
    mon = _make_monitor(entries, resolve_port="3", arp_reply_strict_vlan=True, arp_reply_no_vlan=False, arp_reply_localize_vlan=True)
    mon.config.arp_reply_remote_vlan = 10
    mon._get_local_vlans = lambda: None
    pkt = Ether(src="00:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff") / Dot1Q(vlan=100) / ARP(op=1, psrc="172.16.12.10", pdst=str(ip))
    with patch("src.packet_monitor.time.time", return_value=now):
        ok = mon._do_arp_reply(pkt, br, "test")
    _test_assert(ok is False, "invalid callback result should not crash and should skip reply")


def test_do_arp_reply_negative_invalid_packet() -> None:
    """_do_arp_reply: invalid or malformed packet -> no reply (negative)."""
    if Ether is None or ARP is None:
        raise AssertionError("scapy required")
    entries = IPEntryStore()
    ip = IPv4Address("192.168.12.5")
    mac = MACAddress("aa:bb:cc:dd:ee:ff")
    br = BridgeName("vmbr0")
    now = 1000.0
    entries.set(IPEntry(ipv4=ip, mac=mac, bridge=br, last_seen=now - 100.0))
    mon = _make_monitor(entries, resolve_port="3")

    # no Ether layer: ensure we don't crash and return False
    pkt_no_ether = ARP(op=1, psrc="192.168.13.183", pdst="192.168.12.5")
    with patch("src.packet_monitor.time.time", return_value=now):
        ok = mon._do_arp_reply(pkt_no_ether, br, "test")
    _test_assert(ok is False, "packet without Ether -> no reply (negative)")
    _test_assert(not mon.of_manager.send_packet_out.called, "send_packet_out not called")

    # wrong bridge: entry on vmbr0, request on vmbr1 -> no entry for (ip, vmbr1)
    br_other = BridgeName("vmbr1")
    pkt = Ether(src="00:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, psrc="192.168.13.183", pdst="192.168.12.5"
    )
    with patch("src.packet_monitor.time.time", return_value=now):
        ok2 = mon._do_arp_reply(pkt, br_other, "test")
    _test_assert(ok2 is False, "request on bridge with no entry -> no reply (negative)")


def test_do_arp_reply_invalid_pdst_no_crash() -> None:
    """_do_arp_reply returns False for invalid ARP.pdst."""
    if Ether is None or ARP is None:
        raise AssertionError("scapy required")
    entries = IPEntryStore()
    br = BridgeName("vmbr0")
    mon = _make_monitor(entries, resolve_port="3")
    pkt = Ether(src="00:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, psrc="192.168.13.183", pdst="not-an-ip"
    )
    ok = mon._do_arp_reply(pkt, br, "test")
    _test_assert(ok is False, "invalid pdst -> no reply, no crash")


def test_parse_packet_info_dhcp() -> None:
    """_parse_packet_info returns (mac, ip, dhcp, vlan) for DHCP with yiaddr or ciaddr."""
    if Ether is None or UDP is None or BOOTP is None:
        raise AssertionError("scapy required")
    entries = IPEntryStore()
    mon = _make_monitor(entries)
    br = BridgeName("vmbr0")

    # DHCP offer/ACK: server sets yiaddr (assigned IP)
    pkt_yiaddr = (
        Ether(src="aa:bb:cc:dd:ee:11", dst="ff:ff:ff:ff:ff:ff")
        / UDP(sport=67, dport=68)
        / BOOTP(yiaddr="192.168.10.50", ciaddr="0.0.0.0")
    )
    parsed = mon._parse_packet_info(pkt_yiaddr, br)
    _test_assert(parsed is not None, "DHCP with yiaddr parsed")
    mac, ip, ptype, vlan_id = parsed
    _test_assert(ptype == "dhcp", "ptype dhcp")
    _test_assert(str(mac).lower() == "aa:bb:cc:dd:ee:11", "mac from Ether.src")
    _test_assert(str(ip) == "192.168.10.50", "ip from yiaddr")
    _test_assert(vlan_id is None, "untagged vlan None")

    # DHCP request/renew: client has ciaddr
    pkt_ciaddr = (
        Ether(src="aa:bb:cc:dd:ee:22", dst="ff:ff:ff:ff:ff:ff")
        / UDP(sport=68, dport=67)
        / BOOTP(yiaddr="0.0.0.0", ciaddr="192.168.10.51")
    )
    parsed2 = mon._parse_packet_info(pkt_ciaddr, br)
    _test_assert(parsed2 is not None, "DHCP with ciaddr parsed")
    _, ip2, ptype2, _ = parsed2
    _test_assert(ptype2 == "dhcp" and str(ip2) == "192.168.10.51", "ip from ciaddr")

    # DHCP relayed/request path: use BOOTP chaddr over Ether.src
    pkt_chaddr = (
        Ether(src="46:22:81:68:97:4a", dst="bc:24:11:aa:aa:01")
        / UDP(sport=67, dport=67)
        / BOOTP(
            yiaddr="0.0.0.0",
            ciaddr="172.16.12.254",
            chaddr=b"\xbc$\x11.[\xe5" + (b"\x00" * 10),
        )
    )
    parsed_chaddr = mon._parse_packet_info(pkt_chaddr, br)
    _test_assert(parsed_chaddr is not None, "DHCP with chaddr parsed")
    mac3, ip3, ptype3, _ = parsed_chaddr
    _test_assert(ptype3 == "dhcp", "ptype dhcp with chaddr")
    _test_assert(str(mac3).lower() == "bc:24:11:2e:5b:e5", "mac from BOOTP chaddr")
    _test_assert(str(ip3) == "172.16.12.254", "ip from ciaddr with chaddr")

    # No usable IP -> None
    pkt_no_ip = (
        Ether(src="aa:bb:cc:dd:ee:33", dst="ff:ff:ff:ff:ff:ff")
        / UDP(sport=67, dport=68)
        / BOOTP(yiaddr="0.0.0.0", ciaddr="0.0.0.0")
    )
    parsed3 = mon._parse_packet_info(pkt_no_ip, br)
    _test_assert(parsed3 is None, "DHCP yiaddr/ciaddr both zero -> None")


def test_parse_packet_info_invalid_ip_no_crash() -> None:
    """_parse_packet_info returns None for malformed ARP IP fields."""
    if Ether is None or ARP is None:
        raise AssertionError("scapy required")
    entries = IPEntryStore()
    mon = _make_monitor(entries)
    br = BridgeName("vmbr0")
    pkt_arp = Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, psrc="bad-ip", pdst="192.168.1.1"
    )
    _test_assert(mon._parse_packet_info(pkt_arp, br) is None, "bad ARP psrc -> None")


def test_parse_packet_info_arp_probe_filtered() -> None:
    """_parse_packet_info returns None for ARP probe (psrc=0.0.0.0) and broadcast psrc."""
    if Ether is None or ARP is None:
        raise AssertionError("scapy required")
    entries = IPEntryStore()
    mon = _make_monitor(entries)
    br = BridgeName("vmbr0")
    # RFC 5227 ARP probe: psrc=0.0.0.0
    pkt_probe = Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, psrc="0.0.0.0", pdst="192.168.1.10"
    )
    _test_assert(mon._parse_packet_info(pkt_probe, br) is None, "ARP probe psrc=0.0.0.0 -> None")
    # Broadcast psrc (invalid)
    pkt_bcast = Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, psrc="255.255.255.255", pdst="192.168.1.10"
    )
    _test_assert(mon._parse_packet_info(pkt_bcast, br) is None, "ARP psrc=255.255.255.255 -> None")


def test_parse_packet_info_arp_non_ethernet_filtered() -> None:
    """_parse_packet_info returns None for non-Ethernet/non-IPv4 ARP."""
    if Ether is None or ARP is None:
        raise AssertionError("scapy required")
    entries = IPEntryStore()
    mon = _make_monitor(entries)
    br = BridgeName("vmbr0")
    # hwtype=6 (IEEE 802) instead of 1 (Ethernet)
    pkt_bad_hw = Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff") / ARP(
        hwtype=6, ptype=0x0800, op=1, psrc="192.168.1.10", pdst="192.168.1.1"
    )
    _test_assert(mon._parse_packet_info(pkt_bad_hw, br) is None, "non-Ethernet hwtype -> None")
    # ptype != 0x0800 (e.g. IPX)
    pkt_bad_proto = Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff") / ARP(
        hwtype=1, ptype=0x8137, op=1, psrc="192.168.1.10", pdst="192.168.1.1"
    )
    _test_assert(mon._parse_packet_info(pkt_bad_proto, br) is None, "non-IPv4 ptype -> None")


def test_parse_packet_info_arp_mac_mismatch_rejected() -> None:
    """ARP with Ether.src != ARP.hwsrc is rejected (proxy ARP / spoofing)."""
    if Ether is None or ARP is None:
        raise AssertionError("scapy required")
    entries = IPEntryStore()
    mon = _make_monitor(entries)
    br = BridgeName("vmbr0")
    pkt = Ether(src="aa:bb:cc:dd:ee:01", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2, hwsrc="aa:bb:cc:dd:ee:99", psrc="192.168.1.10", pdst="192.168.1.1"
    )
    _test_assert(mon._parse_packet_info(pkt, br) is None, "mac mismatch -> None")
    _test_assert(mon._arp_mac_mismatch_count == 1, "mismatch counter incremented")


def test_parse_packet_info_arp_mac_match_accepted() -> None:
    """ARP with matching Ether.src and ARP.hwsrc passes validation."""
    if Ether is None or ARP is None:
        raise AssertionError("scapy required")
    entries = IPEntryStore()
    mon = _make_monitor(entries)
    br = BridgeName("vmbr0")
    pkt = Ether(src="aa:bb:cc:dd:ee:01", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, hwsrc="aa:bb:cc:dd:ee:01", psrc="192.168.1.10", pdst="192.168.1.1"
    )
    parsed = mon._parse_packet_info(pkt, br)
    _test_assert(parsed is not None, "matching MACs -> parsed")
    mac, ip, ptype, _ = parsed
    _test_assert(str(mac).lower() == "aa:bb:cc:dd:ee:01", "correct mac")
    _test_assert(str(ip) == "192.168.1.10", "correct ip")
    _test_assert(mon._arp_mac_mismatch_count == 0, "no mismatch counted")


def test_parse_bootp_chaddr_non_ethernet_htype() -> None:
    """_parse_bootp_chaddr returns None for non-Ethernet htype."""
    if BOOTP is None:
        raise AssertionError("scapy required")
    entries = IPEntryStore()
    mon = _make_monitor(entries)
    # htype=6 (IEEE 802): chaddr bytes should not be interpreted as Ethernet MAC
    bootp_pkt = BOOTP(htype=6, chaddr=b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x00" * 10)
    result = mon._parse_bootp_chaddr(bootp_pkt)
    _test_assert(result is None, "non-Ethernet htype -> None from _parse_bootp_chaddr")


def test_parse_ipv4_invalid_returns_none() -> None:
    """_parse_ipv4 returns None for invalid values."""
    _test_assert(PacketMonitor._parse_ipv4("not-an-ip") is None, "invalid text -> None")
    _test_assert(PacketMonitor._parse_ipv4("") is None, "empty text -> None")
    _test_assert(PacketMonitor._parse_ipv4(None) is None, "none -> None")


def test_handle_packet_dhcp_updates_store() -> None:
    """_handle_packet processes DHCP and updates store (mac, ip, origin dhcp)."""
    if Ether is None or UDP is None or BOOTP is None:
        raise AssertionError("scapy required")
    entries = IPEntryStore()
    netlink_mock = MagicMock()
    netlink_mock.ip_in_bridge_subnets.return_value = True
    netlink_mock.is_tap_mac.return_value = False
    netlink_mock.is_bridge_mac.return_value = False
    netlink_mock.bridge_mac_for_ip.return_value = None
    netlink_mock.is_host_local.return_value = False
    netlink_mock.get_bridge_names_with_ips.return_value = set()
    log = logging.getLogger("test")
    instances = InstanceStore()
    cfg = Config(bridges=["vmbr0"], snoop_bridge=True)
    ovs_mock = MagicMock()
    ovs_mock.get_bridge_vlan_to_local_port.return_value = {}
    of_mock = MagicMock()
    with patch("src.packet_monitor.NetlinkInfo", MagicMock(return_value=netlink_mock)):
        mon = PacketMonitor(instances, entries, log, ovs_mock, of_mock, cfg, node_id=NodeID("n1"))
    br = BridgeName("vmbr0")
    pkt = (
        Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff")
        / UDP(sport=67, dport=68)
        / BOOTP(yiaddr="192.168.10.100", ciaddr="0.0.0.0")
    )
    mon._handle_packet(pkt, br)
    entry = entries.get(IPv4Address("192.168.10.100"), br, None)
    _test_assert(entry is not None, "DHCP processed -> entry in store")
    _test_assert(entry.mac == MACAddress("aa:bb:cc:dd:ee:ff"), "mac from packet")
    _test_assert("dhcp" in (entry.snoop_origin or []), "snoop_origin includes dhcp")


def test_handle_packet_dhcp_rejected_not_in_subnet() -> None:
    """_handle_packet does not add entry when DHCP IP not in bridge subnets."""
    if Ether is None or UDP is None or BOOTP is None:
        raise AssertionError("scapy required")
    entries = IPEntryStore()
    netlink_mock = MagicMock()
    netlink_mock.ip_in_bridge_subnets.return_value = False
    netlink_mock.get_bridge_names_with_ips.return_value = set()
    log = logging.getLogger("test")
    instances = InstanceStore()
    cfg = Config(bridges=["vmbr0"], snoop_bridge=True)
    ovs_mock = MagicMock()
    of_mock = MagicMock()
    with patch("src.packet_monitor.NetlinkInfo", MagicMock(return_value=netlink_mock)):
        mon = PacketMonitor(instances, entries, log, ovs_mock, of_mock, cfg, node_id=NodeID("n1"))
    br = BridgeName("vmbr0")
    pkt = (
        Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff")
        / UDP(sport=67, dport=68)
        / BOOTP(yiaddr="10.99.99.1", ciaddr="0.0.0.0")
    )
    mon._handle_packet(pkt, br)
    entry = entries.get(IPv4Address("10.99.99.1"), br, None)
    _test_assert(entry is None, "IP not in bridge subnets -> no entry")


def test_handle_packet_exception_logged_when_running() -> None:
    """_handle_packet logs debug on inner failure while running."""
    log = MagicMock(spec=logging.Logger)
    entries = IPEntryStore()
    instances = InstanceStore()
    cfg = Config(bridges=["vmbr0"])
    ovs_mock = MagicMock()
    of_mock = MagicMock()
    netlink_mock = MagicMock()
    netlink_mock.get_bridge_names_with_ips.return_value = set()
    with patch("src.packet_monitor.NetlinkInfo", MagicMock(return_value=netlink_mock)):
        mon = PacketMonitor(instances, entries, log, ovs_mock, of_mock, cfg, node_id=NodeID("n1"))
    mon._handle_packet_impl = MagicMock(side_effect=RuntimeError("boom"))  # type: ignore[method-assign]
    mon._handle_packet(object(), BridgeName("vmbr0"))
    _test_assert(log.debug.called, "debug logged on packet error")


def test_handle_packet_exception_suppressed_when_stopping() -> None:
    """_handle_packet suppresses debug when stop flag is set."""
    log = MagicMock(spec=logging.Logger)
    entries = IPEntryStore()
    instances = InstanceStore()
    cfg = Config(bridges=["vmbr0"])
    ovs_mock = MagicMock()
    of_mock = MagicMock()
    netlink_mock = MagicMock()
    netlink_mock.get_bridge_names_with_ips.return_value = set()
    with patch("src.packet_monitor.NetlinkInfo", MagicMock(return_value=netlink_mock)):
        mon = PacketMonitor(instances, entries, log, ovs_mock, of_mock, cfg, node_id=NodeID("n1"))
    mon._handle_packet_impl = MagicMock(side_effect=RuntimeError("boom"))  # type: ignore[method-assign]
    mon.stop()
    mon._handle_packet(object(), BridgeName("vmbr0"))
    _test_assert(not log.debug.called, "no debug while stopping")


def test_handle_packet_peer_tracker_invalid_pdst_skips_track() -> None:
    """_handle_packet skips peer tracking for invalid ARP pdst."""
    if Ether is None or ARP is None:
        raise AssertionError("scapy required")
    entries = IPEntryStore()
    instances = InstanceStore()
    peer_tracker = MagicMock()
    log = logging.getLogger("test")
    cfg = Config(bridges=["vmbr0"], arp_refresh=True)
    ovs_mock = MagicMock()
    of_mock = MagicMock()
    netlink_mock = MagicMock()
    netlink_mock.get_bridge_names_with_ips.return_value = set()
    netlink_mock.ip_in_bridge_subnets.return_value = True
    netlink_mock.is_tap_mac.return_value = False
    netlink_mock.is_bridge_mac.return_value = False
    netlink_mock.bridge_mac_for_ip.return_value = None
    netlink_mock.is_host_local.return_value = False
    with patch("src.packet_monitor.NetlinkInfo", MagicMock(return_value=netlink_mock)):
        mon = PacketMonitor(
            instances,
            entries,
            log,
            ovs_mock,
            of_mock,
            cfg,
            node_id=NodeID("n1"),
            peer_tracker=peer_tracker,
        )
    br = BridgeName("vmbr0")
    pkt = Ether(src="aa:bb:cc:dd:ee:01", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, hwsrc="aa:bb:cc:dd:ee:01", psrc="192.168.1.10", pdst="bad-ip"
    )
    mon._handle_packet(pkt, br)
    peer_tracker.track.assert_not_called()
    _test_assert(entries.get(IPv4Address("192.168.1.10"), br, None) is not None, "entry still updated")


def _make_snoop_monitor(
    entries: IPEntryStore,
    instances: Optional[InstanceStore] = None,
    bridge: str = "vmbr0",
    exclude_subnets: Optional[list[str]] = None,
    snoop_bridge: bool = True,
    snoop_host_local: bool = False,
    ip_in_bridge_subnets: bool = True,
    is_tap_mac: bool = False,
    is_bridge_mac: bool = False,
    bridge_mac_for_ip: Optional[str] = None,
    is_host_local: bool = False,
) -> PacketMonitor:
    """Monitor with netlink mocked for snooping tests; default = allow snoop."""
    log = logging.getLogger("test")
    inst = instances or InstanceStore()
    cfg = Config(
        bridges=[bridge],
        snoop_bridge=snoop_bridge,
        snoop_host_local=snoop_host_local,
        exclude_subnets=exclude_subnets or [],
    )
    ovs_mock = MagicMock()
    ovs_mock.get_bridge_vlan_to_local_port.return_value = {}
    of_mock = MagicMock()
    netlink_mock = MagicMock()
    netlink_mock.get_bridge_names_with_ips.return_value = set()
    netlink_mock.ip_in_bridge_subnets.return_value = ip_in_bridge_subnets
    netlink_mock.is_tap_mac.return_value = is_tap_mac
    netlink_mock.is_bridge_mac.return_value = is_bridge_mac
    netlink_mock.bridge_mac_for_ip.return_value = bridge_mac_for_ip
    netlink_mock.is_host_local.return_value = is_host_local
    with patch("src.packet_monitor.NetlinkInfo", MagicMock(return_value=netlink_mock)):
        return PacketMonitor(
            inst, entries, log, ovs_mock, of_mock, cfg, node_id=NodeID("n1")
        )


def test_snoop_new_entry_without_vlan() -> None:
    """Snooping adds new entry for untagged ARP (no VLAN)."""
    if Ether is None or ARP is None:
        raise AssertionError("scapy required")
    entries = IPEntryStore()
    mon = _make_snoop_monitor(entries)
    br = BridgeName("vmbr0")
    pkt = Ether(src="aa:bb:cc:dd:ee:01", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, hwsrc="aa:bb:cc:dd:ee:01", psrc="192.168.1.10", pdst="192.168.1.1"
    )
    mon._handle_packet(pkt, br)
    entry = entries.get(IPv4Address("192.168.1.10"), br, None)
    _test_assert(entry is not None, "new entry created")
    _test_assert(entry.mac == MACAddress("aa:bb:cc:dd:ee:01"), "mac from packet")
    _test_assert(entry.vlan is None, "no vlan")
    _test_assert(entry.type == "bridge", "type bridge when no instance")
    _test_assert("arp" in (entry.snoop_origin or []), "origin arp")


def test_snoop_new_entry_with_vlan() -> None:
    """Snooping adds new entry with VLAN from Dot1Q."""
    if Ether is None or ARP is None or Dot1Q is None:
        raise AssertionError("scapy required")
    entries = IPEntryStore()
    mon = _make_snoop_monitor(entries)
    br = BridgeName("vmbr0")
    pkt = (
        Ether(src="aa:bb:cc:dd:ee:02", dst="ff:ff:ff:ff:ff:ff")
        / Dot1Q(vlan=42)
        / ARP(op=1, hwsrc="aa:bb:cc:dd:ee:02", psrc="192.168.2.20", pdst="192.168.2.1")
    )
    mon._handle_packet(pkt, br)
    entry = entries.get(IPv4Address("192.168.2.20"), br, 42)
    _test_assert(entry is not None, "new entry with vlan created")
    _test_assert(entry.vlan == 42, "vlan from Dot1Q")
    _test_assert(entry.mac == MACAddress("aa:bb:cc:dd:ee:02"), "mac from packet")


def test_snoop_bridge_mac_for_bridge_ip() -> None:
    """Bridge MAC with its bridge IP is accepted as type bridge."""
    if Ether is None or ARP is None:
        raise AssertionError("scapy required")
    entries = IPEntryStore()
    bridge_mac = "aa:00:00:00:00:01"
    mon = _make_snoop_monitor(
        entries,
        is_bridge_mac=True,
        bridge_mac_for_ip=bridge_mac,
    )
    br = BridgeName("vmbr0")
    pkt = Ether(src=bridge_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, hwsrc=bridge_mac, psrc="192.168.1.1", pdst="192.168.1.2"
    )
    mon._handle_packet(pkt, br)
    entry = entries.get(IPv4Address("192.168.1.1"), br, None)
    _test_assert(entry is not None, "bridge MAC for bridge IP -> entry")
    _test_assert(entry.type == "bridge", "type bridge")
    _test_assert(entry.mac == MACAddress(bridge_mac), "mac preserved")


def test_snoop_bridge_mac_for_non_bridge_ip_skipped() -> None:
    """Bridge MAC claiming non-bridge IP is skipped (no entry)."""
    if Ether is None or ARP is None:
        raise AssertionError("scapy required")
    entries = IPEntryStore()
    # Packet from bridge MAC aa:..; 192.168.1.99 is not that bridge's IP so bridge_mac_for_ip returns other MAC
    mon = _make_snoop_monitor(
        entries,
        is_bridge_mac=True,
        bridge_mac_for_ip="bb:00:00:00:00:01",  # IP belongs to different bridge MAC -> skip
    )
    br = BridgeName("vmbr0")
    pkt = Ether(src="aa:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, psrc="192.168.1.99", pdst="192.168.1.1"
    )
    mon._handle_packet(pkt, br)
    entry = entries.get(IPv4Address("192.168.1.99"), br, None)
    _test_assert(entry is None, "bridge MAC for non-bridge IP -> no entry")


def test_snoop_non_bridge_mac_for_bridge_ip_skipped() -> None:
    """Non-bridge MAC claiming bridge IP is skipped (expected_mac set)."""
    if Ether is None or ARP is None:
        raise AssertionError("scapy required")
    entries = IPEntryStore()
    mon = _make_snoop_monitor(
        entries,
        is_bridge_mac=False,
        bridge_mac_for_ip="aa:00:00:00:00:01",  # bridge owns this IP
    )
    br = BridgeName("vmbr0")
    pkt = Ether(src="bb:bb:bb:bb:bb:bb", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, psrc="192.168.1.1", pdst="192.168.1.2"
    )
    mon._handle_packet(pkt, br)
    entry = entries.get(IPv4Address("192.168.1.1"), br, None)
    _test_assert(entry is None, "non-bridge MAC for bridge IP -> no entry")


def test_snoop_tap_mac_skipped() -> None:
    """Tap/veth interface MAC is skipped (no entry)."""
    if Ether is None or ARP is None:
        raise AssertionError("scapy required")
    entries = IPEntryStore()
    mon = _make_snoop_monitor(entries, is_tap_mac=True)
    br = BridgeName("vmbr0")
    pkt = Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, psrc="192.168.1.50", pdst="192.168.1.1"
    )
    mon._handle_packet(pkt, br)
    entry = entries.get(IPv4Address("192.168.1.50"), br, None)
    _test_assert(entry is None, "tap MAC -> no entry")


def test_snoop_excluded_subnet_skipped() -> None:
    """IP in exclude_subnets is not snooped."""
    if Ether is None or ARP is None:
        raise AssertionError("scapy required")
    entries = IPEntryStore()
    mon = _make_snoop_monitor(entries, exclude_subnets=["192.168.100.0/24"])
    br = BridgeName("vmbr0")
    pkt = Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, psrc="192.168.100.10", pdst="192.168.100.1"
    )
    mon._handle_packet(pkt, br)
    entry = entries.get(IPv4Address("192.168.100.10"), br, None)
    _test_assert(entry is None, "excluded subnet -> no entry")


def test_snoop_host_local_skipped() -> None:
    """Host-local IP is skipped when snoop_host_local False."""
    if Ether is None or ARP is None:
        raise AssertionError("scapy required")
    entries = IPEntryStore()
    mon = _make_snoop_monitor(entries, is_host_local=True, snoop_host_local=False)
    br = BridgeName("vmbr0")
    pkt = Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, psrc="127.0.0.1", pdst="192.168.1.1"
    )
    mon._handle_packet(pkt, br)
    entry = entries.get(IPv4Address("127.0.0.1"), br, None)
    _test_assert(entry is None, "host-local without snoop_host_local -> no entry")


def test_snoop_host_local_allowed() -> None:
    """Host-local IP is snooped when snoop_host_local True."""
    if Ether is None or ARP is None:
        raise AssertionError("scapy required")
    entries = IPEntryStore()
    mon = _make_snoop_monitor(entries, is_host_local=True, snoop_host_local=True)
    br = BridgeName("vmbr0")
    pkt = Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, hwsrc="aa:bb:cc:dd:ee:ff", psrc="192.168.1.200", pdst="192.168.1.1"
    )
    mon._handle_packet(pkt, br)
    entry = entries.get(IPv4Address("192.168.1.200"), br, None)
    _test_assert(entry is not None, "host-local with snoop_host_local -> entry")
    _test_assert("arp" in (entry.snoop_origin or []), "origin arp")


def test_snoop_same_ip_different_mac_overwrites() -> None:
    """Same IP with different MAC overwrites entry (warning logged)."""
    if Ether is None or ARP is None:
        raise AssertionError("scapy required")
    entries = IPEntryStore()
    mon = _make_snoop_monitor(entries)
    br = BridgeName("vmbr0")
    ip = IPv4Address("192.168.1.30")
    pkt1 = Ether(src="aa:bb:cc:dd:ee:01", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, hwsrc="aa:bb:cc:dd:ee:01", psrc="192.168.1.30", pdst="192.168.1.1"
    )
    mon._handle_packet(pkt1, br)
    entry1 = entries.get(ip, br, None)
    _test_assert(entry1 is not None and entry1.mac == MACAddress("aa:bb:cc:dd:ee:01"), "first mac")
    pkt2 = Ether(src="aa:bb:cc:dd:ee:02", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, hwsrc="aa:bb:cc:dd:ee:02", psrc="192.168.1.30", pdst="192.168.1.1"
    )
    mon._handle_packet(pkt2, br)
    entry2 = entries.get(ip, br, None)
    _test_assert(entry2 is not None and entry2.mac == MACAddress("aa:bb:cc:dd:ee:02"), "overwrite with new mac")


def test_snoop_snoop_bridge_false_no_entry() -> None:
    """When snoop_bridge False, non-instance traffic is not snooped."""
    if Ether is None or ARP is None:
        raise AssertionError("scapy required")
    entries = IPEntryStore()
    mon = _make_snoop_monitor(entries, snoop_bridge=False)
    br = BridgeName("vmbr0")
    pkt = Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, psrc="192.168.1.40", pdst="192.168.1.1"
    )
    mon._handle_packet(pkt, br)
    entry = entries.get(IPv4Address("192.168.1.40"), br, None)
    _test_assert(entry is None, "snoop_bridge False -> no entry for unknown MAC")


def test_snoop_instance_mac_type_vm() -> None:
    """MAC in instance store gets entry type from instance (vm/lxc)."""
    if Ether is None or ARP is None:
        raise AssertionError("scapy required")
    entries = IPEntryStore()
    instances = InstanceStore()
    vm_mac = MACAddress("aa:bb:cc:dd:ee:99")
    instances.set(
        vm_mac,
        InstanceInfo(
            vmid=VMID("101"),
            type="qemu",
            bridge=BridgeName("vmbr0"),
            mac=vm_mac,
            ip=None,
        ),
    )
    mon = _make_snoop_monitor(entries, instances=instances)
    br = BridgeName("vmbr0")
    pkt = Ether(src="aa:bb:cc:dd:ee:99", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, hwsrc="aa:bb:cc:dd:ee:99", psrc="192.168.1.99", pdst="192.168.1.1"
    )
    mon._handle_packet(pkt, br)
    entry = entries.get(IPv4Address("192.168.1.99"), br, None)
    _test_assert(entry is not None, "instance MAC -> entry")
    _test_assert(entry.type == "qemu", "type from instance (vm)")
    _test_assert(entry.vmid == VMID("101"), "vmid from instance")


def _make_snoop_monitor_with_node(
    entries: IPEntryStore,
    node_id: str = "n1",
    instances: Optional[InstanceStore] = None,
    snoop_takeover_sec: Optional[float] = None,
    verify_local_migration: bool = True,
    is_local_migration_confirmed: Optional[Callable[[MACAddress], bool]] = None,
    on_owner_change: Optional[
        Callable[[IPv4Address, BridgeName, Optional[int], Optional[NodeID], Optional[NodeID]], None]
    ] = None,
) -> PacketMonitor:
    """Monitor with netlink mocked; node_id set for _update_snoop_entry node tests."""
    log = logging.getLogger("test")
    inst = instances or InstanceStore()
    cfg = Config(
        bridges=["vmbr0"],
        mesh_ttl=990.0,
        flood_min_interval=5.0,
        snoop_takeover_sec=snoop_takeover_sec if snoop_takeover_sec is not None else 99.0,
        verify_local_migration=verify_local_migration,
    )
    ovs_mock = MagicMock()
    ovs_mock.get_bridge_vlan_to_local_port.return_value = {}
    of_mock = MagicMock()
    netlink_mock = MagicMock()
    netlink_mock.get_bridge_names_with_ips.return_value = set()
    netlink_mock.ip_in_bridge_subnets.return_value = True
    netlink_mock.is_tap_mac.return_value = False
    netlink_mock.is_bridge_mac.return_value = False
    netlink_mock.bridge_mac_for_ip.return_value = None
    netlink_mock.is_host_local.return_value = False
    with patch("src.packet_monitor.NetlinkInfo", MagicMock(return_value=netlink_mock)):
        return PacketMonitor(
            inst,
            entries,
            log,
            ovs_mock,
            of_mock,
            cfg,
            node_id=NodeID(node_id),
            is_local_migration_confirmed=is_local_migration_confirmed,
            on_owner_change=on_owner_change,
        )


def test_snoop_refresh_keeps_remote_node() -> None:
    """Refresh (same mac) keeps remote node and does not refresh timestamps."""
    entries = IPEntryStore()
    mon = _make_snoop_monitor_with_node(entries, node_id="172.16.12.10")
    br = BridgeName("vmbr0")
    ip = IPv4Address("192.168.13.177")
    mac = MACAddress("bc:24:11:90:b6:f3")
    remote = NodeID("172.16.12.13")
    now = 1000.0
    entries.set(
        IPEntry(
            ipv4=ip,
            mac=mac,
            bridge=br,
            vlan=99,
            node=remote,
            last_seen=now - 10,
            snoop_origin=["arp"],
        )
    )
    with patch("src.packet_monitor.time") as m_time:
        m_time.time.return_value = now
        mon._update_snoop_entry(mac, ip, br, "bridge", "arp", 99, None)
    entry = entries.get(ip, br, 99)
    _test_assert(entry is not None, "entry still present")
    _test_assert(entry.node == remote, "node unchanged (remote)")
    _test_assert(entry.last_seen == now - 10, "last_seen unchanged for remote owner")
    _test_assert(entry.mac == mac, "mac unchanged")


def test_snoop_refresh_keeps_local_node() -> None:
    """Refresh (same mac) keeps node=self when entry is local."""
    entries = IPEntryStore()
    self_node = "172.16.12.10"
    mon = _make_snoop_monitor_with_node(entries, node_id=self_node)
    br = BridgeName("vmbr0")
    ip = IPv4Address("192.168.12.2")
    mac = MACAddress("82:51:f3:21:c9:47")
    now = 1000.0
    entries.set(
        IPEntry(
            ipv4=ip,
            mac=mac,
            bridge=br,
            vlan=None,
            node=NodeID(self_node),
            last_seen=now - 10,
            snoop_origin=["arp"],
        )
    )
    with patch("src.packet_monitor.time") as m_time:
        m_time.time.return_value = now
        mon._update_snoop_entry(mac, ip, br, "bridge", "arp", None, None)
    entry = entries.get(ip, br, None)
    _test_assert(entry is not None and entry.node == NodeID(self_node), "node stays self")
    _test_assert(entry.last_seen == now, "last_seen updated")


def test_snoop_refresh_sets_node_when_none() -> None:
    """Refresh when entry has node=None sets node=self (claim)."""
    entries = IPEntryStore()
    mon = _make_snoop_monitor_with_node(entries, node_id="n1")
    br = BridgeName("vmbr0")
    ip = IPv4Address("192.168.1.1")
    mac = MACAddress("aa:bb:cc:dd:ee:01")
    now = 1000.0
    entries.set(
        IPEntry(
            ipv4=ip,
            mac=mac,
            bridge=br,
            last_seen=now - 10,
            snoop_origin=["arp"],
            node=None,
        )
    )
    with patch("src.packet_monitor.time") as m_time:
        m_time.time.return_value = now
        mon._update_snoop_entry(mac, ip, br, "bridge", "arp", None, None)
    entry = entries.get(ip, br, None)
    _test_assert(entry is not None and entry.node == NodeID("n1"), "node set to self")
    _test_assert(entry.last_seen == now, "last_seen updated")


def test_snoop_refresh_claims_stale_remote_owner() -> None:
    """Same MAC can be claimed when remote owner entry is expired/stale."""
    entries = IPEntryStore()
    mon = _make_snoop_monitor_with_node(entries, node_id="n1")
    br = BridgeName("vmbr0")
    ip = IPv4Address("192.168.13.105")
    mac = MACAddress("fa:9b:c9:91:4d:47")
    now = 1000.0
    entries.set(
        IPEntry(
            ipv4=ip,
            mac=mac,
            bridge=br,
            vlan=100,
            node=NodeID("172.16.12.10"),
            last_seen=100.0,
            expired=200.0,
            snoop_origin=["arp"],
        )
    )
    with patch("src.packet_monitor.time") as m_time:
        m_time.time.return_value = now
        mon._update_snoop_entry(mac, ip, br, "bridge", "arp", 100, None)
    entry = entries.get(ip, br, 100)
    _test_assert(entry is not None, "entry still present")
    _test_assert(entry.node == NodeID("n1"), "stale remote owner can be claimed")
    _test_assert(entry.last_seen == now, "last_seen updated on takeover")
    _test_assert(entry.expired is None, "expired cleared on takeover")


def test_snoop_refresh_remote_logs_debug() -> None:
    """When keeping remote node on refresh, debug log is emitted."""
    entries = IPEntryStore()
    mon = _make_snoop_monitor_with_node(entries, node_id="n1")
    log = MagicMock(spec=logging.Logger)
    mon.log = log
    br = BridgeName("vmbr0")
    ip = IPv4Address("192.168.13.177")
    mac = MACAddress("bc:24:11:90:b6:f3")
    remote = NodeID("172.16.12.13")
    now = 1000.0
    entries.set(
        IPEntry(
            ipv4=ip,
            mac=mac,
            bridge=br,
            vlan=99,
            node=remote,
            last_seen=now - 10,
            snoop_origin=["arp"],
        )
    )
    with patch("src.packet_monitor.time") as m_time:
        m_time.time.return_value = now
        mon._update_snoop_entry(mac, ip, br, "bridge", "arp", 99, None)
    log.debug.assert_any_call("recv ip=%s kept remote node=%s (bridge, no migration)", ip, remote)


def test_snoop_new_entry_gets_self_node() -> None:
    """New entry (no existing) gets node=self."""
    entries = IPEntryStore()
    mon = _make_snoop_monitor_with_node(entries, node_id="n1")
    br = BridgeName("vmbr0")
    ip = IPv4Address("192.168.1.50")
    mac = MACAddress("aa:bb:cc:dd:ee:50")
    now = 1000.0
    with patch("src.packet_monitor.time") as m_time:
        m_time.time.return_value = now
        mon._update_snoop_entry(mac, ip, br, "bridge", "arp", None, None)
    entry = entries.get(ip, br, None)
    _test_assert(entry is not None, "entry created")
    _test_assert(entry.node == NodeID("n1"), "new entry node=self")
    _test_assert(entry.mac == mac and entry.last_seen == now, "mac and last_seen set")


def test_snoop_changed_mac_overwrites_and_claims_node() -> None:
    """Different mac (VM moved) overwrites entry, sets node=self and logs ownership change."""
    entries = IPEntryStore()
    mon = _make_snoop_monitor_with_node(entries, node_id="n1")
    log = MagicMock(spec=logging.Logger)
    mon.log = log
    br = BridgeName("vmbr0")
    ip = IPv4Address("192.168.1.60")
    old_mac = MACAddress("aa:bb:cc:dd:ee:60")
    new_mac = MACAddress("aa:bb:cc:dd:ee:61")
    remote = NodeID("172.16.12.13")
    now = 1000.0
    entries.set(
        IPEntry(
            ipv4=ip,
            mac=old_mac,
            bridge=br,
            vlan=None,
            node=remote,
            last_seen=now - 10,
            snoop_origin=["arp"],
        )
    )
    with patch("src.packet_monitor.time") as m_time:
        m_time.time.return_value = now
        mon._update_snoop_entry(new_mac, ip, br, "bridge", "arp", None, None)
    entry = entries.get(ip, br, None)
    _test_assert(entry is not None, "entry updated")
    _test_assert(entry.mac == new_mac, "mac overwritten")
    _test_assert(entry.node == NodeID("n1"), "node claimed by self (VM moved)")
    _test_assert(log.warning.call_count >= 1, "ownership change emits warning")


def test_snoop_remote_on_other_vlan_early_return_no_overwrite() -> None:
    """Packet with vlan=None; existing remote entry on vlan 99 -> return early, entry unchanged."""
    entries = IPEntryStore()
    mon = _make_snoop_monitor_with_node(entries, node_id="n1")
    br = BridgeName("vmbr0")
    ip = IPv4Address("192.168.13.177")
    mac = MACAddress("bc:24:11:90:b6:f3")
    remote = NodeID("172.16.12.13")
    now = 1000.0
    entries.set(
        IPEntry(
            ipv4=ip,
            mac=mac,
            bridge=br,
            vlan=99,
            node=remote,
            last_seen=now - 10,
            snoop_origin=["arp"],
        )
    )
    with patch("src.packet_monitor.time") as m_time:
        m_time.time.return_value = now
        mon._update_snoop_entry(mac, ip, br, "bridge", "arp", None, None)
    entry = entries.get(ip, br, 99)
    _test_assert(entry is not None, "entry still present")
    _test_assert(entry.node == remote, "remote node untouched (early return)")
    _test_assert(entry.last_seen == now - 10, "last_seen not updated (we returned)")


def test_snoop_remote_on_other_vlan_confirmed_claim_moves_owner() -> None:
    """Confirmed local migration can claim remote entry on other vlan."""
    entries = IPEntryStore()
    instances = InstanceStore()
    mac = MACAddress("bc:24:11:2e:5b:e5")
    instances.set(
        mac,
        InstanceInfo(
            vmid=VMID("901"),
            type="qemu",
            bridge=BridgeName("vmbr0"),
            mac=mac,
            vlan=99,
        ),
    )
    confirm = MagicMock(return_value=True)
    mon = _make_snoop_monitor_with_node(
        entries,
        node_id="172.16.12.11",
        instances=instances,
        verify_local_migration=True,
        is_local_migration_confirmed=confirm,
    )
    br = BridgeName("vmbr0")
    ip = IPv4Address("192.168.13.183")
    remote = NodeID("172.16.12.10")
    now = 1000.0
    entries.set(
        IPEntry(
            ipv4=ip,
            mac=mac,
            bridge=br,
            vlan=None,
            node=remote,
            last_seen=995.0,
            snoop_origin=["arp"],
        )
    )
    inst = instances.get(mac)
    _test_assert(inst is not None, "instance exists")
    with patch("src.packet_monitor.time") as m_time:
        m_time.time.return_value = now
        mon._update_snoop_entry(mac, ip, br, "qemu", "arp", 99, inst)
    claimed = entries.get(ip, br, 99)
    old = entries.get(ip, br, None)
    _test_assert(confirm.call_count == 1, "confirm called once")
    _test_assert(claimed is not None and claimed.node == NodeID("172.16.12.11"), "claimed on local vlan")
    _test_assert(old is not None and old.expired == now, "old remote entry expired")


def test_snoop_remote_on_other_vlan_confirm_fail_keeps_remote() -> None:
    """Denied local migration keeps remote owner on other vlan."""
    entries = IPEntryStore()
    instances = InstanceStore()
    mac = MACAddress("bc:24:11:2e:5b:e5")
    instances.set(
        mac,
        InstanceInfo(
            vmid=VMID("901"),
            type="qemu",
            bridge=BridgeName("vmbr0"),
            mac=mac,
            vlan=99,
        ),
    )
    confirm = MagicMock(return_value=False)
    mon = _make_snoop_monitor_with_node(
        entries,
        node_id="172.16.12.11",
        instances=instances,
        verify_local_migration=True,
        is_local_migration_confirmed=confirm,
    )
    mon.log = MagicMock(spec=logging.Logger)
    br = BridgeName("vmbr0")
    ip = IPv4Address("192.168.13.183")
    remote = NodeID("172.16.12.10")
    now = 1000.0
    entries.set(
        IPEntry(
            ipv4=ip,
            mac=mac,
            bridge=br,
            vlan=None,
            node=remote,
            last_seen=995.0,
            snoop_origin=["arp"],
        )
    )
    inst = instances.get(mac)
    _test_assert(inst is not None, "instance exists")
    with patch("src.packet_monitor.time") as m_time:
        m_time.time.return_value = now
        mon._update_snoop_entry(mac, ip, br, "qemu", "arp", 99, inst)
    kept = entries.get(ip, br, None)
    claimed = entries.get(ip, br, 99)
    _test_assert(confirm.call_count == 1, "confirm called once")
    _test_assert(kept is not None and kept.node == remote, "remote kept")
    _test_assert(claimed is None, "no local claimed entry")
    _test_assert(mon.log.error.call_count >= 1, "alert logged")


def test_snoop_refresh_remote_multiple_calls_still_remote() -> None:
    """Multiple refresh calls for same remote entry keep node/last_seen unchanged."""
    entries = IPEntryStore()
    mon = _make_snoop_monitor_with_node(entries, node_id="172.16.12.10")
    br = BridgeName("vmbr0")
    ip = IPv4Address("192.168.13.177")
    mac = MACAddress("bc:24:11:90:b6:f3")
    remote = NodeID("172.16.12.13")
    base = 1000.0
    entries.set(
        IPEntry(
            ipv4=ip,
            mac=mac,
            bridge=br,
            vlan=99,
            node=remote,
            last_seen=base - 10,
            snoop_origin=["arp"],
        )
    )
    for i in range(3):
        t = base + i * 10.0
        with patch("src.packet_monitor.time") as m_time:
            m_time.time.return_value = t
            mon._update_snoop_entry(mac, ip, br, "bridge", "arp", 99, None)
        entry = entries.get(ip, br, 99)
        _test_assert(entry is not None and entry.node == remote, f"after call {i+1} node still remote")
    _test_assert(entries.get(ip, br, 99).last_seen == base - 10, "last_seen unchanged for remote owner")


def test_snoop_refresh_flood_interval_skips_update() -> None:
    """Remote-owned entry refresh does not update even outside flood interval."""
    entries = IPEntryStore()
    mon = _make_snoop_monitor_with_node(entries, node_id="n1")
    br = BridgeName("vmbr0")
    ip = IPv4Address("192.168.1.70")
    mac = MACAddress("aa:bb:cc:dd:ee:70")
    remote = NodeID("172.16.12.13")
    now = 1000.0
    entries.set(
        IPEntry(
            ipv4=ip,
            mac=mac,
            bridge=br,
            vlan=None,
            node=remote,
            last_seen=now - 10,
            snoop_origin=["arp"],
        )
    )
    with patch("src.packet_monitor.time") as m_time:
        m_time.time.return_value = now
        mon._update_snoop_entry(mac, ip, br, "bridge", "arp", None, None)
    entry_after_first = entries.get(ip, br, None)
    _test_assert(entry_after_first is not None and entry_after_first.node == remote, "after first: node remote")
    last_seen_first = entry_after_first.last_seen
    with patch("src.packet_monitor.time") as m_time:
        m_time.time.return_value = now + 1.0
        mon._update_snoop_entry(mac, ip, br, "bridge", "arp", None, None)
    entry_after_second = entries.get(ip, br, None)
    _test_assert(entry_after_second.last_seen == last_seen_first, "within flood interval: last_seen unchanged")
    _test_assert(entry_after_second.node == remote, "node still remote")


def test_snoop_takeover_default_ttl_div_10() -> None:
    """Default takeover window is mesh_ttl/10."""
    entries = IPEntryStore()
    mon = _make_snoop_monitor_with_node(entries, node_id="n1")
    br = BridgeName("vmbr0")
    ip = IPv4Address("192.168.1.71")
    mac = MACAddress("aa:bb:cc:dd:ee:71")
    now = 1000.0
    # last_seen is stale for default takeover window (99s), even if mesh-received is fresh.
    entries.set(
        IPEntry(
            ipv4=ip,
            mac=mac,
            bridge=br,
            node=NodeID("172.16.12.13"),
            last_seen=800.0,
            last_received=995.0,
            snoop_origin=["arp"],
        )
    )
    with patch("src.packet_monitor.time") as m_time:
        m_time.time.return_value = now
        mon._update_snoop_entry(mac, ip, br, "bridge", "arp", None, None)
    entry = entries.get(ip, br, None)
    _test_assert(entry is not None and entry.node == NodeID("n1"), "default ttl/10 allows takeover")


def test_snoop_takeover_override_keeps_remote() -> None:
    """Configured takeover window can keep remote owner."""
    entries = IPEntryStore()
    mon = _make_snoop_monitor_with_node(entries, node_id="n1", snoop_takeover_sec=300.0)
    br = BridgeName("vmbr0")
    ip = IPv4Address("192.168.1.72")
    mac = MACAddress("aa:bb:cc:dd:ee:72")
    now = 1000.0
    entries.set(
        IPEntry(
            ipv4=ip,
            mac=mac,
            bridge=br,
            node=NodeID("172.16.12.13"),
            last_seen=800.0,
            last_received=995.0,
            snoop_origin=["arp"],
        )
    )
    with patch("src.packet_monitor.time") as m_time:
        m_time.time.return_value = now
        mon._update_snoop_entry(mac, ip, br, "bridge", "arp", None, None)
    entry = entries.get(ip, br, None)
    _test_assert(entry is not None and entry.node == NodeID("172.16.12.13"), "override keeps remote owner")


def test_snoop_takeover_bridge_skips_db_confirm() -> None:
    """Bridge entry_type skips DB migration confirm; keeps remote quietly."""
    entries = IPEntryStore()
    confirm = MagicMock(return_value=False)
    mon = _make_snoop_monitor_with_node(
        entries,
        node_id="n1",
        snoop_takeover_sec=300.0,
        verify_local_migration=True,
        is_local_migration_confirmed=confirm,
    )
    mon.log = MagicMock(spec=logging.Logger)
    br = BridgeName("vmbr0")
    ip = IPv4Address("192.168.1.73")
    mac = MACAddress("aa:bb:cc:dd:ee:73")
    now = 1000.0
    entries.set(
        IPEntry(
            ipv4=ip,
            mac=mac,
            bridge=br,
            node=NodeID("172.16.12.13"),
            last_seen=999.0,
            last_received=995.0,
            snoop_origin=["arp"],
        )
    )
    with patch("src.packet_monitor.time") as m_time:
        m_time.time.return_value = now
        mon._update_snoop_entry(mac, ip, br, "bridge", "arp", None, None)
    entry = entries.get(ip, br, None)
    _test_assert(entry is not None and entry.node == NodeID("172.16.12.13"), "remote owner kept")
    _test_assert(confirm.call_count == 0, "DB confirm never called for bridge")
    _test_assert(mon.log.error.call_count == 0, "no error logged")
    _test_assert(mon.log.warning.call_count == 0, "no warning logged")


def test_snoop_takeover_denied_when_local_confirm_fails_qemu_logs_error() -> None:
    """QEMU migration denial remains an alert/error log."""
    entries = IPEntryStore()
    instances = InstanceStore()
    mac = MACAddress("aa:bb:cc:dd:ee:77")
    instances.set(
        mac,
        InstanceInfo(
            vmid=VMID("777"),
            type="qemu",
            bridge=BridgeName("vmbr0"),
            mac=mac,
            vlan=None,
        ),
    )
    confirm = MagicMock(return_value=False)
    mon = _make_snoop_monitor_with_node(
        entries,
        node_id="n1",
        instances=instances,
        snoop_takeover_sec=300.0,
        verify_local_migration=True,
        is_local_migration_confirmed=confirm,
    )
    mon.log = MagicMock(spec=logging.Logger)
    br = BridgeName("vmbr0")
    ip = IPv4Address("192.168.1.77")
    now = 1000.0
    entries.set(
        IPEntry(
            ipv4=ip,
            mac=mac,
            bridge=br,
            node=NodeID("172.16.12.13"),
            last_seen=999.0,
            snoop_origin=["arp"],
        )
    )
    inst = instances.get(mac)
    _test_assert(inst is not None, "instance exists")
    with patch("src.packet_monitor.time") as m_time:
        m_time.time.return_value = now
        mon._update_snoop_entry(mac, ip, br, "qemu", "arp", None, inst)
    entry = entries.get(ip, br, None)
    _test_assert(entry is not None and entry.node == NodeID("172.16.12.13"), "owner unchanged when not confirmed")
    _test_assert(confirm.call_count == 1, "confirm callback called")
    _test_assert(mon.log.error.call_count >= 1, "qemu denied migration logs error")


def test_snoop_takeover_allowed_when_local_confirm_passes() -> None:
    """Takeover is allowed when verify_local_migration confirm passes."""
    entries = IPEntryStore()
    confirm = MagicMock(return_value=True)
    mon = _make_snoop_monitor_with_node(
        entries,
        node_id="n1",
        snoop_takeover_sec=10.0,
        verify_local_migration=True,
        is_local_migration_confirmed=confirm,
    )
    br = BridgeName("vmbr0")
    ip = IPv4Address("192.168.1.74")
    mac = MACAddress("aa:bb:cc:dd:ee:74")
    now = 1000.0
    entries.set(
        IPEntry(
            ipv4=ip,
            mac=mac,
            bridge=br,
            node=NodeID("172.16.12.13"),
            last_seen=800.0,
            snoop_origin=["arp"],
        )
    )
    with patch("src.packet_monitor.time") as m_time:
        m_time.time.return_value = now
        mon._update_snoop_entry(mac, ip, br, "bridge", "arp", None, None)
    entry = entries.get(ip, br, None)
    _test_assert(entry is not None and entry.node == NodeID("n1"), "owner switches after confirmation")


def test_snoop_takeover_calls_owner_change_hook() -> None:
    """Owner change on takeover calls hook."""
    entries = IPEntryStore()
    owner_change = MagicMock()
    mon = _make_snoop_monitor_with_node(
        entries,
        node_id="n1",
        snoop_takeover_sec=10.0,
        on_owner_change=owner_change,
    )
    br = BridgeName("vmbr0")
    ip = IPv4Address("192.168.1.76")
    mac = MACAddress("aa:bb:cc:dd:ee:76")
    old_owner = NodeID("172.16.12.13")
    now = 1000.0
    entries.set(
        IPEntry(
            ipv4=ip,
            mac=mac,
            bridge=br,
            node=old_owner,
            last_seen=800.0,
            snoop_origin=["arp"],
        )
    )
    with patch("src.packet_monitor.time") as m_time:
        m_time.time.return_value = now
        mon._update_snoop_entry(mac, ip, br, "bridge", "arp", None, None)
    owner_change.assert_called_once_with(ip, br, None, old_owner, NodeID("n1"))


def test_snoop_takeover_immediate_when_confirmed_even_if_fresh_remote() -> None:
    """Migration verification can bypass takeover_sec and move owner immediately (VM)."""
    entries = IPEntryStore()
    instances = InstanceStore()
    mac = MACAddress("aa:bb:cc:dd:ee:75")
    instances.set(
        mac,
        InstanceInfo(
            vmid=VMID("975"),
            type="qemu",
            bridge=BridgeName("vmbr0"),
            mac=mac,
            vlan=None,
        ),
    )
    confirm = MagicMock(return_value=True)
    mon = _make_snoop_monitor_with_node(
        entries,
        node_id="n1",
        instances=instances,
        snoop_takeover_sec=300.0,
        verify_local_migration=True,
        is_local_migration_confirmed=confirm,
    )
    br = BridgeName("vmbr0")
    ip = IPv4Address("192.168.1.75")
    now = 1000.0
    entries.set(
        IPEntry(
            ipv4=ip,
            mac=mac,
            bridge=br,
            node=NodeID("172.16.12.13"),
            last_seen=999.0,  # fresh remote owner, normally blocked by takeover_sec
            snoop_origin=["arp"],
        )
    )
    inst = instances.get(mac)
    with patch("src.packet_monitor.time") as m_time:
        m_time.time.return_value = now
        mon._update_snoop_entry(mac, ip, br, "qemu", "arp", None, inst)
    entry = entries.get(ip, br, None)
    _test_assert(confirm.call_count == 1, "confirm callback called for override")
    _test_assert(entry is not None and entry.node == NodeID("n1"), "confirmed migration overrides takeover window")


def test_arp_refresher_iter_active_peer_entries_basic() -> None:
    """ArpRefresher.iter_active_peer_entries resolves peers to entry pairs."""
    entries = IPEntryStore()
    local_mac = MACAddress("aa:bb:cc:dd:ee:01")
    remote_ip = "192.0.2.10"
    bridge = BridgeName("vmbr0")
    vlan_id = 10
    local_entry = IPEntry(
        ipv4=IPv4Address("10.0.0.1"),
        mac=local_mac,
        bridge=bridge,
        vlan=vlan_id,
    )
    remote_entry = IPEntry(
        ipv4=IPv4Address(remote_ip),
        mac=MACAddress("aa:bb:cc:dd:ee:02"),
        bridge=bridge,
        vlan=vlan_id,
    )
    entries.set(local_entry)
    entries.set(remote_entry)

    class DummyTracker:
        def get_active_peers_with_ttl(self) -> list[tuple[MACAddress, str, float]]:
            return [(local_mac, remote_ip, 123.0)]

    tracker = DummyTracker()
    pairs = ArpRefresher.iter_active_peer_entries(tracker, entries)
    _test_assert(len(pairs) == 1, "one resolved peer")
    lm, rip, last_seen, le, re = pairs[0]
    _test_assert(lm == local_mac, "local mac matches")
    _test_assert(rip == remote_ip, "remote ip matches")
    _test_assert(last_seen == 123.0, "last_seen propagated")
    _test_assert(le.ipv4 == local_entry.ipv4 and le.bridge == local_entry.bridge, "local entry matches")
    _test_assert(re.ipv4 == remote_entry.ipv4 and re.bridge == remote_entry.bridge, "remote entry matches")


def test_arp_reply_counters_sent_and_skipped() -> None:
    """ARP reply counters increment for sent and skipped paths."""
    if Ether is None or ARP is None:
        raise AssertionError("scapy required")
    entries = IPEntryStore()
    br = BridgeName("vmbr0")
    ip = IPv4Address("10.10.10.1")
    entries.set(
        IPEntry(
            ipv4=ip,
            mac=MACAddress("aa:bb:cc:dd:ee:01"),
            bridge=br,
            last_seen=time.time(),
        )
    )
    mon = _make_monitor(entries, resolve_port="5")
    pkt_ok = Ether(src="00:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, psrc="10.10.10.2", pdst="10.10.10.1"
    )
    _test_assert(mon._do_arp_reply(pkt_ok, br, "test") is True, "reply sent")
    pkt_skip = Ether(src="00:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, psrc="10.10.10.2", pdst="10.10.10.99"
    )
    _test_assert(mon._do_arp_reply(pkt_skip, br, "test") is False, "reply skipped")
    c = mon.arp_counters()
    _test_assert(c.get("reply_attempt", 0) == 1, "one reply attempt")
    _test_assert(c.get("reply_sent", 0) == 1, "one reply sent")
    _test_assert(c.get("reply_skipped", 0) >= 1, "skipped incremented")


def test_arp_reinject_counters() -> None:
    """ARP reinject counters increment on success and failure."""
    if Ether is None or ARP is None:
        raise AssertionError("scapy required")
    entries = IPEntryStore()
    br = BridgeName("vmbr0")
    mon = _make_monitor(entries, arp_reply=False)
    mon.config.arp_reinject = True
    pkt = Ether(src="00:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, psrc="10.10.10.2", pdst="10.10.10.99"
    )
    mon._send_arp_reply(pkt, br, already_sent=False)
    c1 = mon.arp_counters()
    _test_assert(c1.get("reinject_sent", 0) == 1, "reinject sent increments")
    mon.of_manager.send_packet_out_async.side_effect = RuntimeError("x")
    mon._send_arp_reply(pkt, br, already_sent=False)
    c2 = mon.arp_counters()
    _test_assert(c2.get("reinject_failed", 0) == 1, "reinject failed increments")
