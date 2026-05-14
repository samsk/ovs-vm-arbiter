"""Tests for src.of_manager."""
import logging
import time
from typing import Optional
from unittest.mock import patch
from src.types import MACAddress, IPv4Address, BridgeName, NodeID, OFPort, OVSCookie
from src.ovs_cmd import OVSCommand
from src.of_manager import OFManager
from src.models import IPEntry, IPEntryStore
from src.test import _test_assert, _MockFlowRegistry


def test_of_manager_flow_specs() -> None:
    """OFManager: FLOW_SPECS_BASE, _cookie_spec with mock (no ovs-ofctl)."""
    _test_assert(len(OFManager.FLOW_SPECS_BASE) >= 3, "FLOW_SPECS_BASE")
    log = logging.getLogger("test")
    of = OFManager(_MockFlowRegistry(), [BridgeName("vmbr0")], log)
    _test_assert(of._cookie_spec() == OVSCookie("0x10000000"), "_cookie_spec")


def test_of_manager_flow_actions() -> None:
    """OFManager: of_action, of_arp_action, of_dhcp_action set _flow_specs actions correctly."""
    log = logging.getLogger("test")
    bridges = [BridgeName("vmbr0")]
    of = OFManager(_MockFlowRegistry(), bridges, log)
    for _m, actions, _n in of._flow_specs:
        _test_assert(actions == "output:LOCAL,NORMAL", "default NORMAL")
    of_no = OFManager(_MockFlowRegistry(), bridges, log, of_action="no")
    for _m, actions, _n in of_no._flow_specs:
        _test_assert(actions == "output:LOCAL", "action no -> LOCAL only")
    of_arp = OFManager(_MockFlowRegistry(), bridges, log, of_arp_action="no")
    by_name = {n: (m, a) for m, a, n in of_arp._flow_specs}
    _test_assert(by_name["arp"][1] == "output:LOCAL", "arp override no")
    _test_assert(by_name["udp67"][1] == "output:LOCAL,NORMAL", "udp67 keeps NORMAL")
    of_dhcp = OFManager(_MockFlowRegistry(), bridges, log, of_dhcp_action="no")
    by_name2 = {n: (m, a) for m, a, n in of_dhcp._flow_specs}
    _test_assert(by_name2["arp"][1] == "output:LOCAL,NORMAL", "arp keeps NORMAL")
    _test_assert(by_name2["udp67"][1] == "output:LOCAL", "udp67 override no")
    _test_assert(by_name2["udp68"][1] == "output:LOCAL", "udp68 override no")
    of_custom = OFManager(_MockFlowRegistry(), bridges, log, of_arp_action="output:123")
    by_name3 = {n: a for _m, a, n in of_custom._flow_specs}
    _test_assert(by_name3["arp"] == "output:LOCAL,output:123", "arp custom action")
    of_drop = OFManager(_MockFlowRegistry(), bridges, log, of_action="drop")
    for _m, actions, _n in of_drop._flow_specs:
        _test_assert(actions == "output:LOCAL", "action drop -> LOCAL only")


def _reply_actions_endswith_in_port(actions: str) -> bool:
    """True if ARP reply action list ends with IN_PORT (clone body when mirror, else full string)."""
    if "actions=" in actions:
        actions = actions.split("actions=", 1)[1]
    # When mirror: clone(output:LOCAL),clone(reply..IN_PORT); use last clone (reply)
    idx = actions.rindex("clone(") if "clone(" in actions else -1
    if idx >= 0:
        start = idx + 6
        depth = 0
        for i, c in enumerate(actions[start:], start=start):
            if c == "(":
                depth += 1
            elif c == ")":
                if depth == 0:
                    inner = actions[start:i]
                    return inner.endswith("IN_PORT")
                depth -= 1
        return False
    return actions.endswith("IN_PORT")


def test_arp_responder_match_actions() -> None:
    """OFManager: _arp_responder_match and _arp_responder_actions build correct strings."""
    log = logging.getLogger("test")
    of = OFManager(_MockFlowRegistry(), [BridgeName("vmbr0")], log)
    ip = IPv4Address("10.0.0.5")
    mac = MACAddress("aa:bb:cc:dd:ee:ff")
    m1 = of._arp_responder_match(ip)
    _test_assert("arp,arp_op=1,arp_tpa=10.0.0.5" in m1 and "vlan_tci" not in m1, "match without vlan")
    m_vlan = of._arp_responder_match(ip, 99)
    _test_assert("vlan_tci=0x" in m_vlan, "match with vlan uses vlan_tci when register not set")
    of_reg = OFManager(_MockFlowRegistry(), [BridgeName("vmbr0")], log, arp_responder_vlan_register=0)
    m_reg = of_reg._arp_responder_match(ip, 10)
    _test_assert("NXM_NX_REG0[]=0xa" in m_reg and "vlan_tci" not in m_reg, "match with vlan uses REG0 when arp_responder_vlan_register=0")
    a1 = of._arp_responder_actions(mac, ip, mirror_local=True)
    _test_assert(a1.startswith("clone(output:LOCAL),"), "mirror: request to LOCAL first")
    _test_assert("clone(" in a1, "mirror: clone(reply) for IN_PORT")
    _test_assert(_reply_actions_endswith_in_port(a1), "reply action ends with IN_PORT")
    _test_assert("mod_dl_src:aa:bb:cc:dd:ee:ff" in a1, "actions reply mac")
    a2 = of._arp_responder_actions(mac, ip, mirror_local=False)
    _test_assert(_reply_actions_endswith_in_port(a2), "reply action ends with IN_PORT")
    _test_assert("output:LOCAL" not in a2, "no mirror: no LOCAL")


def test_arp_responder_reply_to_in_port() -> None:
    """Reply destination is always IN_PORT, never output:N (so requester gets the reply)."""
    log = logging.getLogger("test")
    of = OFManager(_MockFlowRegistry(), [BridgeName("vmbr0")], log)
    ip = IPv4Address("10.0.0.5")
    mac = MACAddress("aa:bb:cc:dd:ee:ff")
    # No learning: reply must end with IN_PORT
    a = of._arp_responder_actions(mac, ip, mirror_local=False, out_port=None)
    _test_assert(_reply_actions_endswith_in_port(a), "reply ends with IN_PORT when no learning")
    # With learning: reply still ends with IN_PORT; port only inside learn(), not as reply output
    a_learn = of._arp_responder_actions(mac, ip, mirror_local=False, out_port=OFPort("6394"))
    _test_assert(_reply_actions_endswith_in_port(a_learn), "reply ends with IN_PORT when learning enabled")
    _test_assert("output:6394" not in a_learn, "reply not sent to output:6394; only learn() uses port")
    # With mirror: clone body (reply) ends with IN_PORT
    a_mirror = of._arp_responder_actions(mac, ip, mirror_local=True, out_port=None)
    _test_assert(_reply_actions_endswith_in_port(a_mirror), "reply (clone body) ends with IN_PORT when mirror")


def test_arp_responder_actions_learning() -> None:
    """Reply always IN_PORT; out_port set adds learn() for FDB, reply still IN_PORT."""
    log = logging.getLogger("test")
    of = OFManager(_MockFlowRegistry(), [BridgeName("vmbr0")], log)
    ip = IPv4Address("10.0.0.5")
    mac = MACAddress("aa:bb:cc:dd:ee:ff")
    a_none = of._arp_responder_actions(mac, ip, mirror_local=True, out_port=None)
    _test_assert(_reply_actions_endswith_in_port(a_none), "reply ends with IN_PORT")
    _test_assert("learn(" not in a_none, "no learn when out_port None")
    a_port = of._arp_responder_actions(mac, ip, mirror_local=True, out_port=OFPort("5"))
    _test_assert(_reply_actions_endswith_in_port(a_port), "reply ends with IN_PORT when learning")
    _test_assert("learn(" in a_port, "out_port set: has learn()")
    _test_assert("load:0x5->NXM_NX_REG2[]" in a_port, "learn() loads port 5 to REG2")
    _test_assert("output:NXM_NX_REG2[]" in a_port, "learn() outputs to REG2")


def test_sync_arp_responder_flows_learning() -> None:
    """sync_arp_responder_flows with get_learning_port: add-flow has learn() and IN_PORT."""
    log = logging.getLogger("test")
    br = BridgeName("vmbr0")
    ip = IPv4Address("192.168.2.1")
    mac = MACAddress("aa:bb:cc:dd:ee:04")
    desired = {(br, ip, mac, None)}
    of = OFManager(_MockFlowRegistry(), [br], log)
    learning_port = OFPort("3")

    def get_port(b: BridgeName, i: IPv4Address) -> Optional[OFPort]:
        if b == br and i == ip:
            return learning_port
        return None

    with patch("src.of_manager.OVSCommand.run_ofctl") as m:
        m.return_value = (True, "")
        of.sync_arp_responder_flows(desired=desired, get_learning_port=get_port)
    _test_assert((br, ip, mac, None) in of._arp_responder_installed, "flow installed")
    _test_assert(m.called, "run_ofctl called")
    add_flow_calls = [c for c in m.call_args_list if len(c[0]) >= 2 and c[0][0] == "add-flow"]
    _test_assert(len(add_flow_calls) >= 1, "add-flow was called")
    spec = add_flow_calls[0][0][2]
    _test_assert("learn(" in spec and "load:0x3->NXM_NX_REG2[]" in spec, "learn() for port 3")
    _test_assert(_reply_actions_endswith_in_port(spec), "reply action ends with IN_PORT")


def test_sync_arp_responder_flows_learning_port_change() -> None:
    """When learning port changes, flow is removed and re-added with new output:PORT."""
    log = logging.getLogger("test")
    br = BridgeName("vmbr0")
    ip = IPv4Address("192.168.2.1")
    mac = MACAddress("aa:bb:cc:dd:ee:04")
    desired = {(br, ip, mac, None)}
    of = OFManager(_MockFlowRegistry(), [br], log)
    current_port: Optional[OFPort] = OFPort("3")

    def get_port(b: BridgeName, i: IPv4Address) -> Optional[OFPort]:
        if b == br and i == ip:
            return current_port
        return None

    with patch("src.of_manager.OVSCommand.run_ofctl") as m:
        m.return_value = (True, "")
        of.sync_arp_responder_flows(desired=desired, get_learning_port=get_port)
    _test_assert((br, ip, mac, None) in of._arp_responder_installed, "flow installed")
    _test_assert(of._arp_responder_out_port.get((br, ip, mac, None)) == OFPort("3"), "out_port tracked")
    add_calls_1 = [c for c in m.call_args_list if len(c[0]) >= 2 and c[0][0] == "add-flow"]
    _test_assert(any("load:0x3->NXM_NX_REG2[]" in (c[0][2] if len(c[0]) > 2 else "") for c in add_calls_1), "first add has learn port 3")

    # Change port: next sync should remove (port changed) and re-add with learn() for port 7
    current_port = OFPort("7")
    with patch("src.of_manager.OVSCommand.run_ofctl") as m2:
        m2.return_value = (True, "")
        of.sync_arp_responder_flows(desired=desired, get_learning_port=get_port)
    _test_assert((br, ip, mac, None) in of._arp_responder_installed, "still installed after port change")
    _test_assert(of._arp_responder_out_port.get((br, ip, mac, None)) == OFPort("7"), "out_port updated to 7")
    del_calls = [c for c in m2.call_args_list if len(c[0]) >= 2 and c[0][0] == "del-flows"]
    _test_assert(len(del_calls) >= 1, "del-flows called for port change")
    add_calls_2 = [c for c in m2.call_args_list if len(c[0]) >= 2 and c[0][0] == "add-flow"]
    _test_assert(any("load:0x7->NXM_NX_REG2[]" in (c[0][2] if len(c[0]) > 2 else "") for c in add_calls_2), "re-add has learn port 7")


def test_sync_arp_responder_flows_learning_port_to_none() -> None:
    """When learning port becomes None (e.g. node left), flow re-added with IN_PORT."""
    log = logging.getLogger("test")
    br = BridgeName("vmbr0")
    ip = IPv4Address("192.168.2.2")
    mac = MACAddress("aa:bb:cc:dd:ee:05")
    desired = {(br, ip, mac, None)}
    of = OFManager(_MockFlowRegistry(), [br], log)
    current_port: Optional[OFPort] = OFPort("4")

    def get_port(b: BridgeName, i: IPv4Address) -> Optional[OFPort]:
        return current_port if (b == br and i == ip) else None

    with patch("src.of_manager.OVSCommand.run_ofctl") as m:
        m.return_value = (True, "")
        of.sync_arp_responder_flows(desired=desired, get_learning_port=get_port)
    _test_assert(of._arp_responder_out_port.get((br, ip, mac, None)) == OFPort("4"), "out_port 4 tracked")
    current_port = None
    with patch("src.of_manager.OVSCommand.run_ofctl") as m2:
        m2.return_value = (True, "")
        of.sync_arp_responder_flows(desired=desired, get_learning_port=get_port)
    _test_assert(of._arp_responder_out_port.get((br, ip, mac, None)) is None, "out_port cleared")
    add_calls = [c for c in m2.call_args_list if len(c[0]) >= 2 and c[0][0] == "add-flow"]
    spec_readd = (add_calls[0][0][2] if add_calls and len(add_calls[0][0]) > 2 else "")
    _test_assert(_reply_actions_endswith_in_port(spec_readd), "re-add reply action ends with IN_PORT")


def test_compute_desired_responders_ip_store() -> None:
    """compute_desired_responders from IPEntryStore yields (bridge, ip, mac)."""
    from src.of_manager import compute_desired_responders
    log = logging.getLogger("test")
    entries = IPEntryStore()
    ip = IPv4Address("192.168.2.1")
    mac = MACAddress("aa:bb:cc:dd:ee:04")
    br = BridgeName("vmbr0")
    now = time.time()
    entries.set(IPEntry(ipv4=ip, mac=mac, bridge=br, type="bridge", node=NodeID("n1"), last_seen=now))
    desired = compute_desired_responders(entries, 300.0, [br])
    _test_assert((br, ip, mac, None) in desired, "one IP entry -> one responder key")
    _test_assert(len(desired) == 1, "single entry")


def test_compute_desired_responders_local_reply_flags() -> None:
    """Local entries included only when both arp_reply_local and arp_responder_reply_local True."""
    from src.of_manager import compute_desired_responders
    entries = IPEntryStore()
    br = BridgeName("vmbr0")
    now = time.time()
    ip_local = IPv4Address("192.168.1.10")
    mac_local = MACAddress("aa:bb:cc:dd:ee:01")
    ip_remote = IPv4Address("192.168.1.20")
    mac_remote = MACAddress("aa:bb:cc:dd:ee:02")
    node_self = "this-node"
    node_other = "other-node"
    entries.set(IPEntry(ipv4=ip_local, mac=mac_local, bridge=br, node=NodeID(node_self), last_seen=now))
    entries.set(IPEntry(ipv4=ip_remote, mac=mac_remote, bridge=br, node=NodeID(node_other), last_seen=now))

    # node_id None: both entries included (no local filtering)
    d = compute_desired_responders(entries, 300.0, [br])
    _test_assert(len(d) == 2, "no node_id: both included")
    _test_assert((br, ip_local, mac_local, None) in d, "local in when no node_id")
    _test_assert((br, ip_remote, mac_remote, None) in d, "remote in when no node_id")

    # node_id set, both flags False: local excluded, remote included
    d_ff = compute_desired_responders(
        entries, 300.0, [br], node_id=node_self,
        arp_reply_local=False, arp_responder_reply_local=False,
    )
    _test_assert((br, ip_local, mac_local, None) not in d_ff, "local excluded when both False")
    _test_assert((br, ip_remote, mac_remote, None) in d_ff, "remote still in")

    # one True one False: local still excluded
    d_tf = compute_desired_responders(
        entries, 300.0, [br], node_id=node_self,
        arp_reply_local=True, arp_responder_reply_local=False,
    )
    _test_assert((br, ip_local, mac_local, None) not in d_tf, "local excluded when only arp_reply_local")
    d_ft = compute_desired_responders(
        entries, 300.0, [br], node_id=node_self,
        arp_reply_local=False, arp_responder_reply_local=True,
    )
    _test_assert((br, ip_local, mac_local, None) not in d_ft, "local excluded when only arp_responder_reply_local")

    # both True: local included
    d_tt = compute_desired_responders(
        entries, 300.0, [br], node_id=node_self,
        arp_reply_local=True, arp_responder_reply_local=True,
    )
    _test_assert((br, ip_local, mac_local, None) in d_tt, "local in when both True")
    _test_assert((br, ip_remote, mac_remote, None) in d_tt, "remote in when both True")


def test_compute_desired_responders_strict_no_vlan() -> None:
    """strict=True: tagged entry gets (vlan) and with arp_reply_no_vlan also (None). strict=False: only (None)."""
    from src.of_manager import compute_desired_responders
    entries = IPEntryStore()
    br = BridgeName("vmbr0")
    ip = IPv4Address("192.168.1.5")
    mac = MACAddress("aa:bb:cc:dd:ee:05")
    now = time.time()
    entries.set(IPEntry(ipv4=ip, mac=mac, bridge=br, vlan=99, last_seen=now))
    d_strict_no = compute_desired_responders(
        entries, 300.0, [br], arp_reply_strict_vlan=True, arp_reply_no_vlan=True,
    )
    _test_assert((br, ip, mac, 99) in d_strict_no, "strict+no_vlan: add vlan 99 key")
    _test_assert((br, ip, mac, None) in d_strict_no, "strict+no_vlan: add no-vlan key for untagged requests")
    _test_assert(len(d_strict_no) == 2, "strict+no_vlan: two keys")
    d_strict_only = compute_desired_responders(
        entries, 300.0, [br], arp_reply_strict_vlan=True, arp_reply_no_vlan=False,
    )
    _test_assert((br, ip, mac, 99) in d_strict_only, "strict only: add vlan 99 key")
    _test_assert((br, ip, mac, None) not in d_strict_only, "strict only: no untagged key")
    _test_assert(len(d_strict_only) == 1, "strict only: one key")
    d_not_strict = compute_desired_responders(
        entries, 300.0, [br], arp_reply_strict_vlan=False,
    )
    _test_assert((br, ip, mac, None) in d_not_strict, "not strict: one key no vlan")
    _test_assert(len(d_not_strict) == 1, "not strict: single key")


def test_compute_desired_responders_untagged_entry() -> None:
    """Untagged entry (vlan None/0): strict+no_vlan only (None) key; strict+no_vlan off still (None) for reply to untagged."""
    from src.of_manager import compute_desired_responders
    entries = IPEntryStore()
    br = BridgeName("vmbr0")
    ip = IPv4Address("192.168.1.10")
    mac = MACAddress("aa:bb:cc:dd:ee:0a")
    now = time.time()
    entries.set(IPEntry(ipv4=ip, mac=mac, bridge=br, vlan=None, last_seen=now))
    d_strict = compute_desired_responders(
        entries, 300.0, [br], arp_reply_strict_vlan=True, arp_reply_no_vlan=True,
    )
    _test_assert((br, ip, mac, None) in d_strict, "untagged entry strict+no_vlan: one key (None)")
    _test_assert(len(d_strict) == 1, "untagged entry: single key only")
    d_strict_no_off = compute_desired_responders(
        entries, 300.0, [br], arp_reply_strict_vlan=True, arp_reply_no_vlan=False,
    )
    _test_assert((br, ip, mac, None) in d_strict_no_off, "untagged entry strict, no_vlan off: still (None) for untagged requests")
    _test_assert(len(d_strict_no_off) == 1, "untagged entry strict no_vlan off: one key")


def test_compute_desired_responders_negative() -> None:
    """compute_desired_responders: empty store -> empty desired; no (None) for tagged when strict+no_vlan False."""
    from src.of_manager import compute_desired_responders
    entries = IPEntryStore()
    br = BridgeName("vmbr0")
    desired_empty = compute_desired_responders(entries, 300.0, [br])
    _test_assert(len(desired_empty) == 0, "empty store -> empty desired (negative)")
    ip = IPv4Address("192.168.1.7")
    mac = MACAddress("aa:bb:cc:dd:ee:07")
    now = time.time()
    entries.set(IPEntry(ipv4=ip, mac=mac, bridge=br, vlan=10, last_seen=now))
    d = compute_desired_responders(
        entries, 300.0, [br], arp_reply_strict_vlan=True, arp_reply_no_vlan=False,
    )
    _test_assert((br, ip, mac, None) not in d, "strict+no_vlan False: no (None) key for tagged entry (negative)")
    _test_assert((br, ip, mac, 10) in d, "strict+no_vlan False: (vlan 10) key present")


def test_compute_desired_responders_for_responder_ignores_no_vlan() -> None:
    """for_responder=True: no (None) key for tagged entries (arp_reply_no_vlan ignored)."""
    from src.of_manager import compute_desired_responders
    entries = IPEntryStore()
    br = BridgeName("vmbr0")
    ip = IPv4Address("192.168.1.5")
    mac = MACAddress("aa:bb:cc:dd:ee:05")
    now = time.time()
    entries.set(IPEntry(ipv4=ip, mac=mac, bridge=br, vlan=99, last_seen=now))
    d = compute_desired_responders(
        entries, 300.0, [br],
        arp_reply_strict_vlan=True, arp_reply_no_vlan=True, for_responder=True,
    )
    _test_assert((br, ip, mac, 99) in d, "for_responder: add vlan 99 key")
    _test_assert((br, ip, mac, None) not in d, "for_responder: no untagged key")
    _test_assert(len(d) == 1, "for_responder: one key only")


def test_compute_desired_responders_remote_uses_remote_vlan() -> None:
    """Remote entry with arp_reply_remote_vlan: single key with remote_vlan."""
    from src.of_manager import compute_desired_responders
    entries = IPEntryStore()
    br = BridgeName("vmbr0")
    ip = IPv4Address("192.168.1.20")
    mac = MACAddress("aa:bb:cc:dd:ee:02")
    now = time.time()
    entries.set(IPEntry(ipv4=ip, mac=mac, bridge=br, vlan=100, node=NodeID("other-node"), last_seen=now))
    d = compute_desired_responders(
        entries, 300.0, [br], node_id="this-node",
        arp_reply_strict_vlan=True, arp_reply_remote_vlan=10, for_responder=True,
    )
    _test_assert((br, ip, mac, 10) in d, "remote entry + remote_vlan=10: key has vlan 10")
    _test_assert((br, ip, mac, 100) not in d, "remote entry: not entry vlan 100")
    _test_assert((br, ip, mac, None) not in d, "remote entry: no untagged key")
    _test_assert(len(d) == 1, "remote entry + remote_vlan: one key")


def test_compute_desired_responders_remote_no_remote_vlan_uses_entry_vlan() -> None:
    """Remote entry with arp_reply_remote_vlan None: use entry vlan."""
    from src.of_manager import compute_desired_responders
    entries = IPEntryStore()
    br = BridgeName("vmbr0")
    ip = IPv4Address("192.168.1.21")
    mac = MACAddress("aa:bb:cc:dd:ee:03")
    now = time.time()
    entries.set(IPEntry(ipv4=ip, mac=mac, bridge=br, vlan=50, node=NodeID("other-node"), last_seen=now))
    d = compute_desired_responders(
        entries, 300.0, [br], node_id="this-node",
        arp_reply_strict_vlan=True, arp_reply_remote_vlan=None, for_responder=True,
    )
    _test_assert((br, ip, mac, 50) in d, "remote entry, no remote_vlan: use entry vlan 50")
    _test_assert(len(d) == 1, "one key")


def test_compute_desired_responders_remote_no_entry_vlan_only_none_key() -> None:
    """Remote entry with no learned vlan: only (br, ip, mac, None); strict_vlan only for IPs with vlan."""
    from src.of_manager import compute_desired_responders
    entries = IPEntryStore()
    br = BridgeName("vmbr0")
    ip = IPv4Address("192.168.12.2")
    mac = MACAddress("82:51:f3:21:c9:47")
    now = time.time()
    entries.set(IPEntry(ipv4=ip, mac=mac, bridge=br, vlan=None, node=NodeID("other-node"), last_seen=now))
    d = compute_desired_responders(
        entries, 300.0, [br], node_id="this-node",
        arp_reply_strict_vlan=True, arp_reply_remote_vlan=10, for_responder=True,
    )
    _test_assert((br, ip, mac, None) in d, "remote no entry vlan: single key (None) for match-any vlan")
    _test_assert((br, ip, mac, 10) not in d, "remote no entry vlan: no tunnel vlan key")
    _test_assert(len(d) == 1, "one key only")


def test_compute_desired_responders_remote_localize_uses_entry_vlan() -> None:
    """Remote entry with vlan in local_vlans: use entry vlan instead of remote_vlan."""
    from src.of_manager import compute_desired_responders
    entries = IPEntryStore()
    br = BridgeName("vmbr0")
    ip = IPv4Address("192.168.1.30")
    mac = MACAddress("aa:bb:cc:dd:ee:30")
    now = time.time()
    entries.set(IPEntry(ipv4=ip, mac=mac, bridge=br, vlan=100, node=NodeID("other-node"), last_seen=now))
    d = compute_desired_responders(
        entries,
        300.0,
        [br],
        node_id="this-node",
        arp_reply_strict_vlan=True,
        arp_reply_remote_vlan=10,
        for_responder=True,
        local_vlans={100},
        arp_reply_localize_vlan=True,
    )
    _test_assert((br, ip, mac, 100) in d, "remote, localized: key has entry vlan 100")
    _test_assert((br, ip, mac, 10) not in d, "remote, localized: no remote_vlan key")
    _test_assert((br, ip, mac, None) not in d, "remote, localized: no untagged key")
    _test_assert(len(d) == 1, "remote, localized: one key")


def test_compute_desired_responders_passive_bridges() -> None:
    """Entries on passive bridges excluded from desired responder set."""
    from src.of_manager import compute_desired_responders

    entries = IPEntryStore()
    br_active = BridgeName("vmbr0")
    br_passive = BridgeName("vmbr00")
    now = time.time()
    ip_active = IPv4Address("10.0.0.1")
    mac_active = MACAddress("aa:bb:cc:dd:ee:01")
    ip_passive = IPv4Address("10.0.1.1")
    mac_passive = MACAddress("aa:bb:cc:dd:ee:02")
    entries.set(IPEntry(ipv4=ip_active, mac=mac_active, bridge=br_active, last_seen=now))
    entries.set(IPEntry(ipv4=ip_passive, mac=mac_passive, bridge=br_passive, last_seen=now))

    desired = compute_desired_responders(
        entries,
        300.0,
        [br_active, br_passive],
        passive_bridges=frozenset({"vmbr00"}),
    )
    _test_assert((br_active, ip_active, mac_active, None) in desired, "active bridge entry included")
    _test_assert(
        not any(ip == ip_passive for (_, ip, _, _) in desired),
        "passive bridge entry excluded",
    )


def test_sync_arp_responder_flows_strict_no_vlan_installs_both() -> None:
    """sync_arp_responder_flows: desired with both (vlan) and (None) installs two flows."""
    from src.of_manager import compute_desired_responders
    log = logging.getLogger("test")
    entries = IPEntryStore()
    br = BridgeName("vmbr0")
    ip = IPv4Address("192.168.2.10")
    mac = MACAddress("aa:bb:cc:dd:ee:0a")
    now = time.time()
    entries.set(IPEntry(ipv4=ip, mac=mac, bridge=br, vlan=99, last_seen=now))
    desired = compute_desired_responders(
        entries, 300.0, [br], arp_reply_strict_vlan=True, arp_reply_no_vlan=True,
    )
    _test_assert((br, ip, mac, 99) in desired and (br, ip, mac, None) in desired, "desired has both keys")
    of = OFManager(_MockFlowRegistry(), [br], log)
    with patch("src.of_manager.OVSCommand.run_ofctl") as m:
        m.return_value = (True, "")
        of.sync_arp_responder_flows(desired=desired)
    _test_assert((br, ip, mac, 99) in of._arp_responder_installed, "flow for vlan 99 installed")
    _test_assert((br, ip, mac, None) in of._arp_responder_installed, "flow for no vlan installed")
    _test_assert(len(of._arp_responder_installed) == 2, "two flows installed")


def test_responder_includes_host_local() -> None:
    """sync_arp_responder_flows installs flows for entries in IPEntryStore."""
    log = logging.getLogger("test")
    entries = IPEntryStore()
    mac = MACAddress("aa:bb:cc:dd:ee:04")
    br = BridgeName("vmbr0")
    ip = IPv4Address("192.168.2.1")
    now = time.time()
    entries.set(IPEntry(ipv4=ip, mac=mac, bridge=br, type="bridge", node=NodeID("n1"), last_seen=now))
    of = OFManager(_MockFlowRegistry(), [br], log)
    with patch("src.of_manager.OVSCommand.run_ofctl") as m:
        m.return_value = (True, "")
        of.sync_arp_responder_flows(entries, 300.0, None)
    _test_assert((br, ip, mac, None) in of._arp_responder_installed, "entry gets responder flow")


def test_sync_arp_responder_flows_local_reply_flags() -> None:
    """sync_arp_responder_flows: local entry only gets flow when both reply flags True."""
    log = logging.getLogger("test")
    entries = IPEntryStore()
    br = BridgeName("vmbr0")
    ip = IPv4Address("192.168.2.1")
    mac = MACAddress("aa:bb:cc:dd:ee:04")
    now = time.time()
    node_self = "this-node"
    entries.set(IPEntry(ipv4=ip, mac=mac, bridge=br, type="bridge", node=NodeID(node_self), last_seen=now))
    of = OFManager(_MockFlowRegistry(), [br], log)
    with patch("src.of_manager.OVSCommand.run_ofctl") as m:
        m.return_value = (True, "")
        of.sync_arp_responder_flows(
            entries, 300.0, node_self,
            arp_reply_local=False, arp_responder_reply_local=False,
        )
    _test_assert((br, ip, mac, None) not in of._arp_responder_installed, "local excluded when both False")
    with patch("src.of_manager.OVSCommand.run_ofctl") as m:
        m.return_value = (True, "")
        of.sync_arp_responder_flows(
            entries, 300.0, node_self,
            arp_reply_local=True, arp_responder_reply_local=True,
        )
    _test_assert((br, ip, mac, None) in of._arp_responder_installed, "local included when both True")


def test_of_manager_flow_exists_mocked() -> None:
    """OFManager._flow_exists and ensure_flows skip-add with mocked run_ofctl."""
    log = logging.getLogger("test")
    of = OFManager(_MockFlowRegistry(), [BridgeName("vmbr0")], log, of_table=0, of_priority=100)
    with patch.object(OVSCommand, "run_ofctl") as m:
        m.return_value = (True, " cookie=0x1, table=0, n_packets=0, priority=100,arp actions=output:LOCAL,NORMAL")
        _test_assert(of._flow_exists(BridgeName("vmbr0"), 0, 100, "arp", "output:LOCAL,NORMAL") is True, "_flow_exists when dump has line")
    with patch.object(OVSCommand, "run_ofctl") as m:
        m.return_value = (True, "")
        _test_assert(of._flow_exists(BridgeName("vmbr0"), 0, 100, "arp", "output:LOCAL,NORMAL") is False, "_flow_exists when dump empty")
    with patch.object(OVSCommand, "run_ofctl") as m:
        m.return_value = (False, "bridge not found")
        _test_assert(of._flow_exists(BridgeName("vmbr0"), 0, 100, "arp", "output:LOCAL,NORMAL") is False, "_flow_exists when ofctl fails")
    with patch.object(OVSCommand, "run_ofctl") as m:
        def side_effect(action: str, bridge: str, args: str = "", **kwargs: object) -> tuple[bool, str]:
            if action == "del-flows":
                return True, ""
            if action == "dump-flows":
                return True, (
                    " priority=100,arp actions=output:LOCAL,NORMAL\n"
                    " priority=100,udp,tp_dst=67 actions=output:LOCAL,NORMAL\n"
                    " priority=100,udp,tp_dst=68 actions=output:LOCAL,NORMAL"
                )
            return True, ""
        m.side_effect = side_effect
        of.ensure_flows()
        add_flow_calls = [c for c in m.call_args_list if c[0][0] == "add-flow"]
        _test_assert(len(add_flow_calls) == 0, "ensure_flows skips add when flow exists")


def test_of_manager_flow_exists_real() -> None:
    """OFManager._flow_exists against real OVS: add no-match rule in high table, test, delete."""
    bridge = BridgeName("testbr_arbiter_flow_exists")
    table = 200
    priority = 1
    match = "tcp,tp_dst=65535"
    actions = "drop"
    try:
        ok, _ = OVSCommand.run_vsctl(["add-br", str(bridge)])
        if not ok:
            print("  SKIP test_of_manager_flow_exists_real (ovs-vsctl add-br failed)")
            return
        spec_add = f"table={table},priority={priority},{match},actions={actions}"
        ok, err = OVSCommand.run_ofctl("add-flow", str(bridge), spec_add)
        if not ok:
            print(f"  SKIP test_of_manager_flow_exists_real (add-flow failed: {err})")
            OVSCommand.run_vsctl(["del-br", str(bridge)])
            return

        class _MockRegNoCookie:
            def get_cookie(self) -> Optional[OVSCookie]:
                return None

        log = logging.getLogger("test")
        of = OFManager(_MockRegNoCookie(), [bridge], log, of_table=table, of_priority=priority)
        _test_assert(of._flow_exists(bridge, table, priority, match, actions) is True, "_flow_exists True when flow present")
        OVSCommand.run_ofctl("del-flows", str(bridge), f"table={table},{match}")
        _test_assert(of._flow_exists(bridge, table, priority, match, actions) is False, "_flow_exists False after del")
    finally:
        OVSCommand.run_vsctl(["del-br", str(bridge)])


def test_get_installed_arp_responders_parses_reg_vlan() -> None:
    """get_installed_arp_responders parses vlan from NXM_NX_REG<n>[]=0x when present (list-responders fix)."""
    log = logging.getLogger("test")
    of = OFManager(_MockFlowRegistry(), [BridgeName("vmbr0")], log)
    dump_line = (
        " cookie=0x10000000, table=0, priority=1001,NXM_NX_REG0[]=0x5,arp,arp_op=1,arp_tpa=192.168.1.10 "
        "actions=clone(output:LOCAL),clone(move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],mod_dl_src:aa:bb:cc:dd:ee:01,...)"
    )
    with patch.object(OVSCommand, "run_ofctl") as m:
        m.return_value = (True, dump_line)
        result = of.get_installed_arp_responders()
    _test_assert(len(result) == 1, "one flow parsed")
    br, ip, vlan, mac, prio, learn_port = result[0]
    _test_assert(vlan == 5, "vlan parsed from NXM_NX_REG0[]=0x5")
    _test_assert(str(ip) == "192.168.1.10", "ip parsed")


def test_of_manager_send_packet_out() -> None:
    """OFManager.send_packet_out with mocked OVSCommand."""
    log = logging.getLogger("test")
    of = OFManager(_MockFlowRegistry(), [BridgeName("vmbr0")], log)
    with patch.object(OVSCommand, "run_ofctl") as m:
        m.return_value = (True, "")
        ok = of.send_packet_out(BridgeName("vmbr0"), b"\x00\x01", OFPort("1"))
        _test_assert(ok is True and m.called, "send_packet_out")


def test_of_manager_responder_metric_accessors() -> None:
    """Responder accessors expose totals and per-bridge counts."""
    log = logging.getLogger("test")
    br0 = BridgeName("vmbr0")
    br1 = BridgeName("vmbr1")
    of = OFManager(_MockFlowRegistry(), [br0, br1], log)
    k1 = (br0, IPv4Address("10.0.0.1"), MACAddress("aa:bb:cc:dd:ee:01"), None)
    k2 = (br0, IPv4Address("10.0.0.2"), MACAddress("aa:bb:cc:dd:ee:02"), 20)
    k3 = (br1, IPv4Address("10.0.0.3"), MACAddress("aa:bb:cc:dd:ee:03"), None)
    of._arp_responder_installed[k1] = 1001
    of._arp_responder_installed[k2] = 1002
    of._arp_responder_installed[k3] = 1003
    _test_assert(of.arp_responder_flow_count() == 3, "total flow count")
    per_br = of.arp_responder_flows_by_bridge()
    _test_assert(per_br.get("vmbr0") == 2, "vmbr0 flow count")
    _test_assert(per_br.get("vmbr1") == 1, "vmbr1 flow count")


def test_of_manager_sync_counters() -> None:
    """Sync counters track calls, adds, removes, errors."""
    log = logging.getLogger("test")
    br = BridgeName("vmbr0")
    ip = IPv4Address("10.0.0.10")
    mac = MACAddress("aa:bb:cc:dd:ee:10")
    of = OFManager(_MockFlowRegistry(), [br], log)
    desired = {(br, ip, mac, None)}
    with patch("src.of_manager.OVSCommand.run_ofctl") as m:
        m.return_value = (True, "")
        of.sync_arp_responder_flows(desired=desired)
        of.sync_arp_responder_flows(desired=set())
    c = of.arp_responder_sync_counts()
    _test_assert(c.get("ok", 0) >= 2, "sync ok count")
    _test_assert(c.get("added", 0) >= 1, "sync add count")
    _test_assert(c.get("removed", 0) >= 1, "sync remove count")
