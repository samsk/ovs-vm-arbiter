"""Tests for src.ovs_manager."""
import logging
import time
from unittest.mock import patch
from src.ovs_cmd import OVSCommand
from src.ovs_manager import OVSManager
from src.config import Config
from src.types import NodeID, OFPort, InterfaceName
from src.test import _test_assert


def test_ovs_manager_list_table() -> None:
    """OVSManager.list_table with mocked OVSCommand."""
    log = logging.getLogger("test")
    cfg = Config(bridges=["vmbr0"])
    with patch.object(OVSCommand, "run_vsctl") as m:
        m.return_value = (True, {"headings": ["name"], "data": [["vmbr0"]]})
        ovs = OVSManager(log, cfg)
        rows = ovs.list_table("Bridge")
        _test_assert(len(rows) == 1 and rows[0]["name"] == "vmbr0", "list_table")


def test_ovs_manager_get_bridge_node_to_ofport() -> None:
    """OVSManager.get_bridge_node_to_ofport with mocked cache."""
    log = logging.getLogger("test")
    cfg = Config(bridges=["vmbr0"])
    with patch.object(OVSCommand, "run_vsctl") as m:
        m.return_value = (True, {"headings": [], "data": []})
        ovs = OVSManager(log, cfg)
        ovs._cache._cache = {"vmbr0": {NodeID("10.0.0.2"): (OFPort("3"), InterfaceName("vxlan0"))}}
        ovs._cache._cache_ts = time.time()
        node_map = ovs.get_bridge_node_to_ofport("vmbr0")
        _test_assert(NodeID("10.0.0.2") in node_map and node_map[NodeID("10.0.0.2")][0] == OFPort("3"), "get_bridge_node_to_ofport")


def test_resolve_node_port_basic() -> None:
    """OVSManager.resolve_node_port converts OFPort and returns int and port name."""
    node = NodeID("10.0.0.2")
    node_map = {node: (OFPort("3"), InterfaceName("vxlan0"))}
    ofport, name = OVSManager.resolve_node_port(node_map, node)
    _test_assert(ofport == 3, "ofport converted to int")
    _test_assert(name == "vxlan0", "port name preserved")
    ofport_missing, name_missing = OVSManager.resolve_node_port(node_map, NodeID("10.0.0.3"))
    _test_assert(ofport_missing is None and name_missing is None, "missing node -> (None, None)")


def test_ovs_manager_iface_to_bridge() -> None:
    """OVSManager.iface_to_bridge with mocked run_vsctl."""
    log = logging.getLogger("test")
    cfg = Config(bridges=["vmbr0"])
    with patch.object(OVSCommand, "run_vsctl") as m:
        m.return_value = (True, "vmbr0")
        ovs = OVSManager(log, cfg)
        _test_assert(ovs.iface_to_bridge("vxlan0") == "vmbr0", "iface_to_bridge")
    with patch.object(OVSCommand, "run_vsctl") as m:
        m.return_value = (True, "")
        ovs2 = OVSManager(log, cfg)
        _test_assert(ovs2.iface_to_bridge("eth0") is None, "no bridge")


def test_ovs_manager_list_table_failures() -> None:
    """OVSManager.list_table returns empty list for invalid command output."""
    with patch.object(OVSCommand, "run_vsctl", return_value=(False, {})):
        rows_fail = OVSManager().list_table("Bridge")
    _test_assert(rows_fail == [], "list_table command failure -> []")
    with patch.object(OVSCommand, "run_vsctl", return_value=(True, "bad")):
        rows_bad = OVSManager().list_table("Bridge")
    _test_assert(rows_bad == [], "list_table non-dict payload -> []")


def test_resolve_node_port_invalid_ofport() -> None:
    """OVSManager.resolve_node_port handles invalid ofport safely."""
    node = NodeID("10.0.0.9")
    node_map = {node: (OFPort("not-int"), InterfaceName("vxlan9"))}
    ofport, name = OVSManager.resolve_node_port(node_map, node)
    _test_assert(ofport is None, "invalid ofport -> None")
    _test_assert(name == "vxlan9", "port name still returned")


def test_get_bridge_ofport_to_name_skips_invalid_rows() -> None:
    """OVSManager.get_bridge_ofport_to_name ignores malformed interface rows."""
    ovs = OVSManager()
    with patch.object(
        OVSManager,
        "list_table",
        side_effect=[
            [{"name": "vmbr0", "ports": ["set", [["uuid", "p-good"], ["uuid", "p-bad"]]]}],
            [
                {"_uuid": ["uuid", "p-good"], "name": "port-good", "interfaces": ["set", [["uuid", "i-good"]]]},
                {"_uuid": ["uuid", "p-bad"], "name": "port-bad", "interfaces": ["set", [["uuid", "i-bad"]]]},
            ],
            [
                {"_uuid": ["uuid", "i-good"], "ofport": "7"},
                {"_uuid": ["uuid", "i-bad"], "ofport": "not-a-number"},
            ],
        ],
    ):
        result = ovs.get_bridge_ofport_to_name("vmbr0")
    _test_assert(result == {7: "port-good"}, "invalid ofport rows skipped")


def test_patch_ports_to_local_filters_invalid_entries() -> None:
    """OVSManager._patch_ports_to_local keeps only valid patch links."""
    ovs = OVSManager()
    with patch.object(
        OVSManager,
        "list_table",
        side_effect=[
            [
                {"_uuid": ["uuid", "p1"], "name": "patch1", "tag": "100", "interfaces": ["set", [["uuid", "i1"]]]},
                {"_uuid": ["uuid", "p2"], "name": "int1", "interfaces": ["set", [["uuid", "i2"]]]},
                {"_uuid": ["uuid", "p3"], "name": "patch2", "interfaces": ["set", [["uuid", "i3"]]]},
            ],
            [
                {"_uuid": ["uuid", "i1"], "type": "patch", "options": ["map", [["peer", "peer0"]]], "ofport": 5},
                {"_uuid": ["uuid", "i2"], "type": "internal", "options": ["map", [["peer", "peer1"]]], "ofport": 6},
                {"_uuid": ["uuid", "i3"], "type": "patch", "options": ["map", [["peer", "peer2"]]], "ofport": None},
            ],
            [{"name": "vmbr0", "ports": ["set", [["uuid", "p1"], ["uuid", "p2"], ["uuid", "p3"]]]}],
        ],
    ):
        with patch.object(OVSManager, "iface_to_bridge", side_effect=["vmbr1", "vmbr2"]):
            rows = ovs._patch_ports_to_local(["vmbr0"], {"vmbr1"})
    _test_assert(rows == [("vmbr0", "vmbr1", 100, "5", "patch1")], "only valid patch row returned")


def test_options_peer_rejects_none_and_blank() -> None:
    """OVSManager._options_peer rejects missing peer values."""
    _test_assert(OVSManager._options_peer(["map", [["peer", None]]]) is None, "peer none -> None")
    _test_assert(OVSManager._options_peer(["map", [["peer", "  "]]]) is None, "peer blank -> None")


def test_invalidate_local_fdb_mac_vlan_fallback() -> None:
    """OVSManager.invalidate_local_fdb_mac retries without vlan."""
    ovs = OVSManager()
    with patch.object(
        OVSCommand,
        "run_appctl",
        side_effect=[(False, "bad vlan"), (True, "")],
    ) as run_appctl:
        ok = ovs.invalidate_local_fdb_mac("vmbr0", "aa:bb:cc:dd:ee:ff", vlan=101)
    _test_assert(ok is True, "fallback command succeeds")
    _test_assert(run_appctl.call_count == 2, "tries vlan and fallback cmd")
