"""Tests for src.mesh."""
import json
import logging
import socket
import threading
import time
from unittest.mock import MagicMock, patch
from src.types import MACAddress, IPv4Address, BridgeName, NodeID, RT_SCOPE_HOST
from src.models import IPEntry, IPEntryStore, _key_to_str
from src.config import Config
from src.mesh import PayloadValidator, HMACSigner, MeshBroadcaster
from src.test import _test_assert


def test_payload_validator() -> None:
    """PayloadValidator: check_depth, is_valid."""
    _test_assert(PayloadValidator.check_depth({}, 3) is True, "depth empty")
    _test_assert(PayloadValidator.check_depth({"a": {"b": {"c": 1}}}, 3) is True, "depth 3")
    _test_assert(PayloadValidator.check_depth({"a": {"b": {"c": {"d": 1}}}}, 3) is False, "depth 4")
    _test_assert(PayloadValidator.is_valid({"1.2.3.4": {"ipv4": "1.2.3.4", "mac": "aa:bb:cc:dd:ee:ff"}}) is True, "is_valid")
    _test_assert(PayloadValidator.is_valid("not dict") is False, "is_valid not dict")
    big = {str(i): {} for i in range(1001)}
    _test_assert(PayloadValidator.is_valid(big, max_keys=1000) is False, "is_valid too many keys")


def test_payload_validator_key_len_and_list_depth() -> None:
    """PayloadValidator: max_key_len, list depth."""
    _test_assert(PayloadValidator.is_valid({"k": 1}, max_key_len=1) is True, "key len ok")
    _test_assert(PayloadValidator.is_valid({"ab": 1}, max_key_len=1) is False, "key too long")
    _test_assert(PayloadValidator.check_depth([{"a": 1}], 2) is True, "list depth ok")
    _test_assert(PayloadValidator.check_depth([[["x"]]], 1) is False, "list depth over")


def test_hmac_signer() -> None:
    """HMACSigner: sign, verify_raw (before parse)."""
    key = b"test-key"
    payload = {"mac1": {"ipv4": "1.2.3.4"}}
    signed = HMACSigner.sign(payload, key)
    _test_assert("_sign" in signed and len(json.loads(signed)["_sign"]) == 64, "sign")
    _test_assert(HMACSigner.verify_raw(signed, key) is True, "verify_raw ok")
    _test_assert(HMACSigner.verify_raw(signed, b"wrong") is False, "verify_raw bad key")


def test_hmac_signer_verify_raw_no_sign() -> None:
    """HMACSigner.verify_raw: no _sign in payload returns False."""
    _test_assert(HMACSigner.verify_raw('{"a":1}', b"key") is False, "no _sign")


def test_mesh_broadcaster_send_once() -> None:
    """MeshBroadcaster.send_once uses canonical key and includes entry payload."""
    entries = IPEntryStore()
    ip = IPv4Address("1.2.3.4")
    entries.set(IPEntry(ipv4=ip, mac=MACAddress("aa:bb:cc:dd:ee:ee"), bridge=BridgeName("vmbr0"), last_seen=time.time(), node=NodeID("n1")))
    log = logging.getLogger("test")
    cfg = Config(bridges=["vmbr0"], mesh_ttl=300.0)
    mesh = MeshBroadcaster(entries, log, cfg, node_id=NodeID("n1"))
    sock_mock = MagicMock()
    mesh._sock = sock_mock
    mesh.send_once()
    _test_assert(sock_mock.sendto.called, "sendto called")
    payload = json.loads(mesh._sock.sendto.call_args[0][0].decode("utf-8"))
    key = _key_to_str((ip, BridgeName("vmbr0"), None))
    _test_assert(key in payload and payload[key].get("mac") == "aa:bb:cc:dd:ee:ee", "payload keyed by canonical key")


def test_mesh_send_on_change_not_blocked_by_max_interval() -> None:
    """Changed payload sends immediately, independent of max interval."""
    entries = IPEntryStore()
    ip = IPv4Address("1.2.3.9")
    entry = IPEntry(
        ipv4=ip,
        mac=MACAddress("aa:bb:cc:dd:ee:09"),
        bridge=BridgeName("vmbr0"),
        last_seen=1000.0,
        node=NodeID("n1"),
    )
    entries.set(entry)
    log = logging.getLogger("test")
    cfg = Config(
        bridges=["vmbr0"],
        mesh_ttl=300.0,
        mesh_send_on_change=True,
        mesh_send_max_interval=99.0,
    )
    mesh = MeshBroadcaster(entries, log, cfg, node_id=NodeID("n1"))
    mesh._sock = MagicMock()
    with patch("src.mesh.time.time", side_effect=[1000.0, 1001.0]):
        mesh.send_once()
        # Simulate new snoop update changing payload fingerprint.
        entries.set(
            IPEntry(
                ipv4=ip,
                mac=MACAddress("aa:bb:cc:dd:ee:09"),
                bridge=BridgeName("vmbr0"),
                last_seen=1001.0,
                node=NodeID("n1"),
            )
        )
        mesh.send_once()
    _test_assert(mesh._sock.sendto.call_count == 2, "changed payload sends immediately")


def test_mesh_send_on_change_sends_unchanged_after_max_interval() -> None:
    """Unchanged payload is re-sent after max interval."""
    entries = IPEntryStore()
    ip = IPv4Address("1.2.3.10")
    entries.set(
        IPEntry(
            ipv4=ip,
            mac=MACAddress("aa:bb:cc:dd:ee:10"),
            bridge=BridgeName("vmbr0"),
            last_seen=1000.0,
            node=NodeID("n1"),
        )
    )
    log = logging.getLogger("test")
    cfg = Config(
        bridges=["vmbr0"],
        mesh_ttl=300.0,
        mesh_send_on_change=True,
        mesh_send_max_interval=5.0,
    )
    mesh = MeshBroadcaster(entries, log, cfg, node_id=NodeID("n1"))
    mesh._sock = MagicMock()
    with patch("src.mesh.time.time", side_effect=[1000.0, 1003.0, 1006.0]):
        mesh.send_once()
        mesh.send_once()
        mesh.send_once()
    _test_assert(mesh._sock.sendto.call_count == 2, "unchanged payload re-sent after max interval")


def test_mesh_host_local_not_exported() -> None:
    """Scope host entries not exported (entry.to_mesh_dict() returns None)."""
    entries = IPEntryStore()
    now = time.time()
    ip_export = IPv4Address("10.0.0.5")
    host_local_ip = IPv4Address("192.168.1.1")
    entries.set(IPEntry(ipv4=ip_export, mac=MACAddress("aa:bb:cc:dd:ee:01"), bridge=BridgeName("vmbr0"), last_seen=now, node=NodeID("n1")))
    entries.set(IPEntry(ipv4=host_local_ip, mac=MACAddress("aa:bb:cc:dd:ee:02"), bridge=BridgeName("vmbr0"), last_seen=now, node=NodeID("n1"), scope=RT_SCOPE_HOST))
    log = logging.getLogger("test")
    cfg = Config(bridges=["vmbr0"], mesh_ttl=300.0)
    mesh = MeshBroadcaster(entries, log, cfg, node_id=NodeID("n1"))
    mesh._sock = MagicMock()
    mesh.send_once()
    _test_assert(mesh._sock.sendto.called, "sendto called")
    payload = json.loads(mesh._sock.sendto.call_args[0][0].decode("utf-8"))
    ip_vals = [p.get("ipv4") for p in payload.values() if isinstance(p, dict)]
    _test_assert(str(host_local_ip) not in ip_vals, "scope host IP not in payload")
    _test_assert("10.0.0.5" in ip_vals, "global scope IP in payload")


def test_mesh_host_local_by_netlink_not_exported() -> None:
    """Entry with no scope but netlink says is_host_local(ip) must NOT be in payload (negative)."""
    entries = IPEntryStore()
    now = time.time()
    scope_host_ip = IPv4Address("192.168.12.1")  # scope host on bridge, often snooped without scope
    global_ip = IPv4Address("192.168.12.5")
    entries.set(IPEntry(ipv4=scope_host_ip, mac=MACAddress("f6:87:a0:ad:bb:4a"), bridge=BridgeName("vmbr00"), type="bridge", node=NodeID("172.16.12.13"), last_seen=now, snoop_origin=["arp"]))
    entries.set(IPEntry(ipv4=global_ip, mac=MACAddress("f6:87:a0:ad:bb:4a"), bridge=BridgeName("vmbr00"), type="bridge", node=NodeID("172.16.12.13"), last_seen=now))
    log = logging.getLogger("test")
    cfg = Config(bridges=["vmbr00"], mesh_ttl=300.0)
    netlink_mock = MagicMock()
    netlink_mock.is_host_local.side_effect = lambda ip: str(ip) == "192.168.12.1"
    mesh = MeshBroadcaster(entries, log, cfg, node_id=NodeID("172.16.12.13"), netlink=netlink_mock)
    mesh._sock = MagicMock()
    mesh.send_once()
    payload = json.loads(mesh._sock.sendto.call_args[0][0].decode("utf-8"))
    ip_vals = [p.get("ipv4") for p in payload.values() if isinstance(p, dict)]
    _test_assert("192.168.12.1" not in ip_vals, "host-local by netlink must not be exported")
    _test_assert("192.168.12.5" in ip_vals, "global IP exported")


def test_mesh_minimal_fields() -> None:
    """Mesh payload from to_mesh_dict has ipv4, mac, bridge, type, node, vlan, last_seen."""
    entries = IPEntryStore()
    ip = IPv4Address("10.0.0.6")
    entries.set(IPEntry(ipv4=ip, mac=MACAddress("aa:bb:cc:dd:ee:03"), bridge=BridgeName("vmbr0"), type="vm", node=NodeID("n1"), last_seen=time.time()))
    log = logging.getLogger("test")
    cfg = Config(bridges=["vmbr0"], mesh_ttl=300.0)
    mesh = MeshBroadcaster(entries, log, cfg, node_id=NodeID("n1"))
    mesh._sock = MagicMock()
    mesh.send_once()
    payload = json.loads(mesh._sock.sendto.call_args[0][0].decode("utf-8"))
    allowed = {"ipv4", "mac", "bridge", "type", "node", "vlan", "last_seen"}
    for ip_key, entry_dict in payload.items():
        if ip_key.startswith("_"):
            continue
        _test_assert(set(entry_dict.keys()) <= allowed, f"minimal fields only: {set(entry_dict.keys())}")


def test_mesh_recv_verify_before_parse() -> None:
    """Bad signature: reject before json.loads (verify before parse)."""
    key = b"secret"
    payload = {"1.2.3.4": {"ipv4": "1.2.3.4", "mac": "aa:bb:cc:dd:ee:ff", "bridge": "vmbr0"}}
    signed = HMACSigner.sign(payload, key)
    tampered = signed[:-2] + "00"  # corrupt signature so verify_raw fails
    _test_assert(not HMACSigner.verify_raw(tampered, key), "tampered fails verify_raw")
    entries = IPEntryStore()
    log = logging.getLogger("test")
    cfg = Config(bridges=["vmbr0"], mesh_sign_key=key.decode("utf-8"))
    mesh = MeshBroadcaster(entries, log, cfg, node_id=NodeID("othernode"))
    mesh._sock = MagicMock()
    calls = [0]

    def recv(*args: object, **kwargs: object) -> tuple[bytes, tuple[str, int]]:
        calls[0] += 1
        if calls[0] == 1:
            return (tampered.encode("utf-8"), ("10.0.0.1", 9876))
        mesh._stop.set()
        raise socket.timeout

    mesh._sock.recvfrom = recv
    with patch("src.mesh.json.loads", wraps=json.loads) as mock_loads:
        t = threading.Thread(target=mesh._recv_loop)
        t.start()
        t.join(timeout=2.0)
    _test_assert(mock_loads.call_count == 0, "verify before parse: json.loads not called on bad sig")


def test_mesh_recv_verify_before_parse_valid_sig() -> None:
    """Valid signature: parse and merge into IPEntryStore (keyed by IP)."""
    key = b"secret"
    payload = {"10.0.0.1": {"ipv4": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:01", "bridge": "vmbr0"}}
    signed = HMACSigner.sign(payload, key)
    _test_assert(HMACSigner.verify_raw(signed, key), "valid signed passes verify_raw")
    entries = IPEntryStore()
    log = logging.getLogger("test")
    cfg = Config(bridges=["vmbr0"], mesh_sign_key=key.decode("utf-8"))
    mesh = MeshBroadcaster(entries, log, cfg, node_id=NodeID("othernode"))
    mesh._sock = MagicMock()
    calls = [0]

    def recv(*args: object, **kwargs: object) -> tuple[bytes, tuple[str, int]]:
        calls[0] += 1
        if calls[0] == 1:
            return (signed.encode("utf-8"), ("10.0.0.2", 9876))
        mesh._stop.set()
        raise socket.timeout

    mesh._sock.recvfrom = recv
    t = threading.Thread(target=mesh._recv_loop)
    t.start()
    t.join(timeout=2.0)
    ip = IPv4Address("10.0.0.1")
    e = entries.get(ip, BridgeName("vmbr0"), None)
    _test_assert(e is not None and e.ipv4 == ip and e.mac == MACAddress("aa:bb:cc:dd:ee:01"), "valid sig: parsed and merged")
    _test_assert(e.node == NodeID("10.0.0.2"), "node from sender")


def test_mesh_recv_missing_remote_entry_marks_expired() -> None:
    """When sender omits previously owned key, mark it expired."""
    entries = IPEntryStore()
    now = 1000.0
    sender = NodeID("10.0.0.2")
    keep_ip = IPv4Address("10.0.0.10")
    drop_ip = IPv4Address("10.0.0.11")
    br = BridgeName("vmbr0")
    entries.set(
        IPEntry(
            ipv4=keep_ip,
            mac=MACAddress("aa:bb:cc:dd:ee:10"),
            bridge=br,
            node=sender,
            last_seen=100.0,
        )
    )
    entries.set(
        IPEntry(
            ipv4=drop_ip,
            mac=MACAddress("aa:bb:cc:dd:ee:11"),
            bridge=br,
            node=sender,
            last_seen=100.0,
        )
    )
    log = logging.getLogger("test")
    cfg = Config(bridges=["vmbr0"], mesh_ttl=300.0)
    mesh = MeshBroadcaster(entries, log, cfg, node_id=NodeID("othernode"))
    raw = {
        "10.0.0.10|vmbr0|": {
            "ipv4": "10.0.0.10",
            "mac": "aa:bb:cc:dd:ee:10",
            "bridge": "vmbr0",
            "last_seen": 200.0,
        }
    }
    merged = mesh._merge_payload_entries("10.0.0.2", raw, now)
    _test_assert(merged == 1, "one key merged")
    keep = entries.get(keep_ip, br, None)
    drop = entries.get(drop_ip, br, None)
    _test_assert(keep is not None and keep.expired is None, "present key stays active")
    _test_assert(drop is not None and drop.expired == now, "missing key marked expired")


def test_mesh_recv_missing_remote_entry_keeps_other_nodes() -> None:
    """Omitted keys only expire for sender node, not other owners."""
    entries = IPEntryStore()
    now = 1000.0
    br = BridgeName("vmbr0")
    entries.set(
        IPEntry(
            ipv4=IPv4Address("10.0.0.20"),
            mac=MACAddress("aa:bb:cc:dd:ee:20"),
            bridge=br,
            node=NodeID("10.0.0.2"),
            last_seen=100.0,
        )
    )
    entries.set(
        IPEntry(
            ipv4=IPv4Address("10.0.0.21"),
            mac=MACAddress("aa:bb:cc:dd:ee:21"),
            bridge=br,
            node=NodeID("10.0.0.3"),
            last_seen=100.0,
        )
    )
    log = logging.getLogger("test")
    cfg = Config(bridges=["vmbr0"], mesh_ttl=300.0)
    mesh = MeshBroadcaster(entries, log, cfg, node_id=NodeID("othernode"))
    raw = {}
    merged = mesh._merge_payload_entries("10.0.0.2", raw, now)
    _test_assert(merged == 0, "no keys merged")
    e_sender = entries.get(IPv4Address("10.0.0.20"), br, None)
    e_other = entries.get(IPv4Address("10.0.0.21"), br, None)
    _test_assert(e_sender is not None and e_sender.expired == now, "sender-owned key expired")
    _test_assert(e_other is not None and e_other.expired is None, "other node key untouched")


def test_mesh_send_once_payload_contains_all_active_entries() -> None:
    """send_once exports full active sender snapshot keyed by canonical key."""
    entries = IPEntryStore()
    now = 1000.0
    node = NodeID("10.0.0.2")
    e1 = IPEntry(
        ipv4=IPv4Address("10.0.0.30"),
        mac=MACAddress("aa:bb:cc:dd:ee:30"),
        bridge=BridgeName("vmbr0"),
        vlan=None,
        node=node,
        last_seen=now,
    )
    e2 = IPEntry(
        ipv4=IPv4Address("10.0.0.30"),
        mac=MACAddress("aa:bb:cc:dd:ee:31"),
        bridge=BridgeName("vmbr0"),
        vlan=20,
        node=node,
        last_seen=now,
    )
    e3 = IPEntry(
        ipv4=IPv4Address("10.0.0.40"),
        mac=MACAddress("aa:bb:cc:dd:ee:40"),
        bridge=BridgeName("vmbr1"),
        vlan=30,
        node=node,
        last_seen=now,
    )
    entries.set(e1)
    entries.set(e2)
    entries.set(e3)
    cfg = Config(bridges=["vmbr0", "vmbr1"], mesh_ttl=300.0)
    mesh = MeshBroadcaster(entries, logging.getLogger("test"), cfg, node_id=node)
    mesh._sock = MagicMock()
    with patch("src.mesh.time.time", return_value=now):
        mesh.send_once()
    payload = json.loads(mesh._sock.sendto.call_args[0][0].decode("utf-8"))
    expected_keys = {
        _key_to_str((e1.ipv4, e1.bridge, None)),
        _key_to_str((e2.ipv4, e2.bridge, 20)),
        _key_to_str((e3.ipv4, e3.bridge, 30)),
    }
    payload_keys = {k for k in payload.keys() if not k.startswith("_")}
    _test_assert(payload_keys == expected_keys, "payload has full active snapshot keys")


def test_mesh_recv_missing_remote_entry_seen_keys_multi_key() -> None:
    """seen_keys keeps all provided sender keys active even with same IP."""
    entries = IPEntryStore()
    now = 1000.0
    sender = NodeID("10.0.0.2")
    br = BridgeName("vmbr0")
    ip = IPv4Address("10.0.0.50")
    keep_untagged = IPEntry(ipv4=ip, mac=MACAddress("aa:bb:cc:dd:ee:50"), bridge=br, vlan=None, node=sender, last_seen=100.0)
    keep_vlan = IPEntry(ipv4=ip, mac=MACAddress("aa:bb:cc:dd:ee:51"), bridge=br, vlan=20, node=sender, last_seen=100.0)
    drop_vlan = IPEntry(ipv4=IPv4Address("10.0.0.51"), mac=MACAddress("aa:bb:cc:dd:ee:52"), bridge=br, vlan=30, node=sender, last_seen=100.0)
    entries.set(keep_untagged)
    entries.set(keep_vlan)
    entries.set(drop_vlan)
    mesh = MeshBroadcaster(entries, logging.getLogger("test"), Config(bridges=["vmbr0"], mesh_ttl=300.0), node_id=NodeID("othernode"))
    raw = {
        _key_to_str((keep_untagged.ipv4, keep_untagged.bridge, None)): {
            "ipv4": str(keep_untagged.ipv4),
            "mac": str(keep_untagged.mac),
            "bridge": str(keep_untagged.bridge),
            "vlan": None,
            "last_seen": 200.0,
        },
        _key_to_str((keep_vlan.ipv4, keep_vlan.bridge, 20)): {
            "ipv4": str(keep_vlan.ipv4),
            "mac": str(keep_vlan.mac),
            "bridge": str(keep_vlan.bridge),
            "vlan": 20,
            "last_seen": 200.0,
        },
    }
    merged = mesh._merge_payload_entries(str(sender), raw, now)
    _test_assert(merged == 2, "two keys merged from sender")
    e1 = entries.get(keep_untagged.ipv4, keep_untagged.bridge, None)
    e2 = entries.get(keep_vlan.ipv4, keep_vlan.bridge, 20)
    e3 = entries.get(drop_vlan.ipv4, drop_vlan.bridge, 30)
    _test_assert(e1 is not None and e1.expired is None, "untagged key stays active")
    _test_assert(e2 is not None and e2.expired is None, "vlan key stays active")
    _test_assert(e3 is not None and e3.expired == now, "missing key expires")


def test_mesh_recv_active_local_owner_is_replaced_by_remote_default() -> None:
    """Remote update replaces active local owner when verify is off."""
    entries = IPEntryStore()
    now = 1000.0
    ip = IPv4Address("192.168.13.105")
    br = BridgeName("vmbr0")
    entries.set(
        IPEntry(
            ipv4=ip,
            mac=MACAddress("fa:9b:c9:91:4d:47"),
            bridge=br,
            vlan=100,
            node=NodeID("172.16.12.10"),
            last_seen=950.0,
        )
    )
    log = logging.getLogger("test")
    cfg = Config(bridges=["vmbr0"], mesh_ttl=300.0)
    mesh = MeshBroadcaster(entries, log, cfg, node_id=NodeID("172.16.12.10"))
    raw = {
        "192.168.13.105|vmbr0|100": {
            "ipv4": "192.168.13.105",
            "mac": "fa:9b:c9:91:4d:47",
            "bridge": "vmbr0",
            "vlan": 100,
            "last_seen": 990.0,
        }
    }
    merged = mesh._merge_payload_entries("172.16.12.12", raw, now)
    _test_assert(merged == 1, "one key merged")
    e = entries.get(ip, br, 100)
    _test_assert(e is not None and e.node == NodeID("172.16.12.12"), "active local owner replaced")


def test_mesh_recv_owner_change_calls_hook() -> None:
    """Remote owner change calls hook."""
    entries = IPEntryStore()
    now = 1000.0
    ip = IPv4Address("192.168.13.106")
    br = BridgeName("vmbr0")
    old_owner = NodeID("172.16.12.10")
    new_owner = NodeID("172.16.12.12")
    entries.set(
        IPEntry(
            ipv4=ip,
            mac=MACAddress("fa:9b:c9:91:4d:48"),
            bridge=br,
            vlan=100,
            node=old_owner,
            last_seen=950.0,
        )
    )
    owner_change = MagicMock()
    log = logging.getLogger("test")
    cfg = Config(bridges=["vmbr0"], mesh_ttl=300.0)
    mesh = MeshBroadcaster(
        entries,
        log,
        cfg,
        node_id=NodeID("172.16.12.10"),
        on_owner_change=owner_change,
    )
    raw = {
        "192.168.13.106|vmbr0|100": {
            "ipv4": "192.168.13.106",
            "mac": "fa:9b:c9:91:4d:48",
            "bridge": "vmbr0",
            "vlan": 100,
            "last_seen": 990.0,
        }
    }
    merged = mesh._merge_payload_entries(str(new_owner), raw, now)
    _test_assert(merged == 1, "one key merged")
    owner_change.assert_called_once_with(ip, br, 100, old_owner, new_owner)


def test_mesh_recv_stale_local_owner_can_be_replaced() -> None:
    """Remote update can replace stale/expired local owner."""
    entries = IPEntryStore()
    now = 1000.0
    ip = IPv4Address("192.168.13.105")
    br = BridgeName("vmbr0")
    entries.set(
        IPEntry(
            ipv4=ip,
            mac=MACAddress("fa:9b:c9:91:4d:47"),
            bridge=br,
            vlan=100,
            node=NodeID("172.16.12.10"),
            last_seen=100.0,
            expired=200.0,
        )
    )
    log = logging.getLogger("test")
    cfg = Config(bridges=["vmbr0"], mesh_ttl=300.0)
    mesh = MeshBroadcaster(entries, log, cfg, node_id=NodeID("172.16.12.10"))
    raw = {
        "192.168.13.105|vmbr0|100": {
            "ipv4": "192.168.13.105",
            "mac": "fa:9b:c9:91:4d:47",
            "bridge": "vmbr0",
            "vlan": 100,
            "last_seen": 990.0,
        }
    }
    merged = mesh._merge_payload_entries("172.16.12.12", raw, now)
    _test_assert(merged == 1, "one key merged")
    e = entries.get(ip, br, 100)
    _test_assert(e is not None and e.node == NodeID("172.16.12.12"), "stale local owner replaced")


def test_mesh_recv_reclaim_clears_expired() -> None:
    """Present key from sender clears expired state."""
    entries = IPEntryStore()
    now = 1000.0
    ip = IPv4Address("10.0.0.50")
    br = BridgeName("vmbr0")
    sender = NodeID("10.0.0.2")
    entries.set(
        IPEntry(
            ipv4=ip,
            mac=MACAddress("aa:bb:cc:dd:ee:50"),
            bridge=br,
            node=sender,
            last_seen=100.0,
            expired=900.0,
        )
    )
    log = logging.getLogger("test")
    cfg = Config(bridges=["vmbr0"], mesh_ttl=300.0)
    mesh = MeshBroadcaster(entries, log, cfg, node_id=NodeID("10.0.0.1"))
    raw = {
        "10.0.0.50|vmbr0|": {
            "ipv4": "10.0.0.50",
            "mac": "aa:bb:cc:dd:ee:50",
            "bridge": "vmbr0",
            "last_seen": 980.0,
        }
    }
    merged = mesh._merge_payload_entries(str(sender), raw, now)
    _test_assert(merged == 1, "one key merged")
    e = entries.get(ip, br, None)
    _test_assert(e is not None and e.expired is None, "expired cleared after re-claim")
    _test_assert(e is not None and e.is_active(now, 300.0), "entry active after re-claim")


def test_mesh_recv_uses_payload_node_identity() -> None:
    """Receiver uses payload _node as ownership identity."""
    entries = IPEntryStore()
    log = logging.getLogger("test")
    cfg = Config(bridges=["vmbr0"], mesh_ttl=300.0)
    mesh = MeshBroadcaster(entries, log, cfg, node_id=NodeID("10.0.0.1"))
    payload = {
        "_node": "172.16.12.99",
        "_uptime": 42,
        "10.0.0.60|vmbr0|": {
            "ipv4": "10.0.0.60",
            "mac": "aa:bb:cc:dd:ee:60",
            "bridge": "vmbr0",
            "last_seen": 10.0,
        },
    }
    mesh._handle_recv(json.dumps(payload).encode("utf-8"), ("10.0.0.2", 9876))
    e = entries.get(IPv4Address("10.0.0.60"), BridgeName("vmbr0"), None)
    _test_assert(e is not None and e.node == NodeID("172.16.12.99"), "node from payload _node")
    seen = mesh.get_node_last_seen()
    _test_assert("172.16.12.99" in seen, "last_seen keyed by payload _node")
    _test_assert("10.0.0.2" not in seen, "sender ip not used as node key")


def test_mesh_recv_remote_conflict_trusts_incoming_by_default() -> None:
    """Remote conflict trusts incoming owner change when verify is off."""
    entries = IPEntryStore()
    now = 1000.0
    ip = IPv4Address("10.0.0.70")
    br = BridgeName("vmbr0")
    entries.set(
        IPEntry(
            ipv4=ip,
            mac=MACAddress("aa:bb:cc:dd:ee:70"),
            bridge=br,
            node=NodeID("10.0.0.3"),
            last_seen=900.0,
        )
    )
    log = logging.getLogger("test")
    cfg = Config(bridges=["vmbr0"], mesh_ttl=300.0)
    mesh = MeshBroadcaster(entries, log, cfg, node_id=NodeID("10.0.0.1"))

    raw_older = {
        "10.0.0.70|vmbr0|": {
            "ipv4": "10.0.0.70",
            "mac": "aa:bb:cc:dd:ee:70",
            "bridge": "vmbr0",
            "last_seen": 850.0,
        }
    }
    merged_older = mesh._merge_payload_entries("10.0.0.2", raw_older, now)
    _test_assert(merged_older == 1, "older conflict claim accepted by default")
    e_older = entries.get(ip, br, None)
    _test_assert(e_older is not None and e_older.node == NodeID("10.0.0.2"), "incoming sender becomes owner")

    raw_newer = {
        "10.0.0.70|vmbr0|": {
            "ipv4": "10.0.0.70",
            "mac": "aa:bb:cc:dd:ee:70",
            "bridge": "vmbr0",
            "last_seen": 950.0,
        }
    }
    merged_newer = mesh._merge_payload_entries("10.0.0.2", raw_newer, now)
    _test_assert(merged_newer == 1, "newer conflict claim accepted")
    e_newer = entries.get(ip, br, None)
    _test_assert(e_newer is not None and e_newer.node == NodeID("10.0.0.2"), "newer sender becomes owner")


def test_mesh_recv_remote_conflict_updates_mac_and_owner() -> None:
    """Remote conflict updates owner and MAC when verify is off."""
    entries = IPEntryStore()
    now = 1000.0
    ip = IPv4Address("10.0.0.71")
    br = BridgeName("vmbr0")
    entries.set(
        IPEntry(
            ipv4=ip,
            mac=MACAddress("aa:bb:cc:dd:ee:71"),
            bridge=br,
            node=NodeID("10.0.0.3"),
            last_seen=900.0,
        )
    )
    log = logging.getLogger("test")
    cfg = Config(bridges=["vmbr0"], mesh_ttl=300.0)
    mesh = MeshBroadcaster(entries, log, cfg, node_id=NodeID("10.0.0.1"))
    raw = {
        "10.0.0.71|vmbr0|": {
            "ipv4": "10.0.0.71",
            "mac": "aa:bb:cc:dd:ee:99",
            "bridge": "vmbr0",
            "last_seen": 950.0,
        }
    }
    merged = mesh._merge_payload_entries("10.0.0.2", raw, now)
    _test_assert(merged == 1, "conflict claim accepted")
    e = entries.get(ip, br, None)
    _test_assert(e is not None and e.node == NodeID("10.0.0.2"), "owner updated")
    _test_assert(e is not None and e.mac == MACAddress("aa:bb:cc:dd:ee:99"), "mac updated")


def test_mesh_recv_remote_migration_denied_without_confirmation() -> None:
    """Remote owner change is denied when verify_remote_migration fails."""
    entries = IPEntryStore()
    now = 1000.0
    ip = IPv4Address("10.0.0.80")
    br = BridgeName("vmbr0")
    entries.set(
        IPEntry(
            ipv4=ip,
            mac=MACAddress("aa:bb:cc:dd:ee:80"),
            bridge=br,
            node=NodeID("10.0.0.3"),
            last_seen=900.0,
        )
    )
    cfg = Config(bridges=["vmbr0"], mesh_ttl=300.0, verify_remote_migration=True)
    log = MagicMock(spec=logging.Logger)
    confirm = MagicMock(return_value=False)
    mesh = MeshBroadcaster(
        entries,
        log,
        cfg,
        node_id=NodeID("10.0.0.1"),
        is_remote_migration_confirmed=confirm,
    )
    raw = {
        "10.0.0.80|vmbr0|": {
            "ipv4": "10.0.0.80",
            "mac": "aa:bb:cc:dd:ee:80",
            "bridge": "vmbr0",
            "last_seen": 950.0,
        }
    }
    merged = mesh._merge_payload_entries("10.0.0.2", raw, now)
    _test_assert(merged == 0, "unconfirmed migration denied")
    e = entries.get(ip, br, None)
    _test_assert(e is not None and e.node == NodeID("10.0.0.3"), "owner unchanged")
    _test_assert(confirm.call_count == 1, "confirm callback called")
    _test_assert(log.error.call_count >= 1, "denied migration logs alert")


def test_mesh_recv_remote_migration_allowed_with_confirmation() -> None:
    """Remote owner change is allowed when verify_remote_migration passes."""
    entries = IPEntryStore()
    now = 1000.0
    ip = IPv4Address("10.0.0.81")
    br = BridgeName("vmbr0")
    entries.set(
        IPEntry(
            ipv4=ip,
            mac=MACAddress("aa:bb:cc:dd:ee:81"),
            bridge=br,
            node=NodeID("10.0.0.3"),
            last_seen=900.0,
        )
    )
    cfg = Config(bridges=["vmbr0"], mesh_ttl=300.0, verify_remote_migration=True)
    confirm = MagicMock(return_value=True)
    mesh = MeshBroadcaster(
        entries,
        logging.getLogger("test"),
        cfg,
        node_id=NodeID("10.0.0.1"),
        is_remote_migration_confirmed=confirm,
    )
    raw = {
        "10.0.0.81|vmbr0|": {
            "ipv4": "10.0.0.81",
            "mac": "aa:bb:cc:dd:ee:81",
            "bridge": "vmbr0",
            "last_seen": 950.0,
        }
    }
    merged = mesh._merge_payload_entries("10.0.0.2", raw, now)
    _test_assert(merged == 1, "confirmed migration accepted")
    e = entries.get(ip, br, None)
    _test_assert(e is not None and e.node == NodeID("10.0.0.2"), "owner changed")


def test_mesh_recv_confirm_called_on_new_entry_for_local_mac() -> None:
    """Confirm callback fires on new entries, so remote claims on unknown IP are still authorised."""
    entries = IPEntryStore()
    now = 1000.0
    ip = IPv4Address("192.168.12.32")
    br = BridgeName("vmbr0")
    local_mac = MACAddress("bc:24:11:d7:ad:5a")
    cfg = Config(bridges=["vmbr0"], mesh_ttl=300.0)
    log = MagicMock(spec=logging.Logger)
    confirm = MagicMock(return_value=False)
    mesh = MeshBroadcaster(
        entries,
        log,
        cfg,
        node_id=NodeID("172.16.12.13"),
        is_remote_migration_confirmed=confirm,
    )
    raw = {
        "192.168.12.32|vmbr0|": {
            "ipv4": "192.168.12.32",
            "mac": str(local_mac),
            "bridge": "vmbr0",
            "last_seen": now,
        }
    }
    merged = mesh._merge_payload_entries("172.16.12.10", raw, now)
    _test_assert(merged == 0, "remote claim refused for unknown-but-local mac")
    _test_assert(entries.get(ip, br, None) is None, "no entry created")
    _test_assert(confirm.call_count == 1, "confirm called even with no existing entry")
    _test_assert(log.error.call_count >= 1, "refusal logged as alert")


def test_mesh_recv_confirm_skipped_on_same_owner_refresh() -> None:
    """Confirm callback is not invoked when refresh keeps the same owner."""
    entries = IPEntryStore()
    now = 1000.0
    ip = IPv4Address("192.168.12.40")
    br = BridgeName("vmbr0")
    mac = MACAddress("aa:bb:cc:dd:ee:40")
    sender = NodeID("172.16.12.12")
    entries.set(
        IPEntry(
            ipv4=ip,
            mac=mac,
            bridge=br,
            node=sender,
            last_seen=900.0,
        )
    )
    cfg = Config(bridges=["vmbr0"], mesh_ttl=300.0)
    confirm = MagicMock(return_value=True)
    mesh = MeshBroadcaster(
        entries,
        logging.getLogger("test"),
        cfg,
        node_id=NodeID("172.16.12.13"),
        is_remote_migration_confirmed=confirm,
    )
    raw = {
        "192.168.12.40|vmbr0|": {
            "ipv4": "192.168.12.40",
            "mac": str(mac),
            "bridge": "vmbr0",
            "last_seen": 950.0,
        }
    }
    merged = mesh._merge_payload_entries(str(sender), raw, now)
    _test_assert(merged == 1, "same-owner refresh accepted")
    _test_assert(confirm.call_count == 0, "confirm skipped when owner unchanged")


def test_mesh_start_bind_failure_closes_socket_no_recv_thread() -> None:
    """Bind OSError clears socket and does not start recv thread."""
    entries = IPEntryStore()
    log = logging.getLogger("test")
    cfg = Config(bridges=["vmbr0"], mesh_ttl=300.0, mesh_port=55441)
    mesh = MeshBroadcaster(entries, log, cfg, node_id=NodeID("n1"))
    sock_mock = MagicMock()
    sock_mock.bind.side_effect = OSError(98, "Address already in use")
    with patch("src.mesh.socket.socket", return_value=sock_mock):
        mesh.start()
    _test_assert(mesh._sock is None, "sock cleared after bind fail")
    _test_assert(mesh._recv_thread is None, "no recv thread")
    _test_assert(sock_mock.close.called, "socket closed")


def test_mesh_handle_recv_unexpected_exception_logs_warning() -> None:
    """_handle_recv logs warning (not debug-only) on unexpected errors."""
    entries = IPEntryStore()
    log = logging.getLogger("test_mesh_exc")
    cfg = Config(bridges=["vmbr0"], mesh_ttl=300.0)
    mesh = MeshBroadcaster(entries, log, cfg, node_id=NodeID("n1"))
    raw_ok = {"_node": "other", "k": {"ipv4": "1.2.3.4", "mac": "aa:bb:cc:dd:ee:01"}}
    with patch.object(mesh, "_merge_payload_entries", side_effect=RuntimeError("boom")):
        with patch.object(mesh, "_decode_and_validate_payload", return_value=raw_ok):
            with patch.object(mesh, "_update_peer_uptime", return_value=True):
                with patch.object(mesh, "_is_keepalive_only", return_value=False):
                    with patch.object(mesh, "_is_foreign_node", return_value=True):
                        with patch.object(mesh, "_dedup_payload", return_value=True):
                            with patch.object(mesh.log, "warning") as log_warn:
                                mesh._handle_recv(b"{}", ("10.0.0.2", 12345))
    _test_assert(log_warn.call_count >= 1, "warning logged")
    joined = " ".join(str(c) for c in log_warn.call_args_list)
    _test_assert("unexpected" in joined, "unexpected in log")
