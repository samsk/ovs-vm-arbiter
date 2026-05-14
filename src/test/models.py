"""Tests for src.models."""
import time
from src.types import (
    MACAddress,
    IPv4Address,
    BridgeName,
    NodeID,
    VMID,
    RT_SCOPE_HOST,
)
from src.models import (
    IPEntry,
    InstanceInfo,
    NetInterface,
    IPEntryStore,
    InstanceStore,
    _entry_key,
    iter_ipentries_from_dict,
)
from src.test import _test_assert


def test_ip_entry() -> None:
    """IPEntry: to_dict, from_dict, is_active, merge_from, copy."""
    e = IPEntry(
        ipv4=IPv4Address("1.2.3.4"),
        mac=MACAddress("aa:bb:cc:dd:ee:ff"),
        bridge=BridgeName("vmbr0"),
        last_seen=100.0,
    )
    d = e.to_dict()
    _test_assert(d.get("ipv4") == "1.2.3.4" and d.get("bridge") == "vmbr0", "to_dict")
    e2 = IPEntry.from_dict({**d, "mac": "aa:bb:cc:dd:ee:ff"})
    _test_assert(e2.ipv4 == e.ipv4 and e2.bridge == e.bridge, "from_dict")
    _test_assert(e.is_active(150.0, 60.0) is True, "is_active within TTL")
    _test_assert(e.is_active(200.0, 60.0) is False, "is_active past TTL")
    e.expired = 100.0
    _test_assert(e.is_active(150.0, 999.0) is False, "is_active expired")
    e3 = IPEntry(ipv4=IPv4Address("9.9.9.9"), mac=MACAddress("00:00:00:00:00:01"), node=NodeID("n1"))
    e.merge_from(e3)
    _test_assert(e.node == NodeID("n1"), "merge_from")
    c = e.copy()
    _test_assert(c.ipv4 == e.ipv4 and c is not e, "copy")


def test_ip_entry_is_local() -> None:
    """IPEntry.is_local: True when scope == RT_SCOPE_HOST."""
    e = IPEntry(
        ipv4=IPv4Address("127.0.0.1"),
        mac=MACAddress("aa:bb:cc:dd:ee:ff"),
        scope=RT_SCOPE_HOST,
    )
    _test_assert(e.is_local() is True, "scope host")
    e2 = IPEntry(ipv4=IPv4Address("10.0.0.1"), mac=MACAddress("aa:bb:cc:dd:ee:ff"), scope=0)
    _test_assert(e2.is_local() is False, "scope global")
    e3 = IPEntry(ipv4=IPv4Address("10.0.0.2"), mac=MACAddress("aa:bb:cc:dd:ee:ff"))
    _test_assert(e3.is_local() is False, "scope None")


def test_ip_entry_to_mesh_dict() -> None:
    """IPEntry.to_mesh_dict: None if local (scope) or is_host_local callback True."""
    local = IPEntry(
        ipv4=IPv4Address("127.0.0.1"),
        mac=MACAddress("aa:bb:cc:dd:ee:ff"),
        scope=RT_SCOPE_HOST,
    )
    _test_assert(local.to_mesh_dict() is None, "local not exported")
    global_e = IPEntry(
        ipv4=IPv4Address("10.0.0.1"),
        mac=MACAddress("aa:bb:cc:dd:ee:ff"),
        bridge=BridgeName("vmbr0"),
        last_seen=100.0,
    )
    out = global_e.to_mesh_dict()
    _test_assert(out is not None and out.get("ipv4") == "10.0.0.1" and out.get("mac") == "aa:bb:cc:dd:ee:ff", "to_mesh_dict")


def test_ip_entry_to_mesh_dict_foreign_type_not_exported() -> None:
    """Foreign entries are tracked locally but never meshed."""
    entry = IPEntry(
        ipv4=IPv4Address("192.168.12.32"),
        mac=MACAddress("bc:24:11:d7:ad:5a"),
        bridge=BridgeName("vmbr0"),
        type="foreign",
        last_seen=100.0,
    )
    _test_assert(entry.to_mesh_dict() is None, "foreign not exported to mesh")


def test_ip_entry_to_mesh_dict_is_host_local_callback() -> None:
    """to_mesh_dict(is_host_local): when callback returns True, not exported; else exported."""
    # No scope set (e.g. snooped entry); callback says host-local -> not exported
    ip_host = IPv4Address("192.168.12.1")
    entry_no_scope = IPEntry(
        ipv4=ip_host,
        mac=MACAddress("f6:87:a0:ad:bb:4a"),
        bridge=BridgeName("vmbr0"),
        last_seen=100.0,
    )
    _test_assert(entry_no_scope.to_mesh_dict() is not None, "no callback -> exported")
    _test_assert(
        entry_no_scope.to_mesh_dict(is_host_local=lambda ip: ip == ip_host) is None,
        "is_host_local True -> not exported",
    )
    _test_assert(
        entry_no_scope.to_mesh_dict(is_host_local=lambda ip: False) is not None,
        "is_host_local False -> exported",
    )


def test_ip_entry_from_dict_legacy_ip() -> None:
    """IPEntry.from_dict handles legacy 'ip' key."""
    e = IPEntry.from_dict({"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff"})
    _test_assert(e.ipv4 == IPv4Address("10.0.0.1"), "legacy ip")


def test_ip_entry_from_dict_requires_mac() -> None:
    """IPEntry.from_dict raises without mac."""
    try:
        IPEntry.from_dict({"ipv4": "10.0.0.1"})
        _test_assert(False, "should raise")
    except ValueError:
        pass


def test_ip_entry_last_activity() -> None:
    """IPEntry.last_activity: max of last_seen and last_received."""
    e = IPEntry(
        ipv4=IPv4Address("1.2.3.4"),
        mac=MACAddress("aa:bb:cc:dd:ee:ff"),
        last_seen=10.0,
        last_received=20.0,
    )
    _test_assert(e.last_activity() == 20.0, "last_received wins")
    e2 = IPEntry(ipv4=IPv4Address("1.2.3.4"), mac=MACAddress("aa:bb:cc:dd:ee:ff"), last_seen=30.0)
    _test_assert(e2.last_activity() == 30.0, "last_seen only")


def test_ip_entry_is_owner() -> None:
    """IPEntry.is_owner: active and node match."""
    e = IPEntry(
        ipv4=IPv4Address("1.2.3.4"),
        mac=MACAddress("aa:bb:cc:dd:ee:ff"),
        node=NodeID("n1"),
        last_seen=100.0,
    )
    _test_assert(e.is_owner(150.0, 60.0, NodeID("n1")) is True, "owner active")
    _test_assert(e.is_owner(150.0, 60.0, NodeID("n2")) is False, "owner mismatch")
    _test_assert(e.is_owner(200.0, 60.0, NodeID("n1")) is False, "owner stale")
    _test_assert(e.is_owner(150.0, 60.0, None) is False, "owner none node")
    e.expired = 120.0
    _test_assert(e.is_owner(150.0, 60.0, NodeID("n1")) is False, "owner expired")


def test_ip_entry_can_owner_change() -> None:
    """IPEntry.can_owner_change uses last_seen takeover window."""
    e = IPEntry(
        ipv4=IPv4Address("1.2.3.4"),
        mac=MACAddress("aa:bb:cc:dd:ee:ff"),
        node=NodeID("n2"),
        last_seen=100.0,
    )
    _test_assert(e.can_owner_change(150.0, NodeID("n1"), 60.0) is False, "owner fresh")
    _test_assert(e.can_owner_change(170.0, NodeID("n1"), 60.0) is True, "owner stale")
    e.expired = 120.0
    _test_assert(e.can_owner_change(150.0, NodeID("n1"), 60.0) is True, "owner expired")
    _test_assert(e.can_owner_change(150.0, None, 60.0) is False, "owner none node")


def test_ip_entry_change_owner_guard() -> None:
    """node can only change via change_owner."""
    e = IPEntry(
        ipv4=IPv4Address("1.2.3.4"),
        mac=MACAddress("aa:bb:cc:dd:ee:ff"),
        node=NodeID("n1"),
        last_seen=100.0,
    )
    try:
        e.node = NodeID("n2")
        _test_assert(False, "direct owner change should fail")
    except AttributeError:
        pass
    e.change_owner(NodeID("n2"))
    _test_assert(e.node == NodeID("n2"), "change_owner works")


def test_ip_entry_to_dict_excludes_internal_fields() -> None:
    """to_dict must not persist internal owner-guard state."""
    e = IPEntry(
        ipv4=IPv4Address("10.0.0.1"),
        mac=MACAddress("aa:bb:cc:dd:ee:ff"),
        node=NodeID("n1"),
        last_seen=100.0,
    )
    d = e.to_dict()
    _test_assert("_owner_mutation_allowed" not in d, "internal field not serialized")


def test_ip_entry_from_dict_with_node_uses_change_owner() -> None:
    """from_dict loads node through change_owner path."""
    e = IPEntry.from_dict(
        {
            "ipv4": "10.0.0.1",
            "mac": "aa:bb:cc:dd:ee:ff",
            "node": "n1",
            "last_seen": 100.0,
        }
    )
    _test_assert(e.node == NodeID("n1"), "from_dict node loaded")


def test_ip_entry_from_dict_strips_underscore_keys() -> None:
    """Legacy state may contain internal keys; from_dict ignores them."""
    e = IPEntry.from_dict(
        {
            "ipv4": "10.0.0.2",
            "mac": "aa:bb:cc:dd:ee:ff",
            "_owner_mutation_allowed": True,
            "_bogus": "x",
            "node": "n2",
            "last_seen": 50.0,
        }
    )
    _test_assert(
        not object.__getattribute__(e, "_owner_mutation_allowed"),
        "internal flag not loaded from dict",
    )
    _test_assert(e.node == NodeID("n2"), "node still applied")


def test_ip_entry_merge_from_skips_internal_fields() -> None:
    """merge_from must not copy internal dataclass fields."""
    a = IPEntry(
        ipv4=IPv4Address("10.0.0.3"),
        mac=MACAddress("aa:bb:cc:dd:ee:01"),
        node=NodeID("keep"),
        last_seen=10.0,
    )
    b = IPEntry(
        ipv4=IPv4Address("10.0.0.3"),
        mac=MACAddress("aa:bb:cc:dd:ee:02"),
        node=NodeID("other"),
        last_seen=20.0,
    )
    object.__setattr__(b, "_owner_mutation_allowed", True)
    a.merge_from(b)
    _test_assert(a.node == NodeID("other"), "merge updated node")
    _test_assert(
        not object.__getattribute__(a, "_owner_mutation_allowed"),
        "merge does not copy internal flag",
    )


def test_ip_entry_copy_preserves_node_no_internal_in_to_dict() -> None:
    """copy() is independent; to_dict stays clean."""
    e = IPEntry(
        ipv4=IPv4Address("10.0.0.4"),
        mac=MACAddress("aa:bb:cc:dd:ee:03"),
        node=NodeID("n1"),
        last_seen=100.0,
    )
    c = e.copy()
    _test_assert(c is not e and c.node == e.node, "copy preserves node")
    _test_assert("_owner_mutation_allowed" not in c.to_dict(), "copy to_dict clean")


def test_ip_entry_store_update_ignores_underscore_kwargs() -> None:
    """Store update cannot set internal fields via kwargs."""
    store = IPEntryStore()
    ip = IPv4Address("10.0.0.5")
    br = BridgeName("vmbr0")
    e = IPEntry(ipv4=ip, mac=MACAddress("aa:bb:cc:dd:ee:04"), bridge=br, last_seen=1.0, node=NodeID("n1"))
    store.set(e)
    key = _entry_key(e)
    store.update(key, _owner_mutation_allowed=True)
    inner = store.get(ip, br, None)
    _test_assert(inner is not None, "get after update")
    _test_assert(
        not object.__getattribute__(inner, "_owner_mutation_allowed"),
        "underscore kw ignored",
    )


def test_instance_info() -> None:
    """InstanceInfo: to_dict."""
    info = InstanceInfo(
        vmid=VMID("100"),
        type="qemu",
        bridge=BridgeName("vmbr0"),
        mac=MACAddress("aa:bb:cc:dd:ee:ff"),
    )
    d = info.to_dict()
    _test_assert(d["vmid"] == "100" and d["bridge"] == "vmbr0", "to_dict")


def test_net_interface() -> None:
    """NetInterface: dataclass fields."""
    ni = NetInterface(
        bridge=BridgeName("vmbr0"),
        mac=MACAddress("aa:bb:cc:dd:ee:ff"),
        vlan=10,
    )
    _test_assert(ni.bridge == "vmbr0" and ni.vlan == 10, "fields")


def test_ip_entry_store() -> None:
    """IPEntryStore: get, set, update, get_active, to_dict, load_from_dict."""
    store = IPEntryStore()
    ip = IPv4Address("1.2.3.4")
    br = BridgeName("vmbr0")
    mac = MACAddress("aa:bb:cc:dd:ee:ff")
    _test_assert(store.get(ip, br, None) is None, "get missing")
    e = IPEntry(
        ipv4=ip,
        mac=mac,
        bridge=br,
        last_seen=time.time(),
    )
    store.set(e)
    _test_assert(store.get(ip, br, None) is not None and store.get(ip, br, None).ipv4 == ip, "set/get")
    key = _entry_key(e)
    store.update(key, node=NodeID("n1"))
    _test_assert(store.get(ip, br, None).node == NodeID("n1"), "update")
    active = store.get_active(time.time(), 300.0)
    _test_assert(key in active, "get_active")
    d = store.to_dict()
    store2 = IPEntryStore()
    store2.load_from_dict(d)
    _test_assert(store2.get(ip, br, None) is not None, "load_from_dict")


def test_ip_entry_store_get_bridge_filter() -> None:
    """IPEntryStore.get with bridge filter."""
    store = IPEntryStore()
    ip = IPv4Address("10.0.0.1")
    e = IPEntry(
        ipv4=ip,
        mac=MACAddress("aa:bb:cc:dd:ee:01"),
        bridge=BridgeName("vmbr0"),
        last_seen=1.0,
    )
    store.set(e)
    _test_assert(store.get(ip, BridgeName("vmbr0"), None) is not None, "bridge match")
    _test_assert(store.get(ip, BridgeName("vmbr1"), None) is None, "bridge no match")
    _test_assert(store.get(ip, BridgeName("vmbr0"), None) is not None, "get with bridge")


def test_iter_ipentries_from_dict_parses_keys_and_entries() -> None:
    """iter_ipentries_from_dict parses both composite and legacy keys."""
    ip = IPv4Address("10.0.0.5")
    br = BridgeName("vmbr0")
    key_str = f"{ip}|{br}|42"
    data = {
        key_str: {"ipv4": str(ip), "mac": "aa:bb:cc:dd:ee:ff", "bridge": str(br), "vlan": 42},
        str(IPv4Address("10.0.0.6")): {"ipv4": "10.0.0.6", "mac": "aa:bb:cc:dd:ee:00"},
        "invalid": {"ipv4": "not-an-ip", "mac": "aa:bb:cc:dd:ee:11"},
    }
    pairs = iter_ipentries_from_dict(data)
    keys = {k for k, _ in pairs}
    _test_assert(
        (ip, br, 42) in keys and (IPv4Address("10.0.0.6"), None, None) in keys,
        "both composite and legacy keys parsed",
    )


def test_ip_entry_store_get_or_create() -> None:
    """IPEntryStore.get_or_create: create then return same."""
    store = IPEntryStore()
    ip = IPv4Address("1.2.3.4")
    mac = MACAddress("aa:bb:cc:dd:ee:ff")
    e = store.get_or_create(ip, mac)
    _test_assert(e is not None and store.get(ip, None, None) is not None, "create")
    e.change_owner(NodeID("n1"))
    e2 = store.get_or_create(ip, mac)
    _test_assert(e2.node == NodeID("n1"), "existing returned")


def test_ip_entry_store_get_active_node_filter() -> None:
    """IPEntryStore.get_active with node_id filter."""
    store = IPEntryStore()
    now = time.time()
    store.set(
        IPEntry(
            ipv4=IPv4Address("1.2.3.4"),
            mac=MACAddress("aa:bb:cc:dd:ee:01"),
            bridge=BridgeName("vmbr0"),
            last_seen=now,
            node=NodeID("n1"),
        )
    )
    store.set(
        IPEntry(
            ipv4=IPv4Address("5.6.7.8"),
            mac=MACAddress("aa:bb:cc:dd:ee:02"),
            bridge=BridgeName("vmbr0"),
            last_seen=now,
            node=NodeID("n2"),
        )
    )
    active_n1 = store.get_active(now, 300.0, node_id=NodeID("n1"))
    key1 = (IPv4Address("1.2.3.4"), BridgeName("vmbr0"), None)
    _test_assert(len(active_n1) == 1 and key1 in active_n1, "node filter")
    active_all = store.get_active(now, 300.0)
    _test_assert(len(active_all) == 2, "no filter")


def test_ip_entry_store_get_entries_for_bridge_ip() -> None:
    """IPEntryStore.get_entries_for_bridge_ip returns all (key, entry) for (ip, bridge)."""
    store = IPEntryStore()
    ip = IPv4Address("192.168.1.1")
    br = BridgeName("vmbr0")
    _test_assert(store.get_entries_for_bridge_ip(ip, br) == [], "empty")
    store.set(IPEntry(ipv4=ip, mac=MACAddress("aa:bb:cc:dd:ee:01"), bridge=br, vlan=10, last_seen=1.0))
    store.set(IPEntry(ipv4=ip, mac=MACAddress("aa:bb:cc:dd:ee:02"), bridge=br, vlan=20, last_seen=2.0))
    lst = store.get_entries_for_bridge_ip(ip, br)
    _test_assert(len(lst) == 2, "two entries")
    vlans = {k[2] for k, _ in lst}
    _test_assert(vlans == {10, 20}, "both vlans")


def test_ip_entry_store_get_any_active_for_bridge_ip() -> None:
    """IPEntryStore.get_any_active_for_bridge_ip: any active entry; prefer with node."""
    store = IPEntryStore()
    ip = IPv4Address("192.168.1.1")
    br = BridgeName("vmbr0")
    now = 1000.0
    ttl = 100.0
    _test_assert(store.get_any_active_for_bridge_ip(ip, br, now, ttl) is None, "empty")
    store.set(IPEntry(ipv4=ip, mac=MACAddress("aa:bb:cc:dd:ee:01"), bridge=br, vlan=10, last_seen=now - 50.0))
    e = store.get_any_active_for_bridge_ip(ip, br, now, ttl)
    _test_assert(e is not None and e.vlan == 10, "one active")
    store.set(IPEntry(ipv4=ip, mac=MACAddress("aa:bb:cc:dd:ee:02"), bridge=br, vlan=20, last_seen=now - 30.0, node=NodeID("n2")))
    e2 = store.get_any_active_for_bridge_ip(ip, br, now, ttl)
    _test_assert(e2 is not None and e2.node == NodeID("n2"), "prefer with node")


def test_ip_entry_store_keys_and_contains() -> None:
    """IPEntryStore.keys and __contains__."""
    store = IPEntryStore()
    ip = IPv4Address("1.2.3.4")
    br = BridgeName("vmbr0")
    key = (ip, br, None)
    _test_assert(key not in store and store.keys() == [], "empty")
    e = IPEntry(
        ipv4=ip,
        mac=MACAddress("aa:bb:cc:dd:ee:ff"),
        bridge=br,
        last_seen=time.time(),
    )
    store.set(e)
    _test_assert(key in store and len(store.keys()) == 1, "after set")


def test_instance_store() -> None:
    """InstanceStore: set, get, items, to_dict, clear."""
    store = InstanceStore()
    mac = MACAddress("aa:bb:cc:dd:ee:ff")
    info = InstanceInfo(vmid=VMID("100"), type="qemu", bridge=BridgeName("vmbr0"), mac=mac)
    store.set(mac, info)
    _test_assert(store.get(mac).vmid == "100", "set/get")
    _test_assert(len(store.items()) == 1, "items")
    d = store.to_dict()
    _test_assert(mac in d and d[mac]["vmid"] == "100", "to_dict")
    store.clear()
    _test_assert(len(store) == 0, "clear")


def test_instance_info_to_dict_full() -> None:
    """InstanceInfo.to_dict: vlan, config_ip, tags."""
    info = InstanceInfo(
        vmid=VMID("100"),
        type="lxc",
        bridge=BridgeName("vmbr0"),
        mac=MACAddress("aa:bb:cc:dd:ee:ff"),
        vlan=10,
        ip=IPv4Address("192.168.1.1"),
        tags=["a", "b"],
    )
    d = info.to_dict()
    _test_assert(
        d.get("vlan") == 10 and d.get("config_ip") == "192.168.1.1" and d.get("tags") == ["a", "b"],
        "full to_dict",
    )


def test_instance_store_update_all_and_contains() -> None:
    """InstanceStore.update_all, __contains__, __len__."""
    store = InstanceStore()
    mac = MACAddress("aa:bb:cc:dd:ee:ff")
    info = InstanceInfo(vmid=VMID("1"), type="qemu", bridge=BridgeName("vmbr0"), mac=mac)
    store.set(mac, info)
    _test_assert(mac in store and len(store) == 1, "contains and len")
    new_info = InstanceInfo(
        vmid=VMID("2"),
        type="qemu",
        bridge=BridgeName("vmbr0"),
        mac=MACAddress("00:00:00:00:00:01"),
    )
    store.update_all({MACAddress("00:00:00:00:00:01"): new_info})
    _test_assert(
        mac not in store and store.get(MACAddress("00:00:00:00:00:01")).vmid == "2",
        "update_all",
    )


def test_ip_entry_store_migrate_passive_bridge_keys() -> None:
    """migrate_passive_bridge_keys moves passive keys to active bridge."""
    store = IPEntryStore()
    ip = IPv4Address("10.0.0.1")
    mac = MACAddress("aa:bb:cc:dd:ee:01")
    store.set(IPEntry(ipv4=ip, mac=mac, bridge=BridgeName("vmbr00"), last_seen=1.0, node=NodeID("n1")))
    n = store.migrate_passive_bridge_keys(BridgeName("vmbr0"), frozenset({"vmbr00"}))
    _test_assert(n == 1, "one row moved")
    _test_assert(store.get(ip, BridgeName("vmbr0"), None) is not None, "now under vmbr0")
    _test_assert(store.get(ip, BridgeName("vmbr00"), None) is None, "old key gone")
