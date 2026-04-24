"""Tests for src.metrics."""
from __future__ import annotations

from types import SimpleNamespace

from src.config import Config
from src.metrics import ArbiterMetricsCollector
from src.test import _test_assert


class _FakeEntries:
    """Small fake entry store for metrics tests."""

    def __init__(self, items_list: list[tuple[tuple[object, object, object], object]]) -> None:
        self._items = items_list

    def items(self) -> list[tuple[tuple[object, object, object], object]]:
        """Return fake items."""
        return list(self._items)


def _build_fake_core() -> object:
    """Build fake core with metrics fields."""
    entry = SimpleNamespace(
        ipv4="10.1.1.1",
        mac="aa:bb:cc:dd:ee:01",
        bridge="vmbr0",
        vlan=10,
        node="10.0.0.2",
        snoop_origin=["arp"],
        expired=None,
        last_activity=lambda: 100.0,
    )
    monitor_instances = [
        ("aa:bb:cc:dd:ee:11", SimpleNamespace(type="qemu")),
        ("aa:bb:cc:dd:ee:12", SimpleNamespace(type="lxc")),
    ]
    fake = SimpleNamespace(
        _watcher=SimpleNamespace(
            db_ok=lambda: True,
            last_db_success_time=lambda: 123.0,
            db_poll_counts=lambda: {"ok": 2, "fail": 1, "skipped": 3},
        ),
        _mesh=SimpleNamespace(
            get_node_last_seen=lambda: {"10.0.0.2": 100.0},
            get_last_recv_any=lambda: 110.0,
            get_mesh_counters=lambda: {"rx": 5, "tx": 6, "rx_invalid": 1},
            get_migration_counters=lambda: {"remote_confirmed": 2, "remote_refused": 1},
        ),
        _of=SimpleNamespace(
            arp_responder_flow_count=lambda: 2,
            arp_responder_flows_by_bridge=lambda: {"vmbr0": 2},
            arp_responder_sync_counts=lambda: {"ok": 3, "error": 1, "added": 4, "removed": 2},
        ),
        _peer_tracker=SimpleNamespace(get_active_peers_with_ttl=lambda: [("m", "ip", 1.0)]),
        _monitor=SimpleNamespace(
            instances=SimpleNamespace(items=lambda: monitor_instances),
            get_last_snoop_time=lambda: 115.0,
            arp_counters=lambda: {
                "reply_attempt": 1,
                "reply_sent": 1,
                "reply_failed": 0,
                "reply_skipped": 2,
                "reinject_sent": 3,
                "reinject_failed": 1,
            },
            migration_counters=lambda: {"local_refused": 2, "local_confirmed": 4},
        ),
        _entries=_FakeEntries([(("10.1.1.1", "vmbr0", 10), entry)]),
        _start_time=100.0,
        _node_id="10.0.0.1",
        runtime_counters=lambda: {"owner_changes": 1, "entries_expired": 2, "entries_cleaned": 3, "network_warnings": 4},
        entry_counts=lambda: {"total": 1, "active": 1, "inactive": 0},
        last_loop_tick=lambda: 120.0,
    )
    return fake


def test_metrics_collector_base_names() -> None:
    """Collector emits expected base metric family names."""
    try:
        import prometheus_client.core  # noqa: F401
    except ModuleNotFoundError:
        _test_assert(True, "prometheus_client not installed")
        return
    cfg = Config(bridges=["vmbr0"], mesh_ttl=300.0)
    c = ArbiterMetricsCollector(_build_fake_core(), cfg, extra=False)
    names = {m.name for m in c.collect()}
    _test_assert("ovs_vm_arbiter_mesh_sign_enabled" in names, "mesh sign gauge exists")
    _test_assert("ovs_vm_arbiter_entries_active_total" in names, "active entries gauge exists")
    _test_assert("ovs_vm_arbiter_db_polls" in names, "db polls counter exists")
    _test_assert("ovs_vm_arbiter_mesh_peer_ttl_seconds" in names, "mesh peer ttl gauge exists")
    _test_assert("ovs_vm_arbiter_arp_reply_sent" in names, "arp reply counter exists")
    _test_assert("ovs_vm_arbiter_ip_migrations" in names, "ip migrations counter exists")
    _test_assert("ovs_vm_arbiter_network_warnings_total" in names, "network warnings gauge exists")
    _test_assert("ovs_vm_arbiter_migration_refused" in names, "migration refused counter exists")
    _test_assert("ovs_vm_arbiter_remote_migration_confirmed" not in names, "remote metrics disabled by default")


def test_metrics_collector_remote_metrics_enabled() -> None:
    """Remote migration metrics are emitted only when enabled."""
    try:
        import prometheus_client.core  # noqa: F401
    except ModuleNotFoundError:
        _test_assert(True, "prometheus_client not installed")
        return
    cfg = Config(bridges=["vmbr0"], mesh_ttl=300.0, verify_remote_migration=True)
    c = ArbiterMetricsCollector(_build_fake_core(), cfg, extra=False)
    names = {m.name for m in c.collect()}
    _test_assert("ovs_vm_arbiter_remote_migration_confirmed" in names, "remote confirmed emitted")
    _test_assert("ovs_vm_arbiter_remote_migration_refused" in names, "remote refused emitted")


def test_metrics_collector_extra_mapping() -> None:
    """Collector emits mapping metrics only in extra mode."""
    try:
        import prometheus_client.core  # noqa: F401
    except ModuleNotFoundError:
        _test_assert(True, "prometheus_client not installed")
        return
    cfg = Config(bridges=["vmbr0"], mesh_ttl=300.0)
    c = ArbiterMetricsCollector(_build_fake_core(), cfg, extra=True)
    names = {m.name for m in c.collect()}
    _test_assert("ovs_vm_arbiter_entry_mapping_info" in names, "mapping info exists")
    _test_assert("ovs_vm_arbiter_entry_mapping_ttl_seconds" in names, "mapping ttl exists")
