"""Tests for src.core."""
import os
import io
import logging
import time
from unittest.mock import MagicMock, patch
from src.types import MACAddress, IPv4Address, BridgeName, NodeID, OFPort
from src.models import IPEntry
from src.config import Config
from src.core import ArbiterCore
from src.test import _test_assert


def test_get_responder_learning_port() -> None:
    """_get_responder_learning_port returns OFPort when entry has node in OVS map; else None."""
    import tempfile
    log = logging.getLogger("test")
    with tempfile.TemporaryDirectory() as tmp:
        cfg = Config(
            state_dir=tmp,
            db_path=os.path.join(tmp, "x.db"),
            bridges=["vmbr0"],
            mesh_ttl=300.0,
        )
        core = ArbiterCore(cfg, log)
        br = BridgeName("vmbr0")
        ip = IPv4Address("192.168.1.10")
        mac = MACAddress("aa:bb:cc:dd:ee:01")
        node = NodeID("10.0.0.2")
        now = time.time()
        core._entries.set(
            IPEntry(ipv4=ip, mac=mac, bridge=br, node=node, last_seen=now)
        )
        # No OVS map: returns None
        with patch.object(core._ovs, "get_bridge_node_to_ofport", return_value={}):
            _test_assert(core._get_responder_learning_port(br, ip) is None, "no map -> None")
        # OVS map has node -> (OFPort, name): returns port
        with patch.object(
            core._ovs,
            "get_bridge_node_to_ofport",
            return_value={node: (OFPort("5"), "vxlan0")},
        ):
            port = core._get_responder_learning_port(br, ip)
            _test_assert(port == OFPort("5"), "node in map -> OFPort")
        # Multiple entries for same (bridge, ip) where only one has node:
        # still resolve using entry that has node set.
        core._entries.set(
            IPEntry(
                ipv4=ip,
                mac=MACAddress("aa:bb:cc:dd:ee:02"),
                bridge=br,
                vlan=10,
                last_seen=now,
            )
        )
        with patch.object(
            core._ovs,
            "get_bridge_node_to_ofport",
            return_value={node: (OFPort("5"), "vxlan0")},
        ):
            port2 = core._get_responder_learning_port(br, ip)
            _test_assert(port2 == OFPort("5"), "prefers entry with node when multiple entries exist")
        # Wrong (br, ip): no matching entry -> None (map has other node)
        other_ip = IPv4Address("192.168.1.99")
        with patch.object(
            core._ovs,
            "get_bridge_node_to_ofport",
            return_value={NodeID("other"): (OFPort("5"), "vxlan0")},
        ):
            _test_assert(core._get_responder_learning_port(br, other_ip) is None, "no entry for ip -> None")


def test_arbiter_core_expire_entries() -> None:
    """ArbiterCore._expire_entries marks old entries expired."""
    import tempfile
    log = logging.getLogger("test")
    with tempfile.TemporaryDirectory() as tmp:
        cfg = Config(state_dir=tmp, db_path=os.path.join(tmp, "nonexistent.db"), bridges=["vmbr0"], mesh_ttl=1.0, expiry_grace_sec=0)
        core = ArbiterCore(cfg, log)
        ip = IPv4Address("1.2.3.4")
        core._entries.set(IPEntry(ipv4=ip, mac=MACAddress("aa:bb:cc:dd:ee:ff"), bridge=BridgeName("vmbr0"), last_seen=50.0))
        core._start_time = 0.0
        now = 100.0
        core._expire_entries(now)
        e = core._entries.get(ip, BridgeName("vmbr0"), None)
        _test_assert(e is not None and e.expired is not None, "expired set")


def test_expiry_when_no_snoop() -> None:
    """IP not seen for mesh_ttl is marked expired (negative: no traffic -> expired)."""
    import tempfile
    log = logging.getLogger("test")
    with tempfile.TemporaryDirectory() as tmp:
        cfg = Config(
            state_dir=tmp,
            db_path=os.path.join(tmp, "x.db"),
            bridges=["vmbr0"],
            mesh_ttl=10.0,
            expiry_grace_sec=0,
        )
        core = ArbiterCore(cfg, log)
        ip = IPv4Address("192.168.12.1")
        br = BridgeName("vmbr0")
        core._entries.set(
            IPEntry(ipv4=ip, mac=MACAddress("82:51:f3:21:c9:47"), bridge=br, last_seen=100.0, node=NodeID("self"))
        )
        core._start_time = 0.0
        now = 111.0  # 11s since last_seen > mesh_ttl 10
        core._expire_entries(now)
        e = core._entries.get(ip, br, None)
        _test_assert(e is not None and e.expired is not None, "no snoop -> expired")


def test_check_snoop_silence() -> None:
    """Warn after warn_after; restart only at restart_sec; disabled when both off."""
    import tempfile
    log = logging.getLogger("test")
    with tempfile.TemporaryDirectory() as tmp:
        cfg = Config(
            state_dir=tmp,
            db_path=os.path.join(tmp, "x.db"),
            bridges=["vmbr0"],
            snoop_silence_warn_after_sec=30.0,
            snoop_silence_warn_interval_sec=30.0,
            snoop_silence_restart_sec=200.0,
        )
        core = ArbiterCore(cfg, log)
        core._monitor._last_snoop_time = 0.0
        now = 100.0
        with patch.object(core.log, "warning") as warn:
            with patch.object(core.log, "error"):
                core._check_snoop_silence(now)
        _test_assert(warn.call_count == 0, "last_snoop_time 0 -> no warn")
        core._monitor._last_snoop_time = 10.0  # 90s silence >= 30
        with patch.object(core.log, "warning") as warn2:
            with patch.object(core.log, "error"):
                core._check_snoop_silence(now)
        _test_assert(warn2.call_count == 1, "silence past warn_after -> WARNING")
        with patch.object(core.log, "warning"):
            with patch.object(core.log, "error") as err:
                with patch("sys.exit") as mock_exit:
                    core._check_snoop_silence(220.0)  # last=10 -> 210s silence >= restart 200
        _test_assert(err.call_count == 1, "restart threshold -> ERROR")
        _test_assert(mock_exit.call_count == 1 and mock_exit.call_args[0][0] == 1, "exit(1)")
        cfg.snoop_silence_warn_after_sec = 0
        cfg.snoop_silence_restart_sec = 0
        with patch.object(core.log, "warning"):
            with patch.object(core.log, "error") as err3:
                core._check_snoop_silence(999.0)
        _test_assert(err3.call_count == 0, "both 0 -> no ERROR")


def test_migration_invalidation_enqueue_is_async() -> None:
    """Migration callback only enqueues job."""
    import tempfile
    log = logging.getLogger("test")
    with tempfile.TemporaryDirectory() as tmp:
        cfg = Config(state_dir=tmp, db_path=os.path.join(tmp, "x.db"), bridges=["vmbr0"])
        core = ArbiterCore(cfg, log)
        ip = IPv4Address("10.0.0.10")
        br = BridgeName("vmbr0")
        loop_mock = MagicMock()
        core._event_loop = loop_mock
        with patch.object(core, "_enqueue_migration_invalidation") as _enqueue:
            core._on_migration_invalidate_fdb(ip, br, None, NodeID("n1"), NodeID("n2"))
        loop_mock.call_soon_threadsafe.assert_called_once()
        _enqueue.assert_not_called()


def test_migration_invalidates_fdb_disabled_skips_enqueue() -> None:
    """Disabled migration invalidation skips enqueue."""
    import tempfile
    log = logging.getLogger("test")
    with tempfile.TemporaryDirectory() as tmp:
        cfg = Config(
            state_dir=tmp,
            db_path=os.path.join(tmp, "x.db"),
            bridges=["vmbr0"],
            migration_invalidates_fdb=False,
        )
        core = ArbiterCore(cfg, log)
        core._event_loop = MagicMock()
        with patch.object(core, "_enqueue_migration_invalidation") as _enqueue:
            core._on_migration_invalidate_fdb(
                IPv4Address("10.0.0.12"),
                BridgeName("vmbr0"),
                None,
                NodeID("n1"),
                NodeID("n2"),
            )
        _test_assert(core._event_loop.call_soon_threadsafe.call_count == 0, "not scheduled")  # type: ignore[union-attr]
        _enqueue.assert_not_called()


def test_migration_invalidation_job_invalidates_fdb_and_kernel_arp() -> None:
    """Migration invalidation job invalidates FDB and kernel ARP."""
    import tempfile
    log = logging.getLogger("test")
    with tempfile.TemporaryDirectory() as tmp:
        cfg = Config(state_dir=tmp, db_path=os.path.join(tmp, "x.db"), bridges=["vmbr0"])
        core = ArbiterCore(cfg, log)
        ip = IPv4Address("10.0.0.11")
        br = BridgeName("vmbr0")
        mac = MACAddress("aa:bb:cc:dd:ee:11")
        core._entries.set(IPEntry(ipv4=ip, mac=mac, bridge=br, node=NodeID("n2"), last_seen=time.time()))
        core._ovs.invalidate_local_fdb_mac = MagicMock(return_value=True)  # type: ignore[method-assign]
        core._netlink.invalidate_kernel_arp = MagicMock(return_value=True)  # type: ignore[method-assign]
        core._process_migration_invalidation(ip, br, None, NodeID("n1"), NodeID("n2"))
        core._ovs.invalidate_local_fdb_mac.assert_called_once_with(br, mac, vlan=None)  # type: ignore[attr-defined]
        core._netlink.invalidate_kernel_arp.assert_called_once_with(ip, br, mac=mac)  # type: ignore[attr-defined]


def test_ping_neighbours_missing_cap_net_raw_disables_thread() -> None:
    """Missing raw socket capability logs warning and does not start ping thread."""
    import tempfile
    log = MagicMock(spec=logging.Logger)
    with tempfile.TemporaryDirectory() as tmp:
        cfg = Config(
            state_dir=tmp,
            db_path=os.path.join(tmp, "x.db"),
            bridges=["vmbr0"],
            ping_neighbours_interval=3.0,
        )
        core = ArbiterCore(cfg, log)
        with patch("src.core.raw_icmp_socket_ok", return_value=False):
            core._start_ping_thread_if_enabled()
        _test_assert(core._ping_thread is None, "ping thread disabled")
        _test_assert(log.warning.call_count == 1, "warning logged once")


def test_sync_arp_responder_flows_once_calls_of_sync() -> None:
    """_sync_arp_responder_flows_once injects, computes desired, syncs OF."""
    import tempfile
    log = logging.getLogger("test")
    with tempfile.TemporaryDirectory() as tmp:
        cfg = Config(
            state_dir=tmp,
            db_path=os.path.join(tmp, "x.db"),
            bridges=["vmbr0"],
            mesh_ttl=300.0,
            arp_responder_learning=True,
        )
        core = ArbiterCore(cfg, log)
        with patch.object(core, "_inject_local_iface_entries") as inj:
            with patch.object(core, "get_desired_responders", return_value=set()) as gd:
                with patch.object(core._of, "sync_arp_responder_flows") as sync:
                    core._sync_arp_responder_flows_once()
        _test_assert(inj.call_count == 1, "inject called")
        _test_assert(gd.call_count == 1, "get_desired called")
        _test_assert(sync.call_count == 1, "sync called")


def test_check_proxy_arp_on_monitored_bridges() -> None:
    """Log error when monitored bridge has proxy_arp enabled."""
    import tempfile
    log = logging.getLogger("test_proxy_arp")
    with tempfile.TemporaryDirectory() as tmp:
        cfg = Config(
            state_dir=tmp,
            db_path=os.path.join(tmp, "x.db"),
            bridges=["vmbr0", "vmbr1"],
        )
        core = ArbiterCore(cfg, log)

        def _fake_open(path: str, mode: str = "r", encoding: str = "utf-8"):  # type: ignore[override]
            if path.endswith("/vmbr0/proxy_arp"):
                return io.StringIO("1\n")
            if path.endswith("/vmbr1/proxy_arp"):
                return io.StringIO("0\n")
            raise OSError("missing")

        with patch("src.core.open", side_effect=_fake_open):
            with patch.object(core.log, "error") as err:
                core._check_proxy_arp_on_monitored_bridges()
        _test_assert(err.call_count == 1, "error once for proxy_arp=1 bridge")
        _test_assert("vmbr0" in str(err.call_args[0]), "error includes bridge name")
        _test_assert(core.runtime_counters().get("network_warnings", 0) == 1, "network warning counter incremented")


def test_migration_invalidation_worker_executor_failure_logs_warning() -> None:
    """Worker logs warning when _process_migration_invalidation raises."""
    import asyncio
    import tempfile
    log = logging.getLogger("test_mig")
    with tempfile.TemporaryDirectory() as tmp:
        cfg = Config(
            state_dir=tmp,
            db_path=os.path.join(tmp, "x.db"),
            bridges=["vmbr0"],
            mesh_ttl=300.0,
        )
        core = ArbiterCore(cfg, log)
        queue: asyncio.Queue = asyncio.Queue()
        core._migration_invalidation_queue = queue

        async def run() -> None:
            await queue.put((IPv4Address("1.2.3.4"), BridgeName("vmbr0"), None, None, None))
            with patch.object(core, "_process_migration_invalidation", side_effect=RuntimeError("x")):
                with patch.object(core.log, "warning") as w:
                    task = asyncio.create_task(core._migration_invalidation_worker_loop())
                    await asyncio.sleep(0.2)
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
                    _test_assert(w.call_count >= 1, "warning on executor failure")

    asyncio.run(run())
