"""Tests for src.instance_watcher."""
import logging
import tempfile
from unittest.mock import patch

from src.config import Config
from src.instance_watcher import InstanceWatcher, _path_node
from src.test import _test_assert


def test_path_node() -> None:
    """_path_node extracts node from config.db path; other paths return None."""
    _test_assert(_path_node("nodes/pve1/qemu-server/100.conf") == "pve1", "nodes path")
    _test_assert(_path_node("nodes/pve2/lxc/200.conf") == "pve2", "lxc path")
    _test_assert(_path_node("qemu-server/100.conf") is None, "no nodes prefix")
    _test_assert(_path_node("nodes/") is None, "nodes only no name")


def test_instance_watcher_parse() -> None:
    """InstanceWatcher: _parse_net_line, _parse_tags (no DB)."""
    log = logging.getLogger("test")
    w = InstanceWatcher("/nonexistent/db", log)
    nets = w._parse_net_line("net0: virtio=aa:bb:cc:dd:ee:ff,bridge=vmbr0,tag=10", False)
    _test_assert(len(nets) == 1 and nets[0].bridge == "vmbr0" and nets[0].vlan == 10, "parse_net qemu")
    nets2 = w._parse_net_line("net0: hwaddr=aa:bb:cc:dd:ee:ff,bridge=vmbr0,ip=192.168.1.1/24", True)
    _test_assert(len(nets2) == 1 and nets2[0].ip == "192.168.1.1", "parse_net lxc")
    tags = w._parse_tags("tags: a, b; c")
    _test_assert(set(tags) == {"a", "b", "c"}, "parse_tags")


def test_instance_watcher_parse_net_no_bridge() -> None:
    """InstanceWatcher._parse_net_line: no bridge returns []."""
    log = logging.getLogger("test")
    w = InstanceWatcher("/nonexistent/db", log)
    out = w._parse_net_line("net0: virtio=aa:bb:cc:dd:ee:ff", False)
    _test_assert(out == [], "no bridge")


def test_instance_watcher_parse_tags_empty() -> None:
    """InstanceWatcher._parse_tags: no match or empty."""
    log = logging.getLogger("test")
    w = InstanceWatcher("/nonexistent/db", log)
    _test_assert(w._parse_tags("no tags here") == [], "no match")
    _test_assert(w._parse_tags("tags: ") == [], "empty")


def test_instance_watcher_poll_uses_mtime_optimization() -> None:
    """poll skips reads when mtime unchanged."""
    with tempfile.NamedTemporaryFile() as f:
        cfg = Config(db_path=f.name, db_stat_optimization=True)
        w = InstanceWatcher(f.name, logging.getLogger("test"), cfg)
        with patch.object(w, "_read_db", return_value=True) as m_read:
            _ = w.poll()
            _ = w.poll()
        _test_assert(m_read.call_count == 1, "mtime optimization skips unchanged reads")


def test_instance_watcher_force_refresh_bypasses_mtime_optimization() -> None:
    """force_refresh ignores mtime optimization."""
    with tempfile.NamedTemporaryFile() as f:
        cfg = Config(db_path=f.name, db_stat_optimization=True, db_force_debounce_sec=0.0)
        w = InstanceWatcher(f.name, logging.getLogger("test"), cfg)
        with patch.object(w, "_read_db", return_value=True) as m_read:
            _ = w.poll()
            _ = w.poll(force_refresh=True)
        _test_assert(m_read.call_count == 2, "force refresh bypasses mtime shortcut")


def test_instance_watcher_poll_force_refresh_debounce() -> None:
    """force_refresh obeys db_force_debounce_sec when optimization is off."""
    with tempfile.NamedTemporaryFile() as f:
        cfg = Config(
            db_path=f.name,
            db_stat_optimization=False,
            db_debounce_sec=50.0,
            db_force_debounce_sec=1.0,
        )
        w = InstanceWatcher(f.name, logging.getLogger("test"), cfg)
        with patch.object(w, "_read_db", return_value=True) as m_read:
            with patch("src.instance_watcher.time.time", side_effect=[100.0, 100.2, 101.3]):
                _ = w.poll(force_refresh=True)
                _ = w.poll(force_refresh=True)
                _ = w.poll(force_refresh=True)
        _test_assert(m_read.call_count == 2, "force refresh is debounced to 1s")


def test_instance_watcher_db_status_fields() -> None:
    """db_ok and last_db_success_time update on poll result."""
    with tempfile.NamedTemporaryFile() as f:
        cfg = Config(db_path=f.name, db_stat_optimization=False, db_debounce_sec=0.0)
        w = InstanceWatcher(f.name, logging.getLogger("test"), cfg)
        _test_assert(w.db_ok() is False, "default db_ok false")
        _test_assert(w.last_db_success_time() == 0.0, "default success time zero")
        with patch.object(w, "_read_db", return_value=True):
            with patch("src.instance_watcher.time.time", return_value=111.0):
                _ = w.poll()
        _test_assert(w.db_ok() is True, "success sets db_ok")
        _test_assert(w.last_db_success_time() == 111.0, "success time set")
        with patch.object(w, "_read_db", return_value=False):
            with patch("src.instance_watcher.time.time", return_value=222.0):
                _ = w.poll(force_refresh=True)
        _test_assert(w.db_ok() is False, "failure clears db_ok")
        _test_assert(w.last_db_success_time() == 111.0, "last success retained")


def test_instance_watcher_poll_counters() -> None:
    """db_poll_counts tracks ok, fail, skipped."""
    with tempfile.NamedTemporaryFile() as f:
        cfg = Config(db_path=f.name, db_stat_optimization=False, db_debounce_sec=5.0)
        w = InstanceWatcher(f.name, logging.getLogger("test"), cfg)
        with patch.object(w, "_read_db", return_value=True):
            with patch("src.instance_watcher.time.time", return_value=100.0):
                _ = w.poll()
        with patch("src.instance_watcher.time.time", return_value=101.0):
            _ = w.poll()
        with patch.object(w, "_read_db", return_value=False):
            with patch("src.instance_watcher.time.time", return_value=200.0):
                _ = w.poll(force_refresh=True)
        c = w.db_poll_counts()
        _test_assert(c.get("ok", 0) == 1, "one ok poll")
        _test_assert(c.get("skipped", 0) >= 1, "one skipped poll")
        _test_assert(c.get("fail", 0) == 1, "one fail poll")
