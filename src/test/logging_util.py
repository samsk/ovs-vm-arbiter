"""Tests for src.logging_util (DebugDedupFilter)."""
import logging
from unittest.mock import MagicMock, patch

from src.logging_util import DebugDedupFilter, NO_DEDUP_ATTR, setup_logging
from src.test import _test_assert


def test_dedup_filter_db_ip_updated_once() -> None:
    """Same 'db ip updated' message 50 times -> only first passes filter."""
    f = DebugDedupFilter(max_keys=1000)
    seen: list[logging.LogRecord] = []

    class CaptureHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            seen.append(record)

    log = logging.getLogger("test_dedup")
    log.setLevel(logging.DEBUG)
    log.handlers.clear()
    h = CaptureHandler()
    h.addFilter(f)
    log.addHandler(h)
    msg = "db ip updated remote ip=192.168.12.5 from=172.16.12.13"
    for _ in range(50):
        log.debug(msg)
    _test_assert(len(seen) == 1, "db ip updated logged exactly once")
    _test_assert(seen[0].getMessage() == msg, "message unchanged")


def test_dedup_filter_immediate_sequence_only() -> None:
    """Only consecutive duplicates suppressed; same message after different passes."""
    f = DebugDedupFilter()
    seen: list[str] = []

    class CaptureHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            seen.append(record.getMessage())

    log = logging.getLogger("test_dedup_immediate")
    log.setLevel(logging.DEBUG)
    log.handlers.clear()
    h = CaptureHandler()
    h.addFilter(f)
    log.addHandler(h)
    log.debug("msg A")
    log.debug("msg A")
    log.debug("msg B")
    log.debug("msg A")
    _test_assert(len(seen) == 3, "A,A,B,A -> 3 records (A, B, A)")
    _test_assert(seen[0] == "msg A" and seen[1] == "msg B" and seen[2] == "msg A", "immediate sequence only")


def test_dedup_filter_different_messages_both_pass() -> None:
    """Two different messages -> both pass."""
    f = DebugDedupFilter(max_keys=1000)
    seen: list[str] = []

    class CaptureHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            seen.append(record.getMessage())

    log = logging.getLogger("test_dedup2")
    log.setLevel(logging.DEBUG)
    log.handlers.clear()
    h = CaptureHandler()
    h.addFilter(f)
    log.addHandler(h)
    log.debug("db ip updated remote ip=1.2.3.4 from=node1")
    log.debug("db ip added remote ip=5.6.7.8 mac=aa:bb from=node2")
    _test_assert(len(seen) == 2, "two distinct messages both logged")
    _test_assert("1.2.3.4" in seen[0] and "5.6.7.8" in seen[1], "content correct")


def test_dedup_filter_info_always_passes() -> None:
    """INFO (non-DEBUG) messages are not deduplicated."""
    f = DebugDedupFilter(max_keys=1000)
    seen: list[logging.LogRecord] = []

    class CaptureHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            seen.append(record)

    log = logging.getLogger("test_dedup3")
    log.setLevel(logging.DEBUG)
    log.handlers.clear()
    h = CaptureHandler()
    h.addFilter(f)
    log.addHandler(h)
    for _ in range(5):
        log.info("mesh recv from=172.16.12.13 entries=3")
    _test_assert(len(seen) == 5, "INFO repeated 5 times -> 5 records")


def test_dedup_filter_no_dedup_always_passes() -> None:
    """Same DEBUG message with extra no_dedup=True -> every call passes (e.g. arp reply)."""
    f = DebugDedupFilter(max_keys=1000)
    seen: list[logging.LogRecord] = []

    class CaptureHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            seen.append(record)

    log = logging.getLogger("test_dedup_no_dedup")
    log.setLevel(logging.DEBUG)
    log.handlers.clear()
    h = CaptureHandler()
    h.addFilter(f)
    log.addHandler(h)
    msg = "arp reply who-has 1.2.3.4 => aa:bb on vmbr0 vlan=99 in_port=3 (fast path)"
    for _ in range(5):
        log.debug(msg, extra={NO_DEDUP_ATTR: True})
    _test_assert(len(seen) == 5, "no_dedup: same message 5 times -> 5 records")
    _test_assert(all(getattr(r, NO_DEDUP_ATTR, False) for r in seen), "records have no_dedup")


def test_setup_logging_non_tty_syslog_only_one_handler() -> None:
    """Under systemd: syslog ok + non-tty stderr -> avoid duplicate journal lines."""
    with patch("src.logging_util.logging.handlers.SysLogHandler", MagicMock()):
        with patch("src.logging_util.sys.stderr") as stderr:
            stderr.isatty.return_value = False
            log = setup_logging("info", debug=False)
    _test_assert(len(log.handlers) == 1, "single handler")
    _test_assert(not isinstance(log.handlers[0], logging.StreamHandler), "no stderr when syslog ok")


def test_setup_logging_tty_stderr_only() -> None:
    """Interactive: stderr only (skip syslog so terminal is single path)."""
    with patch("src.logging_util.logging.handlers.SysLogHandler", MagicMock()):
        with patch("src.logging_util.sys.stderr") as stderr:
            stderr.isatty.return_value = True
            log = setup_logging("info", debug=False)
    types = [type(h).__name__ for h in log.handlers]
    _test_assert(types == ["StreamHandler"], "tty: stderr only, no syslog")


def test_setup_logging_no_syslog_uses_stderr() -> None:
    """No /dev/log: stderr only."""
    with patch("src.logging_util.logging.handlers.SysLogHandler", side_effect=OSError("no log")):
        with patch("src.logging_util.sys.stderr") as stderr:
            stderr.isatty.return_value = False
            log = setup_logging("info", debug=False)
    types = [type(h).__name__ for h in log.handlers]
    _test_assert(types == ["StreamHandler"], "fallback to stderr when syslog fails")
