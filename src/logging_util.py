# Logging setup and dedup filter
import logging
import logging.handlers
import sys
from typing import Optional

_LEVEL_MAP = {"debug": logging.DEBUG, "info": logging.INFO, "warning": logging.WARNING, "error": logging.ERROR}

# Extra key: set extra={'no_dedup': True} on log call to always emit (e.g. arp reply)
NO_DEDUP_ATTR = "no_dedup"

# Debug flag bits (Config.debug_flags)
DEBUG_ARP_REPLY = 1


class DebugDedupFilter(logging.Filter):
    """Suppress consecutive duplicate DEBUG messages only.
    Same message as previous -> suppress. Different message (or first) -> emit.
    Records with extra no_dedup=True are always emitted."""

    def __init__(self, max_keys: Optional[int] = None) -> None:
        super().__init__()
        # max_keys unused; kept for backward-compat with tests that pass it
        self._last: Optional[str] = None

    def filter(self, record: logging.LogRecord) -> bool:
        if record.levelno != logging.DEBUG:
            return True
        if getattr(record, NO_DEDUP_ATTR, False):
            return True
        key = record.getMessage()
        if key == self._last:
            return False
        self._last = key
        return True


def setup_logging(log_level: str, debug: bool = False) -> logging.Logger:
    """Configure root logger for ovs-vm-arbiter.

    Uses syslog to /dev/log when stderr is not a TTY (e.g. systemd); uses stderr
    when interactive or when syslog is unavailable. Avoids attaching both, which
    duplicates every line in the journal (syslog + systemd-captured stderr).

    Args:
        log_level: One of debug, info, warning, error.
        debug: If True, forces debug level.

    Returns:
        The configured ``logging.Logger`` named ovs-vm-arbiter.
    """
    if debug:
        log_level = "debug"
    level = _LEVEL_MAP.get(log_level, logging.INFO)
    log = logging.getLogger("ovs-vm-arbiter")
    log.setLevel(level)
    log.propagate = False
    log.handlers.clear()
    log.addFilter(DebugDedupFilter())
    syslog_ok = False
    # systemd / background: one line via syslog (not also stderr -> journal twice)
    if not sys.stderr.isatty():
        try:
            h = logging.handlers.SysLogHandler(
                address="/dev/log",
                facility=logging.handlers.SysLogHandler.LOG_LOCAL0,
            )
            h.setFormatter(logging.Formatter("%(message)s"))
            h.setLevel(level)
            log.addHandler(h)
            syslog_ok = True
        except OSError:
            pass
    if sys.stderr.isatty() or not syslog_ok:
        eh = logging.StreamHandler(sys.stderr)
        eh.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        eh.setLevel(level)
        log.addHandler(eh)
    return log
