"""CLI: --service vs list / test / version."""
from src.main import build_parser, _has_explicit_run_mode
from src.test import _test_assert


def test_explicit_run_mode_service() -> None:
    """--service counts as explicit daemon mode."""
    p = build_parser()
    _test_assert(_has_explicit_run_mode(p.parse_args(["--service"])), "bare --service")
    _test_assert(
        _has_explicit_run_mode(p.parse_args(["--service", "--bridges", "vmbr0"])),
        "service with bridges",
    )


def test_explicit_run_mode_list_flags() -> None:
    """Each list action satisfies the gate without --service."""
    p = build_parser()
    _test_assert(_has_explicit_run_mode(p.parse_args(["--list-db"])), "list-db")
    _test_assert(_has_explicit_run_mode(p.parse_args(["--list-pve-db"])), "list-pve-db")
    _test_assert(_has_explicit_run_mode(p.parse_args(["--list-peers"])), "list-peers")
    _test_assert(_has_explicit_run_mode(p.parse_args(["--list-neigh"])), "list-neigh")
    _test_assert(_has_explicit_run_mode(p.parse_args(["--list-remote"])), "list-remote")
    _test_assert(_has_explicit_run_mode(p.parse_args(["--list-local"])), "list-local")
    _test_assert(_has_explicit_run_mode(p.parse_args(["--list-refreshers"])), "list-refreshers")
    _test_assert(_has_explicit_run_mode(p.parse_args(["--list-responders"])), "list-responders")
    _test_assert(_has_explicit_run_mode(p.parse_args(["--list-vlans"])), "list-vlans")
    _test_assert(_has_explicit_run_mode(p.parse_args(["--list-fdb"])), "list-fdb default bridge")
    _test_assert(
        _has_explicit_run_mode(p.parse_args(["--list-fdb", "vmbr0"])),
        "list-fdb named bridge",
    )


def test_explicit_run_mode_version_test() -> None:
    """--version and --test skip the service requirement."""
    p = build_parser()
    _test_assert(_has_explicit_run_mode(p.parse_args(["--version"])), "version")
    _test_assert(_has_explicit_run_mode(p.parse_args(["--test"])), "test")


def test_explicit_run_mode_rejects_bare_daemon_args() -> None:
    """Bridges-only (or empty) is not explicit without --service."""
    p = build_parser()
    _test_assert(not _has_explicit_run_mode(p.parse_args([])), "empty argv")
    _test_assert(
        not _has_explicit_run_mode(p.parse_args(["--bridges", "vmbr0"])),
        "bridges only",
    )
    _test_assert(
        not _has_explicit_run_mode(p.parse_args(["--bridges", "vmbr0", "--debug"])),
        "bridges and debug",
    )
