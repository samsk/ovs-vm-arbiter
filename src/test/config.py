"""Tests for src.config."""
import os
from unittest.mock import patch, MagicMock
from src.config import (
    Config,
    LIST_MODE_DB,
    LIST_MODE_FDB,
    LIST_MODE_LOCAL_IPS,
    LIST_MODE_REMOTE_IPS,
    get_node_ip,
    _ovs_options_remote_ip,
    parse_vlan_list,
    set_process_name,
)
from src.main import build_parser
from src.test import _test_assert


def test_parse_vlan_list() -> None:
    """parse_vlan_list: single IDs, ranges, empty; 0 = untagged."""
    _test_assert(parse_vlan_list(None) == frozenset(), "None -> empty")
    _test_assert(parse_vlan_list("") == frozenset(), "empty -> empty")
    _test_assert(parse_vlan_list("20") == frozenset({20}), "single")
    _test_assert(parse_vlan_list("20,30-50,99") == frozenset({20, 99}) | set(range(30, 51)), "list and range")
    _test_assert(0 in parse_vlan_list("0,10"), "0 untagged in set")


def test_config() -> None:
    """Config: from_args, is_debug, get_sign_key."""
    parser = build_parser()
    args = parser.parse_args(["--service", "--bridges", "vmbr0", "--state-dir", "/tmp/arbiter-test"])
    config = Config.from_args(args)
    _test_assert(config.bridges == ["vmbr0"] and config.state_dir == "/tmp/arbiter-test", "from_args")
    _test_assert(config.is_debug() is False, "is_debug")
    _test_assert(config.get_sign_key() is None, "get_sign_key none")
    args2 = parser.parse_args(["--service", "--mesh-sign-key", "secret"])
    config2 = Config.from_args(args2)
    _test_assert(config2.get_sign_key() == b"secret", "get_sign_key")


def test_config_broadcast_iface_default() -> None:
    """Config.from_args sets broadcast_iface from first bridge when not provided."""
    parser = build_parser()
    args = parser.parse_args(["--service", "--bridges", "vmbr0", "vmbr1"])
    cfg = Config.from_args(args)
    _test_assert(cfg.broadcast_iface == "vmbr0", "broadcast_iface defaults to first bridge")


def test_ovs_options_remote_ip() -> None:
    """_ovs_options_remote_ip helper."""
    _test_assert(_ovs_options_remote_ip(["map", [["remote_ip", "10.0.0.1"]]]) == "10.0.0.1", "extract")
    _test_assert(_ovs_options_remote_ip([]) is None, "empty")
    _test_assert(_ovs_options_remote_ip(["map", []]) is None, "no remote_ip")


def test_config_get_sign_key_file() -> None:
    """Config.get_sign_key from file."""
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".key", delete=False) as f:
        f.write("file-key\n")
        f.flush()
        path = f.name
    try:
        parser = build_parser()
        args = parser.parse_args(["--service", "--mesh-sign-key-file", path])
        cfg = Config.from_args(args)
        _test_assert(cfg.get_sign_key() == b"file-key", "get_sign_key from file")
    finally:
        os.unlink(path)


def test_get_node_ip_mock() -> None:
    """get_node_ip with mocked IPRoute (only in test mode)."""
    fake_ip = "192.168.99.1"
    ipr_instance = MagicMock()
    route = MagicMock()
    route.get = lambda k, d=None: 0 if k == "dst_len" else d
    route.get_attr = lambda k: 1 if k == "RTA_OIF" else None
    ipr_instance.get_routes.return_value = [route]
    msg = MagicMock()
    msg.get = lambda k, d=None: 2 if k == "family" else d
    msg.get_attr = lambda k: fake_ip if k == "IFA_ADDRESS" else None
    ipr_instance.get_addr.return_value = [msg]
    ipr_instance.link_lookup.return_value = [1]
    ipr_class = MagicMock(return_value=ipr_instance)
    with patch("src.config.IPRoute", ipr_class):
        result = get_node_ip(None)
    _test_assert(result == fake_ip, "get_node_ip returns mocked IP")


def test_set_process_name() -> None:
    """set_process_name accepts short name (no-op or prctl)."""
    set_process_name(b"ovs-vm-arbiter")
    set_process_name(b"")
    set_process_name(b"x" * 20)
    _test_assert(True, "no raise")


def test_config_arp_responder_reply_local_default() -> None:
    """arp_responder_reply_local defaults to arp_reply_local when not set."""
    parser = build_parser()
    # Not set: follows arp_reply_local (default True)
    args = parser.parse_args(["--service", "--bridges", "vmbr0"])
    cfg = Config.from_args(args)
    _test_assert(cfg.arp_reply_local is True, "arp_reply_local default True")
    _test_assert(cfg.arp_responder_reply_local is True, "arp_responder_reply_local follows")

    args_yes = parser.parse_args(["--service", "--bridges", "vmbr0", "--arp-reply-local"])
    cfg_yes = Config.from_args(args_yes)
    _test_assert(cfg_yes.arp_reply_local is True, "arp_reply_local True")
    _test_assert(cfg_yes.arp_responder_reply_local is True, "arp_responder_reply_local follows True")

    args_no = parser.parse_args(["--service", "--bridges", "vmbr0", "--no-arp-reply-local"])
    cfg_no = Config.from_args(args_no)
    _test_assert(cfg_no.arp_responder_reply_local is False, "arp_responder_reply_local follows False")

    # Explicit override
    args_override = parser.parse_args(
        ["--service", "--bridges", "vmbr0", "--arp-reply-local", "--no-arp-responder-reply-local"]
    )
    cfg_ov = Config.from_args(args_override)
    _test_assert(cfg_ov.arp_reply_local is True and cfg_ov.arp_responder_reply_local is False, "explicit no wins")


def test_config_snoop_vlans_from_args() -> None:
    """Config.from_args parses --snoop-vlans and --no-snoop-vlans into sets."""
    parser = build_parser()
    args = parser.parse_args(["--service", "--bridges", "vmbr0", "--snoop-vlans", "20,30-32,99"])
    cfg = Config.from_args(args)
    _test_assert(cfg.snoop_vlan_set is not None, "snoop_vlan_set set")
    _test_assert(cfg.snoop_vlan_set == frozenset({20, 30, 31, 32, 99}), "snoop range parsed")
    args2 = parser.parse_args(["--service", "--bridges", "vmbr0", "--no-snoop-vlans", "1,2"])
    cfg2 = Config.from_args(args2)
    _test_assert(cfg2.no_snoop_vlan_set == frozenset({1, 2}), "no_snoop_vlan_set")


def test_config_snoop_takeover_sec_default_and_override() -> None:
    """snoop_takeover_sec defaults to mesh_ttl/10 and supports override."""
    parser = build_parser()
    args = parser.parse_args(["--service", "--bridges", "vmbr0", "--mesh-ttl", "500"])
    cfg = Config.from_args(args)
    _test_assert(cfg.snoop_takeover_sec == 50.0, "default takeover mesh_ttl/10")
    args2 = parser.parse_args(
        ["--service", "--bridges", "vmbr0", "--mesh-ttl", "500", "--snoop-takeover-sec", "120"]
    )
    cfg2 = Config.from_args(args2)
    _test_assert(cfg2.snoop_takeover_sec == 120.0, "override takeover sec")


def test_config_mesh_send_max_interval() -> None:
    """mesh_send_max_interval is parsed from CLI."""
    parser = build_parser()
    cfg_new = Config.from_args(
        parser.parse_args(
            ["--service", "--bridges", "vmbr0", "--mesh-send-max-interval", "12"]
        )
    )
    _test_assert(cfg_new.mesh_send_max_interval == 12.0, "new max interval arg")


def test_config_migration_and_db_flags_defaults() -> None:
    """Config.from_args sets defaults for migration and DB flags."""
    parser = build_parser()
    cfg = Config.from_args(parser.parse_args(["--service", "--bridges", "vmbr0"]))
    _test_assert(cfg.verify_local_migration is True, "verify_local_migration default true")
    _test_assert(cfg.verify_remote_migration is False, "verify_remote_migration default false")
    _test_assert(cfg.db_stat_optimization is False, "db_stat_optimization default false")
    _test_assert(cfg.db_force_debounce_sec == 1.0, "db_force_debounce_sec default")
    _test_assert(cfg.list_pve_db is False, "list_pve_db default false")


def test_config_migration_and_db_flags_override() -> None:
    """Config.from_args supports migration and DB flag overrides."""
    parser = build_parser()
    cfg = Config.from_args(
        parser.parse_args(
            [
                "--bridges",
                "vmbr0",
                "--no-verify-local-migration",
                "--verify-remote-migration",
                "--no-db-stat-optimization",
                "--db-force-debounce-sec",
                "2.5",
                "--list-pve-db",
            ]
        )
    )
    _test_assert(cfg.verify_local_migration is False, "verify_local_migration override")
    _test_assert(cfg.verify_remote_migration is True, "verify_remote_migration override")
    _test_assert(cfg.db_stat_optimization is False, "db_stat_optimization override")
    _test_assert(cfg.db_force_debounce_sec == 2.5, "db_force_debounce_sec override")
    _test_assert(cfg.list_pve_db is True, "list_pve_db override")


def test_config_migration_invalidates_fdb_default_and_override() -> None:
    """migration_invalidates_fdb defaults on and can be disabled."""
    parser = build_parser()
    cfg = Config.from_args(parser.parse_args(["--service", "--bridges", "vmbr0"]))
    _test_assert(cfg.migration_invalidates_fdb is True, "default enabled")
    cfg2 = Config.from_args(
        parser.parse_args(
            ["--service", "--bridges", "vmbr0", "--no-migration-invalidates-fdb"]
        )
    )
    _test_assert(cfg2.migration_invalidates_fdb is False, "override disabled")


def test_config_is_debug_log_level() -> None:
    """Config.is_debug True when log_level is debug."""
    cfg = Config(debug=False, log_level="debug")
    _test_assert(cfg.is_debug() is True, "log_level debug")


def test_config_get_sign_key_file_missing() -> None:
    """Config.get_sign_key: missing file returns None or inline key."""
    cfg = Config(mesh_sign_key_file="/nonexistent/key", mesh_sign_key=None)
    _test_assert(cfg.get_sign_key() is None, "missing file")
    cfg2 = Config(mesh_sign_key_file="/nonexistent/key", mesh_sign_key="inline")
    _test_assert(cfg2.get_sign_key() == b"inline", "inline fallback")


def test_config_list_mode_mask() -> None:
    """list_mode_mask combines all selected list flags."""
    parser = build_parser()
    cfg = Config.from_args(
        parser.parse_args(
            [
                "--bridges",
                "vmbr0",
                "--list-db",
                "--list-local",
                "--list-remote",
                "--list-fdb",
            ]
        )
    )
    expected = LIST_MODE_DB | LIST_MODE_LOCAL_IPS | LIST_MODE_REMOTE_IPS | LIST_MODE_FDB
    _test_assert(cfg.list_mode_mask == expected, "list_mode_mask bitset")


def test_config_prometheus_flags() -> None:
    """Prometheus flags parse to Config fields."""
    parser = build_parser()
    cfg = Config.from_args(parser.parse_args(["--service", "--bridges", "vmbr0"]))
    _test_assert(cfg.prometheus_metrics is False, "prometheus disabled by default")
    _test_assert(cfg.prometheus_metrics_extra is False, "prometheus extra disabled by default")
    _test_assert(cfg.prometheus_port == 9108, "prometheus port default")
    _test_assert(cfg.prometheus_host == "localhost", "prometheus host default")
    cfg2 = Config.from_args(
        parser.parse_args(
            [
                "--service",
                "--bridges",
                "vmbr0",
                "--prometheus-metrics",
                "--prometheus-metrics-extra",
                "--prometheus-port",
                "9200",
                "--prometheus-host",
                "0.0.0.0",
            ]
        )
    )
    _test_assert(cfg2.prometheus_metrics is True, "prometheus enabled")
    _test_assert(cfg2.prometheus_metrics_extra is True, "prometheus extra enabled")
    _test_assert(cfg2.prometheus_port == 9200, "prometheus port override")
    _test_assert(cfg2.prometheus_host == "0.0.0.0", "prometheus host override")
