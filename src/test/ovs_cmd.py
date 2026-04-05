"""Tests for src.ovs_cmd."""
from unittest.mock import patch, MagicMock
from src.ovs_cmd import OVSCommand
from src.test import _test_assert


def test_ovs_command_parse() -> None:
    """OVSCommand: parse_table_rows (no subprocess)."""
    data = {"headings": ["a", "b"], "data": [[1, 2], [3, 4]]}
    rows = OVSCommand.parse_table_rows(data)
    _test_assert(len(rows) == 2 and rows[0]["a"] == 1 and rows[0]["b"] == 2, "parse_table_rows")
    _test_assert(OVSCommand.parse_table_rows({}) == [], "empty")


def test_ovs_command_run_vsctl() -> None:
    """OVSCommand.run_vsctl with mocked subprocess."""
    fake_out = '{"headings":["name"],"data":[["vmbr0"]]}'
    with patch("subprocess.run") as m_run:
        m_run.return_value = MagicMock(returncode=0, stdout=fake_out, stderr="")
        ok, data = OVSCommand.run_vsctl(["list", "Bridge"])
        _test_assert(ok is True, "run_vsctl ok")
        _test_assert(isinstance(data, dict) and "data" in data, "run_vsctl json")
    with patch("subprocess.run") as m_run:
        m_run.return_value = MagicMock(returncode=1, stdout="", stderr="err")
        ok, _ = OVSCommand.run_vsctl(["list", "x"])
        _test_assert(ok is False, "run_vsctl fail")


def test_parse_table_rows_empty_headings() -> None:
    """parse_table_rows: empty headings or no data returns []."""
    _test_assert(OVSCommand.parse_table_rows({"headings": [], "data": [[1]]}) == [], "empty headings")
    _test_assert(OVSCommand.parse_table_rows({"headings": ["a"], "data": []}) == [], "empty data")


def test_build_ofctl_cmd() -> None:
    """_build_ofctl_cmd: list vs str args."""
    cmd = OVSCommand._build_ofctl_cmd("add-flow", "vmbr0", "priority=1,actions=drop")
    _test_assert(cmd == ["ovs-ofctl", "add-flow", "vmbr0", "priority=1,actions=drop"], "str args")
    cmd2 = OVSCommand._build_ofctl_cmd("dump-flows", "vmbr0", [])
    _test_assert(cmd2 == ["ovs-ofctl", "dump-flows", "vmbr0"], "empty list")
