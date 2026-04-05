"""Tests for dump_pve_db formatting."""
from __future__ import annotations

import io
import logging
from contextlib import redirect_stdout

from src import dump
from src.config import Config
from src.models import InstanceStore, InstanceInfo
from src.types import VMID, BridgeName, MACAddress, IPv4Address


class _DummyWatcher:
    """Watcher stub for dump tests."""

    def __init__(self, store: InstanceStore) -> None:
        self._store = store

    def poll(self, force_refresh: bool = False) -> InstanceStore:
        """Return prepared store.

        Args:
            force_refresh: Unused in stub.

        Returns:
            Prepared instance store.
        """
        return self._store


class _DummyCore:
    """Core-like object with watcher only."""

    def __init__(self, store: InstanceStore) -> None:
        self.config = Config(bridges=["vmbr0"])
        self.log = logging.getLogger("test")
        self._watcher = _DummyWatcher(store)


def test_dump_pve_db_formatted_table() -> None:
    """dump_pve_db prints formatted table rows, not JSON."""
    store = InstanceStore()
    store.set(
        MACAddress("aa:bb:cc:dd:ee:01"),
        InstanceInfo(
            vmid=VMID("101"),
            type="qemu",
            bridge=BridgeName("vmbr0"),
            mac=MACAddress("aa:bb:cc:dd:ee:01"),
            vlan=100,
            ip=IPv4Address("192.168.1.10"),
            tags=["prod", "web"],
        ),
    )
    store.set(
        MACAddress("aa:bb:cc:dd:ee:02"),
        InstanceInfo(
            vmid=VMID("102"),
            type="lxc",
            bridge=BridgeName("vmbr1"),
            mac=MACAddress("aa:bb:cc:dd:ee:02"),
        ),
    )
    core = _DummyCore(store)
    buf = io.StringIO()
    with redirect_stdout(buf):
        dump.dump_pve_db(core)  # type: ignore[arg-type]
    out = buf.getvalue().strip().splitlines()
    assert out, "output exists"
    assert out[0].startswith("MAC"), "header exists"
    assert "VMID" in out[0] and "TAGS" in out[0], "header columns"
    assert any("aa:bb:cc:dd:ee:01" in line and "101" in line for line in out[1:]), "qemu row"
    assert any("aa:bb:cc:dd:ee:02" in line and "102" in line for line in out[1:]), "lxc row"
    assert "{" not in "\n".join(out), "not json output"

