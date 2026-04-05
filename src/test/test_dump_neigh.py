"""Tests for dump_neigh TTL behavior."""
from __future__ import annotations

import io
import logging
from contextlib import redirect_stdout
from unittest.mock import patch

from src import dump
from src.config import Config
from src.models import IPEntryStore, IPEntry
from src.types import BridgeName, IPv4Address, MACAddress, NodeID


class _DummyCore:
    """Minimal core-like object for dump_neigh tests."""

    def __init__(self) -> None:
        self.config = Config(bridges=["vmbr0"], mesh_ttl=200.0)
        self.log = logging.getLogger("test")
        self._entries = IPEntryStore()
        self._state_mgr = None


def test_dump_neigh_ttl_uses_last_seen_only() -> None:
    """dump_neigh TTL uses last_seen only, not last_received."""
    core = _DummyCore()
    core._entries.set(
        IPEntry(
            ipv4=IPv4Address("192.168.13.105"),
            mac=MACAddress("fa:9b:c9:91:4d:47"),
            bridge=BridgeName("vmbr0"),
            vlan=100,
            node=NodeID("172.16.12.10"),
            last_seen=100.0,
            last_received=950.0,
        )
    )
    buf = io.StringIO()
    with patch("src.dump.time.time", return_value=1000.0):
        with redirect_stdout(buf):
            dump.dump_neigh(core)  # type: ignore[arg-type]
    out = buf.getvalue().strip()
    # mesh_ttl=200, now=1000, last_seen=100 -> rem=0
    assert out.endswith(" 0"), f"unexpected TTL output: {out}"

