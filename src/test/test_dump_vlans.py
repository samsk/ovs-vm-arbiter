"""Tests for dump_vlans local/remote classification."""
from __future__ import annotations

import io
import logging
import sys
from contextlib import redirect_stdout

from src.config import Config
from src.core import ArbiterCore
from src.models import IPEntryStore, IPEntry
from src.types import BridgeName, IPv4Address, MACAddress, NodeID
from src import dump


class _DummyCore(ArbiterCore):
    """Minimal ArbiterCore-like object for dump_vlans tests."""

    def __init__(self, config: Config, log: logging.Logger, node_id: str) -> None:
        # Do not call ArbiterCore.__init__; only set attributes used by dump_vlans/_dump_preamble.
        self.config = config
        self.log = log
        self._entries = IPEntryStore()
        self._state_mgr = None  # type: ignore[assignment]
        self._node_id = node_id

    # Reuse ArbiterCore helpers for locality.
    def _is_local_node(self, node: NodeID | None) -> bool:  # type: ignore[override]
        from src.core import ArbiterCore as _Core

        return _Core._is_local_node(self, node)  # type: ignore[arg-type]


def _make_core_with_entries() -> ArbiterCore:
    """Build a minimal core-like object with known entries for dump_vlans."""
    cfg = Config(bridges=["vmbr0"])
    cfg.node = "172.16.12.10"
    log = logging.getLogger("test")
    core = _DummyCore(cfg, log, node_id="172.16.12.10")
    # Local entries on this node
    core._entries.set(
        IPEntry(
            ipv4=IPv4Address("192.168.13.201"),
            mac=MACAddress("aa:bb:cc:dd:ee:01"),
            bridge=BridgeName("vmbr0"),
            vlan=98,
            node=NodeID("172.16.12.10"),
            last_seen=1.0,
        )
    )
    core._entries.set(
        IPEntry(
            ipv4=IPv4Address("192.168.13.183"),
            mac=MACAddress("aa:bb:cc:dd:ee:02"),
            bridge=BridgeName("vmbr0"),
            vlan=99,
            node=NodeID("172.16.12.10"),
            last_seen=1.0,
        )
    )
    # Remote entry on other node
    core._entries.set(
        IPEntry(
            ipv4=IPv4Address("192.168.13.218"),
            mac=MACAddress("aa:bb:cc:dd:ee:03"),
            bridge=BridgeName("vmbr0"),
            vlan=100,
            node=NodeID("172.16.12.12"),
            last_seen=1.0,
        )
    )
    return core  # type: ignore[return-value]


def test_dump_vlans_local_and_remote() -> None:
    """dump_vlans: VLANs present locally are local; others remote; all IPs listed."""
    core = _make_core_with_entries()
    buf = io.StringIO()
    with redirect_stdout(buf):
        # Call dump_vlans without _dump_preamble; we already seeded _entries.
        dump.dump_vlans(core)  # type: ignore[arg-type]
    out = buf.getvalue().strip().splitlines()
    # Sorting is by vlan then scope; we only care about classification.
    lines = {line.split()[0]: line for line in out}
    assert "98" in lines, "vlan 98 present"
    assert "99" in lines, "vlan 99 present"
    assert "100" in lines, "vlan 100 present"
    assert "98 local" in lines["98"], "vlan 98 is local"
    assert "99 local" in lines["99"], "vlan 99 is local"
    assert "100 remote" in lines["100"], "vlan 100 is remote"

