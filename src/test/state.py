"""Tests for src.state."""
import os
import tempfile
import time
from src.types import MACAddress, IPv4Address, BridgeName, NodeID
from src.models import IPEntry, IPEntryStore
from src.state import StateManager
from src.test import _test_assert


def test_state_manager() -> None:
    """StateManager: load_into, save_from (temp dir) with IPEntryStore."""
    with tempfile.TemporaryDirectory() as tmp:
        mgr = StateManager(tmp)
        store = IPEntryStore()
        mgr.load_into(store)
        _test_assert(len(store) == 0, "load_into empty")
        ip = IPv4Address("1.2.3.4")
        br = BridgeName("vmbr0")
        e = IPEntry(ipv4=ip, mac=MACAddress("aa:bb:cc:dd:ee:ff"), bridge=br, last_seen=time.time())
        store.set(e)
        mgr.save_from(store)
        store2 = IPEntryStore()
        mgr.load_into(store2)
        _test_assert(store2.get(ip, br, None).ipv4 == ip, "save_from/load_into")
        store2.update((ip, br, None), node=NodeID("n1"))
        mgr.save_from(store2)
        store3 = IPEntryStore()
        mgr.load_into(store3)
        _test_assert(store3.get(ip, br, None).node == NodeID("n1"), "save_from roundtrip")


def test_state_load_into_missing_file() -> None:
    """StateManager.load_into: missing file leaves store empty."""
    with tempfile.TemporaryDirectory() as tmp:
        mgr = StateManager(tmp)
        store = IPEntryStore()
        ip = IPv4Address("1.2.3.4")
        store.set(IPEntry(ipv4=ip, mac=MACAddress("aa:bb:cc:dd:ee:ff"), bridge=BridgeName("vmbr0"), last_seen=time.time()))
        path = os.path.join(tmp, "state.json")
        assert not os.path.exists(path), "no file yet"
        store2 = IPEntryStore()
        mgr.load_into(store2)
        _test_assert(len(store2) == 0, "load_into missing file leaves empty")
