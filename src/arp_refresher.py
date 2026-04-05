"""ARP refresh worker thread."""
from __future__ import annotations

import os
import random
import threading
import time
from typing import TYPE_CHECKING, List, Tuple, Optional

from src.types import MACAddress, IPv4Address
from src.models import IPEntryStore, IPEntry
from src.netlink import PeerTracker
from src.config import Config

if TYPE_CHECKING:
    import logging
    from src.packet_monitor import PacketMonitor


class ArpRefresher(threading.Thread):
    """Background thread: periodic ARP requests via correct OVS port to refresh FDB."""

    def __init__(
        self,
        tracker: PeerTracker,
        entries: IPEntryStore,
        config: Config,
        log: "logging.Logger",
        monitor: Optional["PacketMonitor"] = None,
    ) -> None:
        super().__init__(daemon=True)
        self._tracker = tracker
        self._entries = entries
        self._config = config
        self._log = log
        self._monitor = monitor
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    @staticmethod
    def iter_active_peer_entries(
        tracker: PeerTracker,
        entries: IPEntryStore,
    ) -> List[Tuple[MACAddress, str, float, IPEntry, IPEntry]]:
        """Resolve active peers to local/remote entry pairs."""
        resolved: List[Tuple[MACAddress, str, float, IPEntry, IPEntry]] = []
        peers = tracker.get_active_peers_with_ttl()
        for local_mac, remote_ip, last_seen in peers:
            local_candidates = entries.get_entries_by_mac(local_mac)
            for _key, local_entry in local_candidates:
                if not local_entry.bridge:
                    continue
                remote_entry = entries.get(
                    IPv4Address(remote_ip),
                    local_entry.bridge,
                    local_entry.vlan,
                )
                if not remote_entry:
                    continue
                resolved.append(
                    (local_mac, str(remote_ip), last_seen, local_entry, remote_entry)
                )
                break
        return resolved

    def run(self) -> None:
        try:
            if hasattr(os, "PRIO_PROCESS"):
                os.nice(10)
        except (OSError, PermissionError):
            pass
        interval = self._config.arp_refresh_interval
        while not self._stop.wait(timeout=interval + random.uniform(-5, 5)):
            self._tracker.cleanup()
            if self._monitor:
                pairs = self.iter_active_peer_entries(self._tracker, self._entries)
                for local_mac, remote_ip, _last_seen, local_entry, remote_entry in pairs:
                    if self._stop.is_set():
                        break
                    try:
                        self._monitor.send_arp_refresh_request(
                            local_mac,
                            local_entry.ipv4,
                            remote_entry.mac,
                            IPv4Address(remote_ip),
                            local_entry.bridge,
                            remote_entry.node,
                            local_entry.vlan,
                        )
                    except Exception as e:
                        self._log.debug(
                            "arp-refresh %s -> %s: %s", local_mac, remote_ip, e
                        )
                    time.sleep(random.uniform(0.05, 0.2))
            else:
                peers = self._tracker.get_active_peers_with_ttl()
                for _ in peers:
                    time.sleep(random.uniform(0.05, 0.2))
