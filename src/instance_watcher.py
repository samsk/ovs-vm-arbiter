# Poll Proxmox config.db for VM/LXC
import os
import re
import socket
import sqlite3
import time
from typing import Optional

from src.types import BridgeName, IPv4Address, MACAddress, VMID, NodeID
from src.models import InstanceInfo, InstanceStore, NetInterface, InstanceType
from src.config import Config

# InstanceType from models
import logging


def _path_node(full_path: str) -> Optional[str]:
    """Extract Proxmox node name from config path (nodes/NODENAME/...). Returns None if not nodes/ path or no name."""
    if not full_path.startswith("nodes/"):
        return None
    parts = full_path.split("/")
    if len(parts) >= 2 and parts[1]:
        return parts[1]
    return None


class InstanceWatcher:
    """Poll PMX config.db for VM/LXC MAC, bridge, tags. Cluster: only instances under nodes/<this_node>/."""

    def __init__(self, db_path: str, log: logging.Logger, config: Optional[Config] = None) -> None:
        self.db_path = db_path
        self.log = log
        self._config = config
        self._last_mtime: float = 0
        self._last_read: float = 0
        self._store = InstanceStore()
        self._db_unavailable_since: Optional[float] = None
        self._last_retry: float = 0
        self._last_force_read: float = 0
        self._last_unavail_log: float = 0
        self._last_db_success: float = 0.0
        self._db_ok: bool = False
        self._poll_ok_count: int = 0
        self._poll_fail_count: int = 0
        self._poll_skip_count: int = 0
        # Node name as in config.db paths (nodes/X/); hostname only (path is never IP)
        self._node_name: str = socket.gethostname()

    def last_db_success_time(self) -> float:
        """Return unix time of last successful DB read.

        Args:
            None.

        Returns:
            Last successful DB read timestamp, or 0.0 if never.
        """
        return self._last_db_success

    def db_ok(self) -> bool:
        """Return current DB health state.

        Args:
            None.

        Returns:
            True when last poll read DB successfully.
        """
        return self._db_ok

    def db_poll_counts(self) -> dict[str, int]:
        """Return poll result counters for metrics.

        Args:
            None.

        Returns:
            Dict with keys: ok, fail, skipped.
        """
        return {
            "ok": self._poll_ok_count,
            "fail": self._poll_fail_count,
            "skipped": self._poll_skip_count,
        }

    @property
    def _debounce_sec(self) -> float:
        return self._config.db_debounce_sec if self._config else 5.0

    @property
    def _periodic_sec(self) -> float:
        return self._config.db_periodic_sec if self._config else 60.0

    @property
    def _retry_sec(self) -> float:
        return self._config.db_retry_sec if self._config else 60.0

    @property
    def _unavail_log_sec(self) -> float:
        return self._config.db_unavail_log_sec if self._config else 300.0

    def _parse_net_line(self, line: str, is_lxc: bool) -> list[NetInterface]:
        out: list[NetInterface] = []
        bridge_m = re.search(r"bridge=([^,\s]+)", line)
        if not bridge_m:
            return out
        bridge = BridgeName(bridge_m.group(1))
        vlan: Optional[int] = None
        tag_m = re.search(r"tag=(\d+)", line)
        if tag_m:
            try:
                vlan = int(tag_m.group(1))
            except (TypeError, ValueError):
                pass
        config_ip: Optional[IPv4Address] = None
        if is_lxc:
            ip_m = re.search(r"ip=([0-9.]+)(?:/\d+)?", line)
            if ip_m:
                try:
                    import ipaddress
                    ipaddress.ip_address(ip_m.group(1))
                    config_ip = IPv4Address(ip_m.group(1))
                except ValueError:
                    pass
        if is_lxc:
            mac_m = re.search(r"hwaddr=([0-9a-fA-F:]+)", line)
        else:
            mac_m = re.search(r"virtio=([0-9a-fA-F:]+)", line) or re.search(r"mac=([0-9a-fA-F:]+)", line)
        if mac_m:
            mac = MACAddress(mac_m.group(1).lower())
            out.append(NetInterface(bridge=bridge, mac=mac, vlan=vlan, ip=config_ip))
        return out

    def _parse_tags(self, data: str) -> list[str]:
        m = re.search(r"tags:\s*([^\n]+)", data)
        if not m:
            return []
        return [t.strip() for t in m.group(1).replace(";", ",").split(",") if t.strip()]

    def poll(self, force_refresh: bool = False) -> InstanceStore:
        """Poll proxmox DB and return cached instance store.

        Args:
            force_refresh: True to bypass normal debounce (still rate-limited by force debounce).

        Returns:
            Current instance store.
        """
        now = time.time()
        if self._db_unavailable_since is not None:
            if now - self._last_retry < self._retry_sec:
                self._poll_skip_count += 1
                return self._store
            self._last_retry = now
        try:
            st = os.stat(self.db_path)
            mtime = st.st_mtime
        except (OSError, FileNotFoundError):
            self._db_ok = False
            self._poll_fail_count += 1
            self._on_db_fail(now)
            return self._store
        # force refresh must bypass mtime shortcut
        if (
            not force_refresh
            and self._config
            and self._config.db_stat_optimization
            and mtime == self._last_mtime
        ):
            self._poll_skip_count += 1
            return self._store
        periodic_force = (now - self._last_read) >= self._periodic_sec
        force_debounce = max(0.0, float(self._config.db_force_debounce_sec)) if self._config else 1.0
        if force_refresh:
            if (now - self._last_force_read) < force_debounce:
                self._poll_skip_count += 1
                return self._store
            self._last_force_read = now
        elif not periodic_force and (now - self._last_read) < self._debounce_sec:
            self._poll_skip_count += 1
            return self._store
        self._last_mtime = mtime
        self._last_read = now
        ok = self._read_db()
        if ok:
            self._db_ok = True
            self._last_db_success = now
            self._poll_ok_count += 1
            self._db_unavailable_since = None
            self._last_unavail_log = 0
        else:
            self._db_ok = False
            self._poll_fail_count += 1
            self._on_db_fail(now)
        return self._store

    def _on_db_fail(self, now: float) -> None:
        if self._db_unavailable_since is None:
            self._db_unavailable_since = now
        if now - self._db_unavailable_since >= self._unavail_log_sec:
            if now - self._last_unavail_log >= self._unavail_log_sec:
                self.log.warning(
                    "config.db unreadable for %.0fm (retry every %.0fs): %s",
                    (now - self._db_unavailable_since) / 60,
                    self._retry_sec,
                    self.db_path,
                )
                self._last_unavail_log = now

    def _read_db(self) -> bool:
        if not os.path.isfile(self.db_path):
            self.log.debug("config.db not found: %s", self.db_path)
            return False
        try:
            path = os.path.abspath(self.db_path)
            uri = f"file:{path}?mode=ro"
            conn = sqlite3.connect(uri, timeout=5, uri=True)
            try:
                cur = conn.execute("SELECT inode, parent, type, name FROM tree")
                all_rows = cur.fetchall()
                cur = conn.execute(
                    "SELECT inode, parent, type, name, data FROM tree WHERE name LIKE '%.conf'"
                )
                conf_rows = cur.fetchall()
            except sqlite3.OperationalError as e:
                if "no such table" in str(e).lower():
                    tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
                    self.log.warning("config.db has no 'tree' table; tables: %s", tables)
                else:
                    self.log.warning("config.db query failed: %s", e)
                conn.close()
                return False
            conn.close()

            inode_info: dict[int, tuple[int, str]] = {0: (0, "")}
            for row in all_rows:
                inode, parent, typ, name = row[0], row[1], row[2], row[3]
                inode_info[inode] = (parent, name or "")

            def path_of(inode: int) -> str:
                seen: set[int] = set()
                parts: list[str] = []
                i = inode
                while i and i in inode_info:
                    if i in seen:
                        break
                    seen.add(i)
                    parent, name = inode_info[i]
                    if name:
                        parts.append(name)
                    i = parent
                parts.reverse()
                return "/".join(parts)

            FILE_TYPES = (8, 32768)
            new_instances: dict[MACAddress, InstanceInfo] = {}
            cluster_nodes: dict[MACAddress, NodeID] = {}
            conf_count = 0
            paths_checked: list[str] = []
            include_cluster_nodes = bool(self._config and self._config.verify_remote_migration)

            for row in conf_rows:
                inode, parent, typ, name, data = row[0], row[1], row[2], row[3], row[4]
                if typ not in FILE_TYPES and (data is None or (isinstance(data, bytes) and len(data) == 0)):
                    continue
                conf_count += 1
                full_path = path_of(inode)
                path_node = _path_node(full_path)
                is_qemu = "qemu-server" in full_path
                is_lxc = "/lxc/" in full_path or full_path.startswith("lxc/")
                if not is_qemu and not is_lxc:
                    continue
                if isinstance(data, bytes):
                    data = data.decode("utf-8", errors="ignore")
                if not (data and data.strip()):
                    self.log.debug("skip path=%s reason=empty_data", full_path)
                    continue
                vmid = VMID(full_path.split("/")[-1].replace(".conf", ""))
                tags = self._parse_tags(data)
                inst_type: InstanceType = "lxc" if is_lxc else "qemu"
                nets_found = 0
                for line in data.splitlines():
                    if re.match(r"net\d+:", line):
                        for net in self._parse_net_line(line, is_lxc):
                            nets_found += 1
                            if include_cluster_nodes and path_node:
                                cluster_nodes[net.mac] = NodeID(path_node)
                            if path_node is not None and path_node != self._node_name:
                                continue
                            new_instances[net.mac] = InstanceInfo(
                                vmid=vmid,
                                type=inst_type,
                                bridge=net.bridge,
                                mac=net.mac,
                                vlan=net.vlan,
                                ip=net.ip,
                                tags=tags,
                            )
                if not nets_found:
                    paths_checked.append(full_path)
                if conf_count <= 20 and not nets_found:
                    self.log.debug("skip path=%s reason=no_net_bridge_mac", full_path)

            if len(new_instances) == 0 and conf_rows:
                self.log.info(
                    "config.db: conf_rows=%d instances=0 (check qemu-server/*.conf lxc/*.conf have netN: bridge=...,virtio=/mac/hwaddr=...)",
                    len(conf_rows),
                )
                if paths_checked:
                    self.log.debug("paths_checked (no net found): %s", paths_checked)

            self._store.update_all(new_instances)
            if include_cluster_nodes:
                self._store.update_cluster_nodes(cluster_nodes)
            else:
                self._store.update_cluster_nodes({})
            return True
        except sqlite3.OperationalError as e:
            self.log.warning("config.db unreadable: %s", e)
            return False
        except Exception as e:
            self.log.warning("config.db unreadable: %s", e)
            return False
