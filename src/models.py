# IPEntry, InstanceInfo, NetInterface, stores
from __future__ import annotations

import dataclasses
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, List, Optional, Tuple, get_args

from src.types import (
    BridgeName,
    EntryType,
    InstanceEntryType,
    InstanceType,
    IPv4Address,
    MACAddress,
    NodeID,
    UnmeshedEntryType,
    VMID,
    RT_SCOPE_HOST,
)


def is_snoopable(entry_type: Optional[str]) -> bool:
    """True for instance-backed types that the daemon actively snoops for.

    Instance types (qemu, lxc, vm) are the primary target of ARP/DHCP snooping
    and ownership arbitration. Non-instance types (bridge, foreign) are known
    via netlink or observed passively. Derived from InstanceEntryType.

    Args:
        entry_type: EntryType value or None.

    Returns:
        True when entry_type is an instance-backed type.
    """
    return entry_type in get_args(InstanceEntryType)


def is_unmeshed(entry_type: Optional[str]) -> bool:
    """True for entry types that are tracked locally and never broadcast to mesh.

    Stays in sync with UnmeshedEntryType via typing.get_args.

    Args:
        entry_type: EntryType value or None.

    Returns:
        True when entry_type must not be sent over the mesh.
    """
    return entry_type in get_args(UnmeshedEntryType)

# Store key: same IP can exist on multiple (bridge, vlan)
IPEntryKey = Tuple[IPv4Address, Optional[BridgeName], Optional[int]]


def normalize_vlan(v: Optional[int]) -> Optional[int]:
    """None for untagged."""
    return None if v is None or v == 0 else int(v)


def _entry_key(entry: "IPEntry") -> IPEntryKey:
    return (entry.ipv4, entry.bridge, normalize_vlan(entry.vlan))


def _key_to_str(k: IPEntryKey) -> str:
    ip, br, vlan = k
    return f"{ip}|{br or ''}|{vlan if vlan is not None else ''}"


def _str_to_key(s: str) -> Optional[IPEntryKey]:
    parts = s.split("|", 2)
    if len(parts) != 3:
        return None
    ip_s, br_s, vlan_s = parts
    if not ip_s:
        return None
    vlan: Optional[int] = None
    if vlan_s:
        try:
            vlan = int(vlan_s)
        except ValueError:
            return None
    return (IPv4Address(ip_s), BridgeName(br_s) if br_s else None, normalize_vlan(vlan))


def iter_ipentries_from_dict(data: dict[str, Any]) -> List[Tuple[IPEntryKey, IPEntry]]:
    """Parse dict of key_str -> entry_data into (IPEntryKey, IPEntry) pairs."""
    result: List[Tuple[IPEntryKey, IPEntry]] = []
    for key_str, entry_data in data.items():
        if not isinstance(entry_data, dict):
            continue
        key = _str_to_key(key_str)
        if key is None:
            try:
                key = (IPv4Address(key_str), None, None)
            except (ValueError, TypeError):
                continue
        try:
            entry = IPEntry.from_dict(entry_data)
        except (ValueError, KeyError, TypeError):
            continue
        result.append((key, entry))
    return result


@dataclass
class IPEntry:
    """Single IP->MAC entry. Keyed by (ipv4, bridge, vlan). scope host = local, not exported.

    expired: if set (timestamp when TTL elapsed), entry is inactive; removed from store after expired_entry_cleanup_sec.
    """

    ipv4: IPv4Address
    mac: MACAddress
    bridge: Optional[BridgeName] = None
    vmid: Optional[VMID] = None
    type: Optional[EntryType] = None
    vlan: Optional[int] = None
    node: Optional[NodeID] = None
    last_seen: Optional[float] = None
    last_received: Optional[float] = None
    snoop_origin: Optional[list[str]] = None
    expired: Optional[float] = None  # set when TTL elapsed; cleanup removes after config threshold
    scope: Optional[int] = None  # RT_SCOPE_*; host = local, not sent to mesh
    _owner_mutation_allowed: bool = field(default=False, init=False, repr=False, compare=False)

    def __setattr__(self, name: str, value: Any) -> None:
        """Guard node assignment outside change_owner()."""
        if name == "node":
            d = object.__getattribute__(self, "__dict__")
            if "node" not in d:
                object.__setattr__(self, name, value)
                return
            try:
                current = object.__getattribute__(self, "node")
            except AttributeError:
                current = None
            else:
                allow = bool(d.get("_owner_mutation_allowed", False))
                if current != value and not allow:
                    raise AttributeError("node is protected; use change_owner()")
        object.__setattr__(self, name, value)

    def is_local(self) -> bool:
        """True if scope is host (do not export to mesh)."""
        return self.scope == RT_SCOPE_HOST

    def to_mesh_dict(
        self,
        is_host_local: Optional[Callable[[IPv4Address], bool]] = None,
    ) -> Optional[dict[str, Any]]:
        """Dict for mesh broadcast; None for host-local, scope=host, or foreign."""
        if self.is_local():
            return None
        if is_unmeshed(self.type):
            return None
        if is_host_local is not None and is_host_local(self.ipv4):
            return None
        return self.to_dict()

    def to_dict(self) -> dict[str, Any]:
        """Full dict for persistence/mesh (all non-None fields)."""
        return {
            f.name: getattr(self, f.name)
            for f in dataclasses.fields(self)
            if not f.name.startswith("_")
            and getattr(self, f.name) is not None
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> IPEntry:
        """Parse from persisted/mesh dict. ipv4 and mac required."""
        d = {k: v for k, v in d.items() if not (isinstance(k, str) and k.startswith("_"))}
        ipv4 = d.get("ipv4") or d.get("ip")
        mac = d.get("mac")
        if not ipv4 or not mac:
            raise ValueError("IPEntry requires ipv4 and mac")
        entry = cls(
            ipv4=IPv4Address(str(ipv4)),
            mac=MACAddress(str(mac)),
            bridge=BridgeName(str(d["bridge"])) if d.get("bridge") else None,
            vmid=VMID(str(d["vmid"])) if d.get("vmid") else None,
            type=d.get("type"),
            vlan=int(d["vlan"]) if d.get("vlan") is not None else None,
            node=None,
            last_seen=float(d["last_seen"]) if d.get("last_seen") is not None else None,
            last_received=float(d["last_received"]) if d.get("last_received") is not None else None,
            snoop_origin=list(d["snoop_origin"]) if d.get("snoop_origin") else None,
            expired=float(d["expired"]) if d.get("expired") is not None else None,
            scope=int(d["scope"]) if d.get("scope") is not None else None,
        )
        if d.get("node"):
            entry.change_owner(NodeID(str(d["node"])))
        return entry

    def is_active(self, now: float, ttl: float) -> bool:
        """Check entry activity.

        Args:
            now: current timestamp.
            ttl: active time window in seconds.

        Returns:
            True when entry is not expired and seen within ttl.
        """
        if self.expired is not None:
            return False
        last = self.last_activity()
        return (now - last) <= ttl if last else False

    def is_owner(self, now: float, ttl: float, node_id: Optional[NodeID]) -> bool:
        """Check active owner match.

        Args:
            now: current timestamp.
            ttl: active time window in seconds.
            node_id: node to match ownership against.

        Returns:
            True when entry is active and owned by node_id.
        """
        return node_id is not None and self.node == node_id and self.is_active(now, ttl)

    def can_owner_change(
        self, now: float, node_id: Optional[NodeID], takeover_sec: float
    ) -> bool:
        """Check if ownership can change.

        Args:
            now: current timestamp.
            node_id: new owner candidate.
            takeover_sec: staleness window based on last_seen.

        Returns:
            True when ownership can move to node_id.
        """
        if node_id is None:
            return False
        if self.node is None or self.node == node_id:
            return True
        if self.expired is not None:
            return True
        last_seen = self.last_seen or 0.0
        if last_seen <= 0.0:
            return True
        return (now - last_seen) > max(0.0, takeover_sec)

    def change_owner(self, node_id: Optional[NodeID]) -> None:
        """Change owner node safely.

        Args:
            node_id: new owner node id.

        Returns:
            None.
        """
        object.__setattr__(self, "_owner_mutation_allowed", True)
        try:
            self.node = node_id
        finally:
            object.__setattr__(self, "_owner_mutation_allowed", False)

    def last_activity(self) -> float:
        return max(self.last_seen or 0.0, self.last_received or 0.0)

    def merge_from(self, other: IPEntry) -> None:
        for f in dataclasses.fields(other):
            if f.name.startswith("_"):
                continue
            val = getattr(other, f.name)
            if val is not None:
                if f.name == "node":
                    self.change_owner(val)
                else:
                    setattr(self, f.name, list(val) if isinstance(val, list) else val)

    def copy(self) -> IPEntry:
        c = dataclasses.replace(self)
        if c.snoop_origin is not None and isinstance(c.snoop_origin, list):
            c.snoop_origin = list(c.snoop_origin)
        elif c.snoop_origin is not None:
            c.snoop_origin = []
        return c


@dataclass
class InstanceInfo:
    """VM/LXC instance from Proxmox DB."""
    vmid: VMID
    type: InstanceType
    bridge: BridgeName
    mac: MACAddress
    vlan: Optional[int] = None
    ip: Optional[IPv4Address] = None
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "vmid": self.vmid,
            "type": self.type,
            "bridge": self.bridge,
        }
        if self.vlan is not None:
            d["vlan"] = self.vlan
        if self.ip is not None:
            d["config_ip"] = self.ip
        if self.tags:
            d["tags"] = self.tags
        return d


@dataclass
class NetInterface:
    """Network interface from VM config."""
    bridge: BridgeName
    mac: MACAddress
    vlan: Optional[int] = None
    ip: Optional[IPv4Address] = None


class IPEntryStore:
    """Thread-safe store keyed by (ip, bridge, vlan). Same IP on multiple VLANs = multiple entries."""

    def __init__(self) -> None:
        self._entries: dict[IPEntryKey, IPEntry] = {}
        self._lock = threading.Lock()

    def get(
        self,
        ip: IPv4Address,
        bridge: Optional[BridgeName] = None,
        vlan: Optional[int] = None,
    ) -> Optional[IPEntry]:
        key = (ip, bridge, normalize_vlan(vlan))
        with self._lock:
            entry = self._entries.get(key)
            return entry.copy() if entry else None

    def set(self, entry: IPEntry) -> None:
        key = _entry_key(entry)
        with self._lock:
            self._entries[key] = entry

    def update(self, key: IPEntryKey, **kwargs: Any) -> IPEntry:
        with self._lock:
            if key not in self._entries:
                raise KeyError(key)
            entry = self._entries[key]
            for k, v in kwargs.items():
                if k.startswith("_"):
                    continue
                if hasattr(entry, k):
                    if k == "node":
                        entry.change_owner(v)
                    else:
                        setattr(entry, k, v)
            return entry

    def get_or_create(
        self,
        ip: IPv4Address,
        mac: MACAddress,
        bridge: Optional[BridgeName] = None,
        vlan: Optional[int] = None,
    ) -> IPEntry:
        key = (ip, bridge, normalize_vlan(vlan))
        with self._lock:
            if key not in self._entries:
                self._entries[key] = IPEntry(
                    ipv4=ip,
                    mac=mac,
                    bridge=bridge,
                    vlan=normalize_vlan(vlan),
                )
            return self._entries[key]

    def items(self) -> list[tuple[IPEntryKey, IPEntry]]:
        with self._lock:
            return [(k, e.copy()) for k, e in self._entries.items()]

    def keys(self) -> list[IPEntryKey]:
        with self._lock:
            return list(self._entries.keys())

    def discard(self, key: IPEntryKey) -> None:
        """Remove entry by key (no-op if missing)."""
        with self._lock:
            self._entries.pop(key, None)

    def __contains__(self, key: IPEntryKey) -> bool:
        with self._lock:
            return key in self._entries

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            return {_key_to_str(k): e.to_dict() for k, e in self._entries.items()}

    def load_from_dict(self, data: dict[str, Any]) -> None:
        with self._lock:
            for key, entry in iter_ipentries_from_dict(data):
                self._entries[key] = entry

    def get_active(
        self, now: float, ttl: float, node_id: Optional[NodeID] = None
    ) -> dict[IPEntryKey, IPEntry]:
        with self._lock:
            result: dict[IPEntryKey, IPEntry] = {}
            for key, entry in self._entries.items():
                if entry.is_active(now, ttl):
                    if node_id is None or entry.is_owner(now, ttl, node_id):
                        result[key] = entry.copy()
            return result

    def get_entries_by_mac(self, mac: MACAddress) -> list[tuple[IPEntryKey, IPEntry]]:
        """All (key, entry) where entry.mac == mac (for ARP refresher)."""
        with self._lock:
            return [
                (k, e.copy())
                for k, e in self._entries.items()
                if e.mac.lower() == mac.lower()
            ]

    def get_known_vlan(self, ip: IPv4Address, bridge: Optional[BridgeName]) -> Optional[int]:
        """Return a known vlan for (ip, bridge) if any entry has one; else None.
        Used when packet has no Dot1Q so we don't overwrite with vlan=None."""
        with self._lock:
            for (eip, ebr, vlan) in self._entries:
                if eip == ip and ebr == bridge and vlan is not None:
                    return vlan
            return None

    def _iter_entries_for_bridge_ip(
        self, ip: IPv4Address, bridge: Optional[BridgeName]
    ) -> List[Tuple[IPEntryKey, IPEntry]]:
        """(ip, bridge) entries; call with lock held. Returns in-memory refs."""
        return [(k, e) for k, e in self._entries.items() if k[0] == ip and k[1] == bridge]

    def get_entries_for_bridge_ip(
        self, ip: IPv4Address, bridge: Optional[BridgeName]
    ) -> List[Tuple[IPEntryKey, IPEntry]]:
        """All (key, entry) for (ip, bridge); any vlan. Caller can check is_active/expired."""
        with self._lock:
            return [(k, e.copy()) for k, e in self._iter_entries_for_bridge_ip(ip, bridge)]

    def _pick_one_prefer_node(
        self, pairs: List[Tuple[IPEntryKey, IPEntry]], copy: bool = True
    ) -> Optional[IPEntry]:
        """Return entry with node if any, else first. Call with lock held."""
        first: Optional[IPEntry] = None
        for _k, e in pairs:
            if e.node:
                return e.copy() if copy else e
            if first is None:
                first = e
        return (first.copy() if first and copy else first) if first else None

    def get_any_active_for_bridge_ip(
        self,
        ip: IPv4Address,
        bridge: Optional[BridgeName],
        now: float,
        ttl: float,
    ) -> Optional[IPEntry]:
        """Any active entry for (ip, bridge); prefer one with node. For ARP reply regardless of vlan."""
        with self._lock:
            active = [(k, e) for k, e in self._iter_entries_for_bridge_ip(ip, bridge) if e.is_active(now, ttl)]
            return self._pick_one_prefer_node(active, copy=True)

    def get_any_for_bridge_ip(
        self, ip: IPv4Address, bridge: Optional[BridgeName]
    ) -> Optional[IPEntry]:
        """Any entry for (ip, bridge); prefer one with node. For responder node lookup when vlan mismatches."""
        with self._lock:
            pairs = self._iter_entries_for_bridge_ip(ip, bridge)
            return self._pick_one_prefer_node(pairs, copy=True)


class InstanceStore:
    """Thread-safe instance store."""

    def __init__(self) -> None:
        self._instances: dict[MACAddress, InstanceInfo] = {}
        self._cluster_nodes: dict[MACAddress, NodeID] = {}
        self._lock = threading.Lock()

    def get(self, mac: MACAddress) -> Optional[InstanceInfo]:
        with self._lock:
            return self._instances.get(mac)

    def set(self, mac: MACAddress, info: InstanceInfo) -> None:
        with self._lock:
            self._instances[mac] = info

    def clear(self) -> None:
        with self._lock:
            self._instances.clear()
            self._cluster_nodes.clear()

    def update_all(self, instances: dict[MACAddress, InstanceInfo]) -> None:
        """Replace local-node instances.

        Args:
            instances: Mapping of MAC to local node instance info.

        Returns:
            None.
        """
        with self._lock:
            self._instances = dict(instances)

    def update_cluster_nodes(self, cluster_nodes: dict[MACAddress, NodeID]) -> None:
        """Replace cluster MAC->node mapping.

        Args:
            cluster_nodes: Mapping of MAC to owner node id.

        Returns:
            None.
        """
        with self._lock:
            self._cluster_nodes = dict(cluster_nodes)

    def get_node_for_mac(self, mac: MACAddress) -> Optional[NodeID]:
        """Get owner node for MAC from cluster view.

        Args:
            mac: MAC address key.

        Returns:
            Owner node id if known, else None.
        """
        with self._lock:
            return self._cluster_nodes.get(mac)

    def items(self) -> list[tuple[MACAddress, InstanceInfo]]:
        with self._lock:
            return list(self._instances.items())

    def __contains__(self, mac: MACAddress) -> bool:
        with self._lock:
            return mac in self._instances

    def __len__(self) -> int:
        with self._lock:
            return len(self._instances)

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            return {mac: info.to_dict() for mac, info in self._instances.items()}
