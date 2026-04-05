# Central config and process/registry helpers
import argparse
import dataclasses
import re
import socket
import sys
from dataclasses import dataclass, field
from typing import Any, Optional

from src.types import IPRoute


def parse_vlan_list(s: Optional[str]) -> frozenset[int]:
    """Parse '20,30-50,99' into frozenset of VLAN IDs. Empty/None -> empty set. 0 = untagged."""
    out: set[int] = set()
    if not s or not s.strip():
        return frozenset()
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, _, hi = part.partition("-")
            try:
                a, b = int(lo.strip()), int(hi.strip())
                if a <= b:
                    out.update(range(a, b + 1))
            except ValueError:
                continue
        else:
            try:
                out.add(int(part))
            except ValueError:
                continue
    return frozenset(out)

LIB_FILE = "/usr/local/lib/ovs-flow-lib.sh"
REGISTRY_FILE_DEFAULT = "/run/ovs-flow-registry"
LOCK_FILE_DEFAULT = "/var/lock/ovs-flow-registry.lock"
COOKIE_BASE = 0x10000000
COOKIE_STEP = 0x10000000
COOKIE_FALLBACK = "0x0fff0001"
SCRIPT_NAME = "ovs-vm-arbiter.py"
ROLE = "proxmox"
STATE_FILE = "state.json"
SO_BINDTODEVICE = 25
OFPP_LOCAL = 65534
SYSLOG_PROCNAME = b"ovs-vm-arbiter.py"

_CONFIG_ARG_RENAMES: dict[str, str] = {"mesh_port": "port", "exclude_subnets": "exclude_subnet"}
_CONFIG_COALESCE_EMPTY: set[str] = {"exclude_subnets", "arp_responder_local_iface"}

LIST_MODE_DB = 1 << 0
LIST_MODE_PVE_DB = 1 << 1
LIST_MODE_PEERS = 1 << 2
LIST_MODE_NEIGH = 1 << 3
LIST_MODE_REMOTE_IPS = 1 << 4
LIST_MODE_LOCAL_IPS = 1 << 5
LIST_MODE_REFRESHERS = 1 << 6
LIST_MODE_RESPONDERS = 1 << 7
LIST_MODE_VLANS = 1 << 8
LIST_MODE_FDB = 1 << 9


@dataclass
class Config:
    """Central configuration — all settings in one place.

    Expiry: mesh_ttl = entry TTL; expiry_grace_sec = grace before first expire; expired_entry_cleanup_sec = remove from store N sec after expiry (0=off, default 14h).
    """

    bridges: list[str] = field(default_factory=lambda: ["vmbr0"])
    db_path: str = "/var/lib/pve-cluster/config.db"
    state_dir: str = "/var/lib/ovs-vm-arbiter"
    no_load_state: bool = False
    load_state_max_age_sec: float = 60.0  # skip load if state file older; 0 = no check
    mesh_port: int = 9876
    mesh_ttl: float = 990.0
    mesh_interval: float = 3.0
    mesh_send_on_change: bool = True
    mesh_recv_dedup_sec: float = 0.0
    mesh_send_max_interval: float = 99.0
    mesh_keepalive_interval: float = 59.0
    snoop_takeover_sec: Optional[float] = None  # local takeover age; None = mesh_ttl/10
    verify_local_migration: bool = True
    verify_remote_migration: bool = False
    mesh_silence_restart: bool = True  # warn + restart mesh if no recv for 10*keepalive; False=disable
    mesh_sign_key: Optional[str] = None
    mesh_sign_key_file: Optional[str] = None
    mesh_recv_max_size: int = 32 * 1024
    mesh_recv_max_keys: int = 1000
    mesh_recv_max_depth: int = 3
    mesh_recv_max_key_len: int = 64
    broadcast_iface: Optional[str] = None
    node: Optional[str] = None
    snoop_bridge: bool = True
    snoop_host_local: bool = True
    snoop_vlans: Optional[str] = None  # raw CLI e.g. "20,30-50,99"
    no_snoop_vlans: Optional[str] = None
    snoop_vlan_set: Optional[frozenset[int]] = None  # parsed; None = no allow filter; 0 = untagged
    no_snoop_vlan_set: frozenset[int] = field(default_factory=frozenset)  # parsed block list
    exclude_subnets: list[str] = field(default_factory=list)
    flood_min_interval: float = 5.0
    arp_reply: bool = True
    arp_reinject: bool = False
    arp_reply_local_fallback: bool = False
    arp_reply_local: bool = True
    arp_reply_strict_vlan: bool = True  # reply only when request vlan matches snooped vlan
    arp_reply_no_vlan: bool = False  # reply when request has no vlan (untagged)
    arp_reply_remote_vlan: Optional[int] = None  # for remote IPs reply on this vlan (tunnel)
    arp_reply_localize_vlan: bool = True  # when True, use entry vlan for remote IPs if vlan is local
    arp_reply_set_register: int = 0  # 0=off; else load value into NXM_NX_REG0[] on ARP reply packet-out
    arp_refresh: bool = False
    arp_refresh_interval: float = 250.0
    arp_peer_timeout: float = 86400.0
    arp_peer_limit: int = 5
    arp_global_limit: int = 200
    arp_flood_threshold: int = 50
    arp_responder: bool = False
    arp_responder_priority: int = 1001
    arp_responder_mirror: bool = True
    arp_responder_forward_normal: bool = False
    arp_responder_learning: bool = True
    arp_responder_sync_interval: float = 10.0
    arp_responder_local_iface: list[str] = field(default_factory=list)
    arp_responder_reply_local: bool = False  # resolved in from_args: None → arp_reply_local
    arp_responder_vlan_register: Optional[int] = None  # None=use vlan_tci; 0-7=match NXM_NX_REG<n>[]=vlan (workaround OVS not seeing 802.1Q)
    of_install: bool = True
    of_table: int = 0
    of_priority: int = 999
    of_verify_interval: float = 90.0
    of_action: str = "NORMAL"
    of_arp_action: Optional[str] = None
    of_dhcp_action: Optional[str] = None
    packet_out_max_queue: int = 10
    db_debounce_sec: float = 5.0
    db_force_debounce_sec: float = 1.0
    db_periodic_sec: float = 60.0
    db_retry_sec: float = 60.0
    db_unavail_log_sec: float = 300.0
    db_stat_optimization: bool = False
    host_local_cache_ttl: float = 60.0
    bridge_subnets_cache_ttl: float = 60.0
    ovs_node_port_cache_ttl: float = 60.0
    expiry_grace_sec: float = 60.0
    expired_entry_cleanup_sec: float = 50400.0  # delete from db N sec after expiry (14h default; 0=off)
    main_loop_interval: float = 2.0
    save_interval: float = 13.0
    expiry_check_interval: float = 30.0
    snoop_silence_warn_after_sec: float = 3600.0  # first WARNING after this much snoop silence; 0=off
    snoop_silence_warn_interval_sec: float = 3600.0  # repeat WARNING; 0=once per episode
    snoop_silence_restart_sec: float = 86400.0  # ERROR+exit after this much silence; 0=off
    debug_flags: int = 0  # bitmask for fine-grained debug (e.g. ARP reply)
    debug: bool = False
    log_level: str = "warning"
    list_db: bool = False
    list_pve_db: bool = False
    list_peers: bool = False
    list_neigh: bool = False
    list_remote_ips: bool = False
    list_local_ips: bool = False
    list_refreshers: bool = False
    list_responders: bool = False
    list_vlans: bool = False
    list_fdb: Optional[str] = None  # None=off; "" or bridge name
    list_mode_mask: int = 0
    ping_neighbours_interval: float = 0.0  # 0=disabled; else ping mesh neighbours every SEC
    migration_invalidates_fdb: bool = True  # invalidate FDB+ARP on ownership change
    prometheus_metrics: bool = False
    prometheus_metrics_extra: bool = False
    prometheus_port: int = 9108
    prometheus_host: str = "localhost"

    def get_sign_key(self) -> Optional[bytes]:
        if self.mesh_sign_key_file:
            try:
                with open(self.mesh_sign_key_file, "r") as f:
                    key = (f.readline() or "").strip()
                    if key:
                        return key.encode("utf-8")
            except OSError:
                pass
        if self.mesh_sign_key:
            return self.mesh_sign_key.encode("utf-8")
        return None

    def is_debug(self) -> bool:
        return self.debug or self.log_level == "debug"

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> "Config":
        kwargs: dict[str, Any] = {}
        for f in dataclasses.fields(cls):
            if f.name.startswith("_"):
                continue
            arg_name = _CONFIG_ARG_RENAMES.get(f.name, f.name)
            val = getattr(args, arg_name, None)
            if f.name in _CONFIG_COALESCE_EMPTY and val is None:
                val = []
            kwargs[f.name] = val
        # Default broadcast_iface to first bridge when not provided
        if kwargs.get("broadcast_iface") is None:
            bridges = kwargs.get("bridges") or []
            if bridges:
                kwargs["broadcast_iface"] = bridges[0]
        # default arp_responder_reply_local to arp_reply_local when not set
        if kwargs.get("arp_responder_reply_local") is None:
            kwargs["arp_responder_reply_local"] = kwargs["arp_reply_local"]
        # parse snoop VLAN lists into sets
        if kwargs.get("snoop_vlans"):
            kwargs["snoop_vlan_set"] = parse_vlan_list(kwargs["snoop_vlans"])
        else:
            kwargs["snoop_vlan_set"] = None
        kwargs["no_snoop_vlan_set"] = parse_vlan_list(kwargs.get("no_snoop_vlans") or "")
        if kwargs.get("snoop_takeover_sec") is None:
            mesh_ttl = float(kwargs.get("mesh_ttl") or cls.mesh_ttl)
            kwargs["snoop_takeover_sec"] = max(0.0, mesh_ttl / 10.0)
        mode_mask = 0
        if kwargs.get("list_db"):
            mode_mask |= LIST_MODE_DB
        if kwargs.get("list_pve_db"):
            mode_mask |= LIST_MODE_PVE_DB
        if kwargs.get("list_peers"):
            mode_mask |= LIST_MODE_PEERS
        if kwargs.get("list_neigh"):
            mode_mask |= LIST_MODE_NEIGH
        if kwargs.get("list_remote_ips"):
            mode_mask |= LIST_MODE_REMOTE_IPS
        if kwargs.get("list_local_ips"):
            mode_mask |= LIST_MODE_LOCAL_IPS
        if kwargs.get("list_refreshers"):
            mode_mask |= LIST_MODE_REFRESHERS
        if kwargs.get("list_responders"):
            mode_mask |= LIST_MODE_RESPONDERS
        if kwargs.get("list_vlans"):
            mode_mask |= LIST_MODE_VLANS
        if kwargs.get("list_fdb") is not None:
            mode_mask |= LIST_MODE_FDB
        kwargs["list_mode_mask"] = mode_mask
        return cls(**kwargs)


_config: Optional[Config] = None


def get_config() -> Config:
    if _config is None:
        raise RuntimeError("Config not initialized")
    return _config


def _ovs_options_remote_ip(val: Any) -> Optional[str]:
    if not isinstance(val, list) or len(val) < 2 or val[0] != "map":
        return None
    inner = val[1]
    if not isinstance(inner, list):
        return None
    for pair in inner:
        if isinstance(pair, (list, tuple)) and len(pair) >= 2 and pair[0] == "remote_ip":
            return str(pair[1])
    return None


def set_process_name(name: bytes) -> None:
    if not name or len(name) > 15:
        return
    try:
        if sys.platform == "linux":
            libc = __import__("ctypes").CDLL(None)
            PR_SET_NAME = 15
            libc.prctl(PR_SET_NAME, name, 0, 0, 0)
    except Exception:
        pass


def build_process_title(argv: list[str], base: str = "ovs-vm-arbiter", max_len: int = 255) -> str:
    if not argv or (len(argv) == 1 and not argv[0].strip()):
        return base
    rest = " ".join(argv)
    title = f"{base} {rest}" if rest else base
    return title[:max_len] if len(title) > max_len else title


def get_node_ip(broadcast_iface: Optional[str]) -> Optional[str]:
    if not IPRoute:
        return None
    try:
        ipr = IPRoute()
        idx: Optional[int] = None
        if broadcast_iface:
            lookup = ipr.link_lookup(ifname=broadcast_iface)
            if lookup:
                idx = lookup[0]
        if idx is None:
            for route in ipr.get_routes(family=2):
                if route.get("dst_len") == 0:
                    oif = route.get_attr("RTA_OIF")
                    if oif is not None:
                        idx = oif
                        break
        if idx is None:
            ipr.close()
            return None
        for msg in ipr.get_addr(index=idx):
            if msg.get("family", 0) != 2:
                continue
            addr = msg.get_attr("IFA_ADDRESS")
            if addr:
                ipr.close()
                return addr
        ipr.close()
    except Exception:
        pass
    return None


def get_local_mesh_ip(config: Config) -> str:
    """Resolve local mesh node identifier.

    Args:
        config: Config instance with node and broadcast_iface.

    Returns:
        Node identifier for mesh, preferring explicit node, then broadcast_iface IP when set, then hostname.
    """
    if config.node:
        return str(config.node)
    if config.broadcast_iface:
        ip = get_node_ip(config.broadcast_iface)
        if ip:
            return str(ip)
    return socket.gethostname()


def _get_registry_paths() -> tuple[Optional[str], str]:
    reg = None
    try:
        with open(LIB_FILE, "r") as f:
            for line in f:
                m = re.search(r'^REGISTRY_FILE=["\']([^"\']+)["\']', line)
                if m:
                    reg = m.group(1)
                    break
    except (FileNotFoundError, OSError):
        pass
    reg = reg or REGISTRY_FILE_DEFAULT
    lock = LOCK_FILE_DEFAULT
    return reg, lock


def _set_global_config(c: Optional[Config]) -> None:
    global _config
    _config = c


REGISTRY_FILE, LOCK_FILE = _get_registry_paths()
