import socket
import threading
import time
import json
import hmac
import re
import logging
from typing import Any, Optional, Dict, Tuple, Callable

from src.types import NodeID, IPv4Address, BridgeName, MACAddress
from src.config import Config, SO_BINDTODEVICE
from src.models import IPEntryStore, IPEntry, _key_to_str, _str_to_key, iter_ipentries_from_dict
from src.netlink import NetlinkInfo

# --- PayloadValidator ---------------------------------------------------------

class PayloadValidator:
    """Validate incoming mesh payloads against limits."""

    @staticmethod
    def check_depth(obj: Any, max_depth: int, depth: int = 0) -> bool:
        """True if obj nesting depth <= max_depth."""
        if depth > max_depth:
            return False
        if isinstance(obj, dict):
            return all(PayloadValidator.check_depth(v, max_depth, depth + 1) for v in obj.values())
        if isinstance(obj, list):
            return all(PayloadValidator.check_depth(i, max_depth, depth + 1) for i in obj)
        return True

    @staticmethod
    def is_valid(
        raw: Any,
        max_keys: int = 1000,
        max_key_len: int = 64,
        max_depth: int = 3,
    ) -> bool:
        """True if payload passes all limits (keys, key length, depth)."""
        if not isinstance(raw, dict):
            return False
        if len(raw) > max_keys:
            return False
        for k in raw:
            if not isinstance(k, str) or len(k) > max_key_len:
                return False
        return PayloadValidator.check_depth(raw, max_depth)


# --- HMAC Signing ------------------------------------------------------------
HMAC_HEXLEN = 64
SIGN_PLACEHOLDER = "X" * HMAC_HEXLEN


class HMACSigner:
    """HMAC-SHA256 signing for mesh payloads."""

    @staticmethod
    def sign(payload: dict[str, Any], key: bytes) -> str:
        """Sign payload; return JSON string with _sign field."""
        out = dict(payload)
        out["_sign"] = SIGN_PLACEHOLDER
        json_str = json.dumps(out, sort_keys=True)
        sig = hmac.new(key, json_str.encode("utf-8"), "sha256").hexdigest()
        return json_str.replace(SIGN_PLACEHOLDER, sig, 1)

    @staticmethod
    def verify_raw(raw_str: str, key: bytes) -> bool:
        """True if _sign in raw_str matches expected HMAC. Use before parsing."""
        m = re.search(r'"_sign"\s*:\s*"([0-9a-fA-F]{64})"', raw_str)
        if not m:
            return False
        got = m.group(1)
        canonical = raw_str[: m.start(1)] + SIGN_PLACEHOLDER + raw_str[m.end(1) :]
        expected = hmac.new(key, canonical.encode("utf-8"), "sha256").hexdigest()
        return hmac.compare_digest(expected, got)


# --- MeshBroadcaster ---------------------------------------------------------


class MeshBroadcaster:
    """UDP broadcast JSON of local IP entries; receive and merge into IPEntryStore."""

    def __init__(
        self,
        entries: IPEntryStore,
        log: logging.Logger,
        config: Config,
        node_id: str = "",
        netlink: Optional[NetlinkInfo] = None,
        is_remote_migration_confirmed: Optional[Callable[[MACAddress, NodeID], bool]] = None,
        on_owner_change: Optional[
            Callable[[IPv4Address, BridgeName, Optional[int], Optional[NodeID], Optional[NodeID]], None]
        ] = None,
    ) -> None:
        self.config = config
        self.broadcast_iface = config.broadcast_iface
        self.port = config.mesh_port
        self.entries = entries
        self.log = log
        self.node_id = node_id or socket.gethostname()
        self._netlink = netlink
        self.ttl = config.mesh_ttl
        self.send_on_change = config.mesh_send_on_change
        self.recv_dedup_sec = max(0.0, config.mesh_recv_dedup_sec)
        self.send_max_interval = max(0.0, config.mesh_send_max_interval)
        self.keepalive_interval = max(0.0, config.mesh_keepalive_interval)
        self.sign_key = config.get_sign_key()
        self._is_remote_migration_confirmed = is_remote_migration_confirmed
        self._on_owner_change = on_owner_change
        # Payload limits from config
        self._max_size = config.mesh_recv_max_size
        self._max_keys = config.mesh_recv_max_keys
        self._max_depth = config.mesh_recv_max_depth
        self._max_key_len = config.mesh_recv_max_key_len
        # State
        self._sock: Optional[socket.socket] = None
        self._stop = threading.Event()
        self._recv_thread: Optional[threading.Thread] = None
        self._last_sent_fingerprint: Optional[str] = None
        self._last_send_time: float = 0
        self._last_keepalive_time: float = 0
        self._start_time: float = 0
        self._recv_dedup: dict[str, tuple[str, float]] = {}
        self._node_last_seen: dict[str, float] = {}  # node_id -> last recv time (for list-remote)
        self._last_recv_any: float = 0  # last time any peer message received (for silence watchdog)
        self._node_uptime: dict[str, int] = {}  # node_id -> last known uptime (restart detection)
        self._send_immediately = False  # set when remote restarted, then send_once() forces send
        self._last_restart_send_time: float = 0  # throttle restart-triggered send to once per 60s
        self._restart_send_interval: float = 60.0
        self._rx_count: int = 0
        self._tx_count: int = 0
        self._rx_invalid_count: int = 0
        self._migration_remote_refused_count: int = 0
        self._migration_remote_confirmed_count: int = 0

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
        if self._recv_thread and self._recv_thread.is_alive():
            self._recv_thread.join(timeout=2)

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if self.broadcast_iface:
            try:
                self._sock.setsockopt(
                    socket.SOL_SOCKET,
                    SO_BINDTODEVICE,
                    (self.broadcast_iface.encode("utf-8") + b"\0"),
                )
            except OSError as e:
                self.log.warning("MeshBroadcaster SO_BINDTODEVICE %s: %s", self.broadcast_iface, e)
        try:
            self._sock.bind(("", self.port))
        except OSError as e:
            self.log.warning("MeshBroadcaster bind: %s", e)
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
            return
        self._sock.settimeout(1.0)
        self._start_time = time.time()
        self._last_recv_any = time.time()  # grace after restart so watchdog does not fire immediately
        self._recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
        self._recv_thread.start()

    def get_node_last_seen(self) -> dict[str, float]:
        """Return copy of node_id -> last recv time (for persistence / list-remote)."""
        return dict(self._node_last_seen)

    def get_last_recv_any(self) -> float:
        """Last time any peer message was received; 0 if never (for silence watchdog)."""
        return self._last_recv_any

    def get_mesh_counters(self) -> dict[str, int]:
        """Return mesh traffic counters.

        Args:
            None.

        Returns:
            Dict with keys: rx, tx, rx_invalid.
        """
        return {
            "rx": self._rx_count,
            "tx": self._tx_count,
            "rx_invalid": self._rx_invalid_count,
        }

    def get_migration_counters(self) -> dict[str, int]:
        """Return remote migration confirmation counters.

        Args:
            None.

        Returns:
            Dict with keys: remote_confirmed, remote_refused.
        """
        return {
            "remote_confirmed": self._migration_remote_confirmed_count,
            "remote_refused": self._migration_remote_refused_count,
        }

    def _recv_loop(self) -> None:
        """Receive broadcast JSON; merge into entries store."""
        while self._sock and not self._stop.is_set():
            try:
                data, sender = self._sock.recvfrom(65535)
            except (OSError, socket.timeout):
                continue
            self._handle_recv(data, sender)

    def _handle_recv(self, data: bytes, sender: Any) -> None:
        """Handle single received datagram from mesh socket."""
        self._rx_count += 1
        sender_node = sender[0] if isinstance(sender, tuple) else str(sender)
        node = sender_node
        now = time.time()
        debug = self.log.isEnabledFor(logging.DEBUG)
        try:
            raw = self._decode_and_validate_payload(sender_node, data, now, debug)
            if raw is None:
                return
            node = self._resolve_payload_node(sender_node, raw)
            if not self._update_peer_uptime(node, raw, now, debug):
                return
            if self._is_keepalive_only(node, raw, debug):
                return
            if not self._is_foreign_node(node, debug):
                return
            if not self._dedup_payload(node, raw, now, debug):
                return
            merged = self._merge_payload_entries(node, raw, now)
            if merged:
                self.log.info("mesh recv from=%s entries=%d", node, merged)
                if debug and raw:
                    pairs = ", ".join(
                        f"{k}=>{e.get('mac', '?')}" for k, e in raw.items() if isinstance(e, dict)
                    )
                    self.log.debug("mesh recv from=%s ip=>mac: %s", node, pairs)
        except json.JSONDecodeError as e:
            self._rx_invalid_count += 1
            if debug:
                self.log.debug("mesh recv from=%s ignored: invalid JSON: %s", node, e)
        except (UnicodeDecodeError, ValueError) as e:
            self._rx_invalid_count += 1
            if debug:
                self.log.debug("mesh recv from=%s ignored: decode error: %s", node, e)
        except (RecursionError, MemoryError) as e:
            self._rx_invalid_count += 1
            self.log.warning("mesh recv parse error from %s: %s", sender, e)
        except Exception as e:
            self._rx_invalid_count += 1
            self.log.warning("mesh recv unexpected error from=%s: %s", node, e, exc_info=True)

    def _resolve_payload_node(self, sender_node: str, raw: dict[str, Any]) -> str:
        """Pick node identity from payload metadata."""
        payload_node = raw.get("_node")
        if isinstance(payload_node, str) and payload_node.strip():
            return payload_node.strip()
        return sender_node

    def _decode_and_validate_payload(
        self,
        node: str,
        data: bytes,
        now: float,
        debug: bool,
    ) -> Optional[dict[str, Any]]:
        """Decode JSON payload, enforce size/signature/shape limits."""
        if len(data) > self._max_size:
            if debug:
                self.log.debug(
                    "mesh recv from=%s ignored: oversized (%d > %d)",
                    node,
                    len(data),
                    self._max_size,
                )
            return None
        raw_str = data.decode("utf-8")
        if self.sign_key:
            if not HMACSigner.verify_raw(raw_str, self.sign_key):
                self._rx_invalid_count += 1
                self.log.info("mesh recv bad signature from %s", node)
                if debug:
                    self.log.debug("mesh recv from=%s ignored: bad signature", node)
                return None
        raw = json.loads(raw_str)
        if not isinstance(raw, dict):
            self._rx_invalid_count += 1
            if debug:
                self.log.debug("mesh recv from=%s ignored: not dict", node)
            return None
        if not PayloadValidator.is_valid(raw, self._max_keys, self._max_key_len, self._max_depth):
            self._rx_invalid_count += 1
            if debug:
                self.log.debug("mesh recv from=%s ignored: keys/depth/len limit", node)
            return None
        return raw

    def _update_peer_uptime(
        self,
        node: str,
        raw: dict[str, Any],
        now: float,
        debug: bool,
    ) -> bool:
        """Update peer last-seen and uptime; trigger restart send when needed."""
        if node != self.node_id:
            self._node_last_seen[node] = now
            self._last_recv_any = now
            uptime_val = raw.get("_uptime")
            if isinstance(uptime_val, int):
                old_uptime = self._node_uptime.get(node)
                self._node_uptime[node] = uptime_val
                if old_uptime is not None and uptime_val < old_uptime:
                    if (now - self._last_restart_send_time) >= self._restart_send_interval:
                        self._send_immediately = True
                        self.send_once()
                        self.log.info(
                            "mesh node %s restarted (uptime %d -> %d), sent update",
                            node,
                            old_uptime,
                            uptime_val,
                        )
        return True

    def _is_keepalive_only(self, node: str, raw: dict[str, Any], debug: bool) -> bool:
        """True when payload only contains keepalive metadata."""
        if set(raw.keys()) <= {"_node", "_uptime", "_sign"}:
            if debug:
                self.log.debug("mesh recv from=%s ignored: keepalive only", node)
            return True
        return False

    def _is_foreign_node(self, node: str, debug: bool) -> bool:
        """False when payload originates from this node_id."""
        if node == self.node_id:
            if debug:
                self.log.debug("mesh recv from=%s ignored: our message", node)
            return False
        return True

    def _dedup_payload(
        self,
        node: str,
        raw: dict[str, Any],
        now: float,
        debug: bool,
    ) -> bool:
        """Return False when payload is duplicate within recv_dedup_sec window."""
        if self.recv_dedup_sec <= 0:
            return True
        items = [
            (k, (e.get("ipv4"), e.get("last_seen")))
            for k, e in raw.items()
            if isinstance(e, dict)
        ]
        fp = json.dumps(sorted(items), default=str)
        prev = self._recv_dedup.get(node)
        if prev and prev[0] == fp and (now - prev[1]) < self.recv_dedup_sec:
            if debug:
                self.log.debug("mesh recv from=%s ignored: dedup", node)
            return False
        self._recv_dedup[node] = (fp, now)
        return True

    def _merge_payload_entries(
        self,
        node: str,
        raw: dict[str, Any],
        now: float,
    ) -> int:
        """Merge validated payload entries into IPEntryStore; return merged count."""
        merged = 0
        sender = NodeID(node)
        seen_keys: set[tuple[IPv4Address, Optional[BridgeName], Optional[int]]] = set()
        passive_set = frozenset(self.config.passive_bridges)
        active_bn = BridgeName(self.config.active_bridge)
        for entry_key, received in iter_ipentries_from_dict(raw):
            ip_k, br_k, vlan_k = entry_key
            if br_k is not None and str(br_k) in passive_set:
                br_k = active_bn
                entry_key = (ip_k, br_k, vlan_k)
                received.bridge = br_k
            seen_keys.add(entry_key)
            if self._netlink and self._netlink.is_bridge_mac(received.mac):
                continue
            existing = self.entries.get(entry_key[0], entry_key[1], entry_key[2])
            # Authorise sender for this MAC on create or owner change. Single
            # confirmation point: the callback decides with local authority
            # (cheap, always-on) and optionally cluster authority (when
            # verify_remote_migration=True). Also runs for new entries so
            # remote-owned entries for locally hosted MACs are refused too.
            if self._is_remote_migration_confirmed is not None and (
                existing is None or existing.node != sender
            ):
                self._migration_remote_confirmed_count += 1
                if not self._is_remote_migration_confirmed(received.mac, sender):
                    self._migration_remote_refused_count += 1
                    self.log.error(
                        "ALERT migration denied ip=%s mac=%s sender=%s reason=remote_confirm_failed",
                        entry_key[0],
                        received.mac,
                        sender,
                    )
                    continue
            received.change_owner(sender)
            received.last_received = now
            received.bridge = entry_key[1] or received.bridge
            received.vlan = entry_key[2] if entry_key[2] is not None else received.vlan
            if existing:
                owner_changed = existing.node != received.node
                if existing.last_seen and (
                    not received.last_seen or existing.last_seen > received.last_seen
                ):
                    received.last_seen = existing.last_seen
                if owner_changed and received.node is not None:
                    # Keep owner+mac together.
                    if self._on_owner_change is not None:
                        bridge_val = entry_key[1] or received.bridge or existing.bridge
                        if bridge_val is not None:
                            self._on_owner_change(
                                entry_key[0],
                                bridge_val,
                                entry_key[2],
                                existing.node,
                                received.node,
                            )
                    existing.change_owner(received.node)
                    existing.mac = received.mac
                existing.expired = None
                existing.merge_from(received)
                self.entries.set(existing)
            else:
                received.expired = None
                self.entries.set(received)
            merged += 1
        # Sender omitted previously owned keys: mark them expired.
        # This relies on sender payloads being full snapshots for that node.
        for key, entry in self.entries.items():
            if entry.node != sender:
                continue
            if key in seen_keys:
                continue
            if entry.expired is not None:
                continue
            try:
                self.entries.update(key, expired=now)
            except KeyError:
                continue
            self.log.debug("db ip expired remote ip=%s from=%s (missing in payload)", key[0], node)
        return merged

    def send_once(self) -> None:
        """Broadcast active entries (node==self). Entry decides export via to_mesh_dict()."""
        now = time.time()
        force_send = self._send_immediately
        if force_send:
            self._send_immediately = False
            self._last_restart_send_time = now
        active = self.entries.get_active(now, self.ttl, NodeID(self.node_id))
        active_dict: dict[str, dict[str, Any]] = {}
        # Always send full active snapshot for this node.
        # Receivers expire sender-owned keys omitted from payload.
        is_host_local = self._netlink.is_host_local if self._netlink else None
        for key, entry in active.items():
            d = entry.to_mesh_dict(is_host_local=is_host_local)
            if d is not None:
                active_dict[_key_to_str(key)] = d
        uptime = int(now - self._start_time)
        active_dict["_node"] = self.node_id
        active_dict["_uptime"] = uptime
        fingerprint = json.dumps(sorted((k, (d.get("ipv4"), d.get("last_seen"))) for k, d in active_dict.items() if k not in ("_node", "_uptime")), default=str)

        changed_payload = fingerprint != self._last_sent_fingerprint
        elapsed_since_send = now - self._last_send_time
        due_to_max_interval = (
            self.send_max_interval > 0
            and self._last_send_time > 0
            and elapsed_since_send >= self.send_max_interval
        )
        if (
            not force_send
            and self.send_on_change
            and not changed_payload
            and not due_to_max_interval
        ):
            return

        if self.sign_key:
            payload = HMACSigner.sign(active_dict, self.sign_key).encode("utf-8")
        else:
            payload = json.dumps(active_dict, sort_keys=True).encode("utf-8")

        if not self._sock:
            return
        if not active_dict:
            if self.keepalive_interval <= 0:
                return
            if (now - self._last_keepalive_time) < self.keepalive_interval:
                return
            uptime = int(now - self._start_time)
            keepalive = {"_node": self.node_id, "_uptime": uptime}
            if self.sign_key:
                payload = HMACSigner.sign(keepalive, self.sign_key).encode("utf-8")
            else:
                payload = json.dumps(keepalive, sort_keys=True).encode("utf-8")
            try:
                self._sock.sendto(payload, ("<broadcast>", self.port))
                self._tx_count += 1
                self._last_keepalive_time = now
                self.log.debug("mesh keepalive origin=%s uptime=%d", self.node_id, uptime)
            except OSError as e:
                self.log.debug("MeshBroadcaster keepalive: %s", e)
            return
        try:
            self._sock.sendto(payload, ("<broadcast>", self.port))
            self._tx_count += 1
            self._last_sent_fingerprint = fingerprint
            self._last_send_time = now
            entry_count = sum(1 for k in active_dict if k not in ("_node", "_uptime"))
            self.log.info("mesh send origin=%s entries=%d", self.node_id, entry_count)
            if self.log.isEnabledFor(logging.DEBUG) and active_dict:
                pairs = ", ".join(f"{k}=>{d.get('mac', '?')}" for k, d in active_dict.items() if isinstance(d, dict))
                self.log.debug("mesh send ip=>mac: %s", pairs)
        except OSError as e:
            self.log.debug("MeshBroadcaster send: %s", e)
