# OVSManager: ovs-vsctl, TTL-cached remote_ip and local discovery
from __future__ import annotations

import logging
import time
from typing import Any, Callable, Optional

from src.config import Config, _ovs_options_remote_ip
from src.ovs_cmd import OVSCommand
from src.ttl_cache import TTLCache
from src.types import BridgeName, InterfaceName, NodeID, OFPort

PortInfo = tuple[OFPort, InterfaceName]
BridgePortMap = dict[NodeID, PortInfo]
AllBridgesMap = dict[BridgeName, BridgePortMap]
# (our_bridge, peer_bridge, ip, mac, vlan, ofport, port_name)
LocalIPRow = tuple[str, str, str, str, Optional[int], str, str]
IPsPerIface = Callable[[set[str]], dict[str, list[tuple[str, str]]]]


class OVSManager:
    """Central OVSDB access: ovs-vsctl --format=json, remote IPs cache, local discovery."""

    def __init__(self, log: Optional[logging.Logger] = None, config: Optional[Config] = None) -> None:
        self._log = log
        self._config = config
        cache_ttl = config.ovs_node_port_cache_ttl if config else 60.0
        self._cache: TTLCache[AllBridgesMap] = TTLCache(
            ttl=cache_ttl,
            fetch_fn=self._fetch_all_bridges_remote_ips,
            default={},
        )

    def list_table(self, table: str) -> list[dict[str, Any]]:
        ok, data = OVSCommand.run_vsctl(["list", table])
        if not ok or not isinstance(data, dict):
            return []
        return OVSCommand.parse_table_rows(data)

    def iface_to_bridge(self, iface_name: str) -> Optional[BridgeName]:
        ok, data = OVSCommand.run_vsctl(["iface-to-br", iface_name], timeout=2, json_output=False)
        if ok and isinstance(data, str) and data:
            return BridgeName(data)
        return None

    def _fetch_all_bridges_remote_ips(self) -> AllBridgesMap:
        result: AllBridgesMap = {}
        for row in self.list_table("Interface"):
            remote_ip = _ovs_options_remote_ip(row.get("options"))
            if not remote_ip:
                continue
            name = row.get("name")
            ofport = row.get("ofport")
            if not name or ofport is None:
                continue
            bridge = self.iface_to_bridge(name)
            if not bridge:
                continue
            if bridge not in result:
                result[bridge] = {}
            result[bridge][NodeID(remote_ip)] = (OFPort(str(ofport)), InterfaceName(name))
        return result

    def get_bridge_node_to_ofport(self, bridge: str, force_refresh: bool = False) -> BridgePortMap:
        full_map = self._cache.get(force_refresh=force_refresh)
        return full_map.get(bridge, {})

    @staticmethod
    def resolve_node_port(
        node_map: BridgePortMap,
        node: NodeID,
    ) -> tuple[Optional[int], Optional[str]]:
        """Return (ofport, port_name) for node from node_map with safe int conversion."""
        port_info = node_map.get(node)
        if not port_info:
            return None, None
        port_id, port_name = port_info
        try:
            ofport = int(str(port_id)) if port_id is not None else None
        except (ValueError, TypeError):
            ofport = None
        return ofport, str(port_name) if port_name is not None else None

    def get_bridge_ofport_to_name(self, bridge: str) -> dict[int, str]:
        """Ofport -> Port name for bridge (from list Port)."""
        bridges = self.list_table("Bridge")
        port_uuids: set[str] = set()
        for b in bridges:
            if b.get("name") == bridge:
                port_uuids = set(self._cell_to_uuids(b.get("ports")))
                break
        if not port_uuids:
            return {}
        ports = self.list_table("Port")
        interfaces = self.list_table("Interface")
        iface_by_uuid = {k: i for i in interfaces for k in [self._uuid_key(i.get("_uuid"))] if k}
        result: dict[int, str] = {}
        for p in ports:
            if self._uuid_key(p.get("_uuid")) not in port_uuids:
                continue
            port_name = str(p.get("name") or "")
            for iu in self._cell_to_uuids(p.get("interfaces")):
                iface = iface_by_uuid.get(iu)
                if not iface or iface.get("ofport") is None:
                    continue
                try:
                    result[int(iface["ofport"])] = port_name
                except (ValueError, TypeError):
                    pass
                break
        return result

    @staticmethod
    def _cell_to_uuids(cell: Any) -> list[str]:
        """OVSDB JSON: uuid or set of uuid -> list of uuid strings."""
        if cell is None:
            return []
        if isinstance(cell, list) and len(cell) >= 2:
            if cell[0] == "uuid":
                return [str(cell[1])]
            if cell[0] == "set":
                return [
                    str(item[1])
                    for item in (cell[1] or [])
                    if isinstance(item, (list, tuple)) and len(item) >= 2 and item[0] == "uuid"
                ]
        return []

    @staticmethod
    def _uuid_key(cell: Any) -> Optional[str]:
        """OVSDB JSON: single uuid cell -> string or None."""
        if cell is None or not isinstance(cell, list) or len(cell) < 2 or cell[0] != "uuid":
            return None
        return str(cell[1])

    @staticmethod
    def _port_tag(port_row: dict[str, Any]) -> Optional[int]:
        """Port VLAN from tag or external_ids.vlan_tag."""
        tag = port_row.get("tag")
        if tag is not None and isinstance(tag, (int, str)):
            try:
                return int(tag)
            except ValueError:
                pass
        eid = port_row.get("external_ids")
        if isinstance(eid, list) and len(eid) >= 2 and eid[0] == "map":
            for pair in (eid[1] or []):
                if isinstance(pair, (list, tuple)) and len(pair) >= 2 and pair[0] == "vlan_tag":
                    try:
                        return int(pair[1])
                    except (ValueError, TypeError):
                        pass
        return None

    @staticmethod
    def _options_peer(options: Any) -> Optional[str]:
        """Interface options (patch) -> peer iface name."""
        if not isinstance(options, list) or len(options) < 2 or options[0] != "map":
            return None
        for pair in (options[1] or []):
            if isinstance(pair, (list, tuple)) and len(pair) >= 2 and pair[0] == "peer":
                peer = pair[1]
                if peer is None:
                    return None
                peer_s = str(peer).strip()
                return peer_s or None
        return None

    def _patch_ports_to_local(
        self, bridges: list[str], bridges_with_ips: set[str]
    ) -> list[tuple[str, str, Optional[int], str, str]]:
        """(our_br, peer_br, vlan, ofport, port_name) for patch ports to local bridges."""
        port_by_uuid: dict[str, dict[str, Any]] = {}
        for row in self.list_table("Port"):
            k = self._uuid_key(row.get("_uuid"))
            if k:
                port_by_uuid[k] = row
        iface_by_uuid: dict[str, dict[str, Any]] = {}
        for row in self.list_table("Interface"):
            k = self._uuid_key(row.get("_uuid"))
            if k:
                iface_by_uuid[k] = row
        monitored = set(bridges)
        out: list[tuple[str, str, Optional[int], str, str]] = []
        for brow in self.list_table("Bridge"):
            name = brow.get("name")
            if name not in monitored:
                continue
            for pu in self._cell_to_uuids(brow.get("ports")):
                port = port_by_uuid.get(pu)
                if not port:
                    continue
                vlan = self._port_tag(port)
                port_name = port.get("name") or ""
                for iu in self._cell_to_uuids(port.get("interfaces")):
                    iface = iface_by_uuid.get(iu)
                    if not iface or iface.get("type") != "patch":
                        continue
                    peer = self._options_peer(iface.get("options"))
                    if not peer:
                        continue
                    peer_br = self.iface_to_bridge(peer)
                    if not peer_br or str(peer_br) not in bridges_with_ips:
                        continue
                    ofport = iface.get("ofport")
                    if ofport is None:
                        continue
                    out.append((name, str(peer_br), vlan, str(ofport), port_name))
                    break
        return out

    def get_bridge_vlan_to_local_port(
        self,
        bridges: list[str],
        bridges_with_ips: set[str],
    ) -> dict[str, dict[Optional[int], tuple[str, str]]]:
        """Bridge -> vlan -> (ofport, port_name) for patch ports to local bridges."""
        result: dict[str, dict[Optional[int], tuple[str, str]]] = {}
        for our_br, _peer, vlan, ofport, port_name in self._patch_ports_to_local(
            bridges, bridges_with_ips
        ):
            result.setdefault(our_br, {})[vlan] = (ofport, port_name)
        return result

    def get_local_ips(
        self,
        bridges: list[str],
        bridges_with_ips: set[str],
        get_ips_fn: IPsPerIface,
    ) -> list[LocalIPRow]:
        """Discover local IPs: patch ports from bridges to peer bridges that have IPs."""
        patch_ports = self._patch_ports_to_local(bridges, bridges_with_ips)
        ips_per_iface = get_ips_fn({p[1] for p in patch_ports})
        return [
            (our_br, peer_br, ip, mac, vlan, ofport, port_name)
            for our_br, peer_br, vlan, ofport, port_name in patch_ports
            for ip, mac in ips_per_iface.get(peer_br, [])
        ]

    def dump_remote_ips(
        self,
        bridges: list[str],
        our_node: Optional[str] = None,
        node_last_seen: Optional[dict[str, float]] = None,
    ) -> None:
        """Print VXLAN remote_ip -> port per bridge (list-remote style)."""
        now = time.time()
        for bridge in bridges:
            m = self.get_bridge_node_to_ofport(bridge, force_refresh=True)
            print(f"Bridge: {bridge}")
            for ip, (port_id, port_name) in sorted(m.items()):
                suffix = "*" if (our_node and str(ip) == our_node) else ""
                last_ts = (node_last_seen or {}).get(str(ip))
                last_sec = int(now - last_ts) if last_ts is not None else None
                extra = f"  {last_sec}" if last_sec is not None else ""
                print(f"  {ip}{suffix}  {port_id}  {port_name}{extra}")
            if not m:
                print("  (none)")

    def dump_local_ips(self, bridges: list[str], config: Config) -> None:
        """Print local IPs per bridge (list-local style)."""
        from src.netlink import NetlinkInfo

        netlink_info = NetlinkInfo(bridges, config)
        bridges_with_ips = netlink_info.get_bridge_names_with_ips()
        rows = self.get_local_ips(bridges, bridges_with_ips, netlink_info.get_ips_per_interface)
        by_bridge: dict[str, list[LocalIPRow]] = {}
        for r in rows:
            by_bridge.setdefault(r[0], []).append(r)
        for bridge in sorted(bridges):
            lines = by_bridge.get(bridge, [])
            print(f"Bridge: {bridge}")
            for our_br, peer_br, ip, mac, vlan, ofport, port_name in sorted(
                lines, key=lambda x: (x[2], x[4] if x[4] is not None else -1)
            ):
                vlan_str = str(vlan) if vlan is not None else "-"
                print(f"  {ip}  {mac}  {vlan_str}  {peer_br}  {ofport}  {port_name}")
            if not lines:
                print("  (none)")

    def invalidate_local_fdb_mac(
        self,
        bridge: BridgeName,
        mac: str,
        vlan: Optional[int] = None,
    ) -> bool:
        """Best-effort local FDB invalidation by MAC."""
        bridge_s = str(bridge)
        mac_s = str(mac)
        candidates: list[tuple[str, ...]] = []
        if vlan is not None:
            vlan_s = str(vlan)
            candidates.append(("fdb/del", bridge_s, vlan_s, mac_s))
        candidates.append(("fdb/del", bridge_s, mac_s))
        for cmd in candidates:
            ok, out = OVSCommand.run_appctl(*cmd, timeout=2)
            if ok:
                if self._log:
                    self._log.debug("fdb invalidated bridge=%s mac=%s vlan=%s", bridge_s, mac_s, vlan)
                return True
            if self._log and out:
                self._log.debug("fdb invalidate try failed cmd=%s err=%s", " ".join(cmd), out)
        return False
