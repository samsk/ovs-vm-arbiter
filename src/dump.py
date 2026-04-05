from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING, Any

from src.netlink import PeerTracker
from src.state import load_json
from src.ovs_cmd import OVSCommand
from src.types import BridgeName, IPv4Address, MACAddress, NodeID
from src.packet_monitor import ArpRefresher

if TYPE_CHECKING:
    from src.core import ArbiterCore


def _dump_preamble(app: ArbiterCore, inject_local: bool = False) -> None:
    """Common setup for list-mode dumps."""
    state_mgr = getattr(app, "_state_mgr", None)
    if state_mgr is not None:
        state_mgr.load_into(app._entries)
    if inject_local and app.config.arp_responder:
        app._inject_local_iface_entries()


def dump_db(app: ArbiterCore) -> None:
    """Print instance cache merged with snoop state (IP store: match by MAC)."""
    _dump_preamble(app)
    instances = app._watcher.poll(force_refresh=True)
    out: dict[str, dict[str, Any]] = {}
    for mac, info in instances.items():
        rec = info.to_dict()
        candidates = app._entries.get_entries_by_mac(mac)
        entry = candidates[0][1] if candidates else None
        if entry:
            rec["ipv4"] = entry.ipv4
            rec["snooped"] = 1
            for k in ("last_seen", "snoop_origin", "vlan", "node", "last_received", "expired"):
                val = getattr(entry, k, None)
                if val is not None:
                    rec[k] = val
        else:
            rec["ipv4"] = info.ip
            rec["snooped"] = 0
        out[str(mac)] = rec
    print(json.dumps(out, indent=2))


def dump_pve_db(app: ArbiterCore) -> None:
    """Print only parsed PVE DB instances in table format."""
    instances = app._watcher.poll(force_refresh=True)
    rows: list[tuple[str, str, str, str, str, str, str]] = []
    for mac, info in sorted(instances.items(), key=lambda item: str(item[0])):
        vlan = "-" if info.vlan is None else str(info.vlan)
        ip = "-" if info.ip is None else str(info.ip)
        tags = ",".join(info.tags) if info.tags else "-"
        rows.append(
            (
                str(mac),
                str(info.vmid),
                str(info.type),
                str(info.bridge),
                vlan,
                ip,
                tags,
            )
        )
    if not rows:
        print("no pve db instances")
        return
    col_w = [max(len(r[i]) for r in rows) for i in range(7)]
    col_w[0] = max(col_w[0], 17)
    col_w[1] = max(col_w[1], 4)
    col_w[2] = max(col_w[2], 4)
    col_w[3] = max(col_w[3], 6)
    col_w[4] = max(col_w[4], 4)
    col_w[5] = max(col_w[5], 2)
    col_w[6] = max(col_w[6], 4)
    header = (
        f"{'MAC':<{col_w[0]}} {'VMID':<{col_w[1]}} {'TYPE':<{col_w[2]}} "
        f"{'BRIDGE':<{col_w[3]}} {'VLAN':<{col_w[4]}} {'IP':<{col_w[5]}} TAGS"
    )
    print(header)
    for row in rows:
        print(
            f"{row[0]:<{col_w[0]}} {row[1]:<{col_w[1]}} {row[2]:<{col_w[2]}} "
            f"{row[3]:<{col_w[3]}} {row[4]:<{col_w[4]}} {row[5]:<{col_w[5]}} {row[6]}"
        )


def dump_peers(app: ArbiterCore) -> None:
    """Print mesh peers from state."""
    _dump_preamble(app)
    counts: dict[str, int] = {}
    for _ip, entry in app._entries.items():
        if entry.node:
            counts[str(entry.node)] = counts.get(str(entry.node), 0) + 1
    print(json.dumps(counts, indent=2))


def dump_neigh(app: ArbiterCore) -> None:
    """Print neighbours from state: ip mac vlan node ttl."""
    _dump_preamble(app, inject_local=True)
    ttl_sec = app.config.mesh_ttl
    now = time.time()
    rows: list[tuple[str, str, str, str, str]] = []
    for _key, entry in app._entries.items():
        vlan_str = str(entry.vlan) if entry.vlan is not None else "-"
        node = entry.node or "-"
        last = entry.last_seen
        if entry.expired is not None or not last:
            rem = 0
        else:
            rem = max(0, int(ttl_sec - (now - last)))
        rows.append((str(entry.ipv4), str(entry.mac), vlan_str, node, str(rem)))
    for ip, mac, vlan_str, node, rem in sorted(rows, key=lambda r: (r[0], r[1])):
        print(f"{ip} {mac} {vlan_str} {node} {rem}")


def dump_refreshers(app: ArbiterCore) -> None:
    """Print ARP refresh peers: LOCAL, REMOTE, VLAN, PORT, TTL."""
    _dump_preamble(app)
    cfg = app.config
    tracker = PeerTracker(cfg.arp_peer_timeout, cfg.arp_peer_limit, cfg.arp_global_limit)
    tracker.load_from_dict(load_json(app._peers_path, {}))
    now = time.time()
    ttl_sec = cfg.arp_peer_timeout
    rows: list[tuple[str, str, str, str, int]] = []
    pairs = ArpRefresher.iter_active_peer_entries(tracker, app._entries)
    for local_mac, remote_ip, last_seen, local_entry, remote_entry in pairs:
        bridge = local_entry.bridge
        if not bridge:
            continue
        vlan_str = str(local_entry.vlan) if local_entry.vlan is not None else "-"
        node_map = app._ovs.get_bridge_node_to_ofport(bridge)
        remote_node = remote_entry.node
        if remote_node and str(remote_node) != app._node_id and remote_node in node_map:
            _port_id, port_name = node_map[remote_node]
            port = port_name or str(_port_id)
        else:
            port = "LOCAL"
        ttl = max(0, int(ttl_sec - (now - last_seen)))
        rows.append((str(local_entry.ipv4), remote_ip, vlan_str, port, ttl))
    for local, remote, vlan_str, port, ttl in sorted(rows):
        print(f"{local}, {remote}, {vlan_str}, {port}, {ttl}")


def dump_responders(app: ArbiterCore) -> None:
    """Print ARP responder flows installed in OVS; learn port as full name when present."""
    _dump_preamble(app, inject_local=True)
    installed = app._of.get_installed_arp_responders()
    ofport_to_name_cache: dict[str, dict[int, str]] = {}
    rows: list[tuple[str, str, str, str, str, str, str]] = []
    for br, ip, vlan, mac, prio, learn_ofport in sorted(
        installed, key=lambda r: (r[0], r[1], r[2] or -1, r[3])
    ):
        vlan_str = str(vlan) if vlan is not None else "-"
        entry = app._entries.get(ip, br, vlan) or app._entries.get_any_for_bridge_ip(ip, br)
        node = (entry.node or "-") if entry else "-"
        br_str = str(br)
        if br_str not in ofport_to_name_cache:
            ofport_to_name_cache[br_str] = app._ovs.get_bridge_ofport_to_name(br_str)
        name_map = ofport_to_name_cache[br_str]
        learn_name = (
            name_map.get(learn_ofport, str(learn_ofport)) if learn_ofport is not None else "-"
        )
        rows.append((br_str, str(ip), str(mac), vlan_str, node, learn_name, str(prio)))
    for r in rows:
        print(f"{r[0]} {r[1]} {r[2]} {r[3]} {r[4]} {r[5]} prio={r[6]}")


def dump_vlans(app: ArbiterCore) -> None:
    """Print VLANs with scope (local/remote) and assigned IPs."""
    _dump_preamble(app, inject_local=True)
    # VLAN scope is based on whether the VLAN is local on this node, using the same
    # logic as ARP responder / ARP reply localization.
    try:
        local_vlans = app._get_local_vlans()
    except Exception:
        local_vlans = frozenset()
    all_ips: dict[int, set[str]] = {}
    for _key, entry in app._entries.items():
        if entry.vlan is None:
            continue
        try:
            v = int(entry.vlan)
        except (TypeError, ValueError):
            continue
        ip_s = str(entry.ipv4)
        all_ips.setdefault(v, set()).add(ip_s)
    all_vlans = sorted(all_ips.keys())
    for v in all_vlans:
        scope = "local" if v in local_vlans else "remote"
        ips = sorted(all_ips.get(v, set()))
        if not ips:
            continue
        print(f"{v} {scope} {','.join(ips)}")


def _fdb_node_info(
    app: ArbiterCore, bridge: str, mac: MACAddress
) -> tuple[str, str, int | None]:
    """(our_ip, node_str, our_ofport) for MAC; ip/node '-' when missing; our_ofport None when no entry."""
    node_map = app._ovs.get_bridge_node_to_ofport(bridge)
    for _key, entry in app._entries.get_entries_by_mac(mac):
        if not entry.node:
            continue
        ofport, port_name = app._ovs.resolve_node_port(node_map, NodeID(entry.node))
        ip_str = str(entry.ipv4)
        node_str = f"{entry.node} {port_name}" if port_name else str(entry.node)
        return (ip_str, node_str, ofport)
    return ("-", "-", None)


def dump_fdb(app: ArbiterCore, bridge: str) -> None:
    """Print FDB: port id, name, vlan, mac, age, our_ip, node; !!! if FDB port != our port."""
    _dump_preamble(app)
    ok, out = OVSCommand.run_appctl("fdb/show", bridge, timeout=5)
    if not ok or not out:
        print(out or "fdb/show failed", file=__import__("sys").stderr)
        return
    lines = out.splitlines()
    ofport_to_name = app._ovs.get_bridge_ofport_to_name(bridge)
    rows: list[tuple[str, str, str, str, str, str, str, bool]] = []
    for line in lines:
        parts = line.split()
        if len(parts) < 4 or parts[0] == "port":
            continue
        port_s, vlan_s, mac_s, age_s = parts[0], parts[1], parts[2], parts[3]
        try:
            port_id = int(port_s)
        except ValueError:
            continue
        port_name = ofport_to_name.get(port_id, port_s)
        ip_str, node_str, our_ofport = _fdb_node_info(app, bridge, MACAddress(mac_s))
        mismatch = our_ofport is not None and our_ofport != port_id
        rows.append((port_s, port_name, vlan_s, mac_s, age_s, ip_str, node_str, mismatch))
    if not rows:
        return
    col_w = [max(len(r[i]) for r in rows) for i in range(6)]
    col_w[0] = max(col_w[0], 4)
    col_w[1] = max(col_w[1], 9)
    col_w[2] = max(col_w[2], 4)
    col_w[3] = max(col_w[3], 17)
    col_w[4] = max(col_w[4], 3)
    col_w[5] = max(col_w[5], 2)
    header = (
        f"{'port':<{col_w[0]}} {'name':<{col_w[1]}} {'VLAN':<{col_w[2]}} "
        f"{'MAC':<{col_w[3]}} {'Age':<{col_w[4]}} {'ip':<{col_w[5]}} node"
    )
    print(header)
    for r in rows:
        line = (
            f"{r[0]:<{col_w[0]}} {r[1]:<{col_w[1]}} {r[2]:<{col_w[2]}} "
            f"{r[3]:<{col_w[3]}} {r[4]:<{col_w[4]}} {r[5]:<{col_w[5]}} {r[6]}"
        )
        if r[7]:
            line += " !!!"
        print(line)
