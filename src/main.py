#!/usr/bin/env python3
"""
OVS VM Arbiter — Proxmox VM/LXC discovery, ARP/DHCP snooping, UDP mesh, OpenFlow mirroring.

One-line summary
---------------
Reads Proxmox config DB; snoops ARP/DHCP on OVS bridges; publishes IP→MAC per (bridge, vlan)
to state.json and UDP mesh; injects OpenFlow flows for mirroring and ARP responder.
Node ID = IP (auto) or hostname. Config source: pmxcfs DB only (no /etc/pve fallback).

Usage (copy-paste)
------------------
  # Daemon (systemd uses --service)
  ovs-vm-arbiter.py --service
  ovs-vm-arbiter.py --service --debug --bridges vmbr0 vmbr1

  # List modes
  ovs-vm-arbiter.py --list-db              # instance cache + snoop state (MAC-keyed)
  ovs-vm-arbiter.py --list-peers            # mesh peers (node -> count)
  ovs-vm-arbiter.py --list-neigh            # neighbours: ip mac vlan node ttl (aliases: --list-n, --list-neighbours)
  ovs-vm-arbiter.py --list-remote-ips      # VXLAN remote_ip -> port (no state; alias: --list-remote)
  ovs-vm-arbiter.py --list-local           # Local IPs on bridges connected via patch (ip mac vlan peer ofport port)
  ovs-vm-arbiter.py --list-responders      # OFS ARP responder: bridge ip mac vlan node learn_port prio
  ovs-vm-arbiter.py --list-fdb [BRIDGE]    # FDB: port id, port name, vlan, mac, age, node (default bridge=first)

Options (essential)
-------------------
  --bridges BR [BR ...]     OVS bridges (default: vmbr0)
  --db-path PATH            Proxmox config.db (default: /var/lib/pve-cluster/config.db)
  --state-dir DIR           State dir (default: /var/lib/ovs-vm-arbiter)
  --no-load-state           Skip loading old state on start
  --load-state-max-age-sec SEC  Skip load if state.json older than SEC, write fresh (default: 60; 0=no check)
  --port N                  UDP mesh port (default: 9876)
  --node IP|NAME            Node ID (default: auto-detect; mesh uses IP when auto)
  --broadcast-iface IFACE   Bind UDP socket to interface (SO_BINDTODEVICE)

Options (mesh)
--------------
  --mesh-ttl SEC              Entry TTL (default: 990)
  --mesh-interval SEC         Send interval (default: 3)
  --mesh-send-on-change       Send only when changed (default: on)
  --mesh-recv-dedup-sec SEC   Recv dedup window (default: 0=off)
  --mesh-send-max-interval SEC  Max seconds without mesh send when unchanged (default: 99)
  --mesh-keepalive-interval SEC  Keepalive when 0 entries (default: 60; 0=off)
  --mesh-silence-restart / --no-mesh-silence-restart
                              Warn and restart mesh if no peer message for 10*keepalive (default: on)
  --mesh-sign-key KEY         HMAC-SHA256 key (default: none)
  --mesh-sign-key-file PATH   Signing key from file (default: none)
  Mesh tracks remote node uptime; on restart (uptime decreased) sends update immediately (throttled once per 60s).

Options (snooping / ARP)
------------------------
  --snoop-bridge / --no-snoop-bridge   Snoop bridge/host (default: on)
  --snoop-host-local                   Snoop scope=host IPs, create responder; not sent to mesh (default: on)
  --exclude-subnet CIDR [CIDR ...]     Exclude subnets from snooping (default: none)
  --snoop-vlans VLANS                 Snoop only on these VLANs: list/ranges e.g. 20,30-50,99 (default: all)
  --no-snoop-vlans VLANS              Do not snoop on these VLANs: list/ranges (default: none)
  --flood-min-interval SEC             Anti-flood per MAC (default: 5)
  --snoop-takeover-sec SEC             Local snoop can claim remote owner after SEC since remote last_seen (default: mesh_ttl/10)
  --arp-reply / --no-arp-reply         Reply to ARP for known IPs (default: on)
  --arp-reinject / --no-arp-reinject   Re-inject unknown ARP to flood (default: on)
  --arp-reply-local                    Reply for IPs on this node (default: on)
  --arp-reply-strict-vlan              Reply only when request vlan matches snooped vlan (default: on)
  --arp-reply-no-vlan                  Reply when request has no vlan / untagged in strict reply mode (default: off)
  --arp-reply-remote-vlan VLAN         Tunnel VLAN (inter-host): match/reply for remote IPs on this VLAN; local use real vlan
  --tunnel-vlan / --tunnel-vlans VLANS   Shortcut: no-snoop these VLAN(s) and set arp-reply-remote-vlan if single (multiple → warn)
  --arp-reply-set-register VALUE       On ARP reply packet-out, load VALUE into NXM_NX_REG0[] (0=off, default: 0)
  --arp-reply-local-fallback           Allow LOCAL in_port fallback (default: off)
  --arp-flood-threshold N              ARP flood warning per bridge (pkt/s; 0=off, default: 50)

Options (OFS ARP responder)
----------------------------
  --arp-responder / --no-arp-responder   Install per-IP OpenFlow rules that answer ARP who-has
                                         in the datapath (no packet-out to host). Default: off.
  --arp-responder-priority N             Flow priority (default: 1001; must be > of-priority).
  --arp-responder-mirror / --no-arp-responder-mirror
                                         When replying, mirror the request to LOCAL so snooping
                                         still sees it. Default: on.
  --arp-responder-forward-normal         Also output reply to NORMAL for FDB/port learning (default: off).
  --arp-responder-sync-interval SEC      Reconcile responder flows with entries every SEC (default: 10).
  --arp-responder-local-iface [IFACE ...]
                                         Interfaces/bridges to scan for host-local IPs that get
                                         ARP replies; empty = use --bridges (default: empty).
  --arp-responder-reply-local / --no-arp-responder-reply-local
                                         Install responder flows for local IPs (snooped or
                                         local-iface); default: same as --arp-reply-local.
                                         Reply for local sent only when both are true.
  --arp-responder-vlan-register N        Match VLAN by REG N (0=off, use vlan_tci)

Options (OpenFlow)
------------------
  --of-install              Install OpenFlow rules for ARP/DHCP mirror (default: on)
  --of-table N              Table for mirror flows (default: 0)
  --of-priority N           Priority (default: 999)
  --of-verify-interval SEC  Check flows every SEC, re-add if missing (0=off, default 90)
  --of-action ACTION        Default mirror flow action (default: NORMAL; no = LOCAL only)
  --of-arp-action ACTION    Override for ARP flows
  --of-dhcp-action ACTION   Override for DHCP flows
  --packet-out-max-queue N  Max queued packet-out requests (default: 10)

Options (expiry)
----------------
  --expiry-grace-sec SEC           Grace period before expiring loaded state (default: 60)
  --expired-entry-cleanup-sec SEC  Delete expired IP/MAC entries from store after SEC (default: 50400=14h; 0=off)
  --expiry-check-interval SEC      Run expire + cleanup every SEC (default: 30)
  --ping-neighbours SEC            Ping mesh neighbours from host every SEC (no reply wait; 0=off, default 0).
  local_entry_refresh_interval was removed; entries now age only from real snoop/mesh activity.
  Expiry: entries with no activity for mesh_ttl are marked expired; after expired_entry_cleanup_sec they are removed.

List-mode flags (exit after output)
------------------------------------
  --list-db           Dump instance cache merged with snoop state
  --list-peers        List mesh peers from state
  --list-neigh        List neighbours (aliases: --list-neighbours, --list-n)
  --list-remote-ips   List VXLAN remote_ip→port (alias: --list-remote)
  --list-local        List local IPs (connected bridges with IPs, patch ports)
  --list-refreshers   List ARP refresh peers: LOCAL, REMOTE, VLAN, PORT, TTL
  --list-responders   List OFS ARP responder entries (bridge ip mac vlan node learn_port prio) and exit
  --list-fdb [BRIDGE] List FDB (port id, name, vlan, mac, age, node from db); bridge default=first --bridges
  --test              Run built-in tests and exit

Logging
-------
  --debug         Enable debug
  --log-level LVL  debug | info | warning | error (default: warning)

Tuning (see --help for full list)
---------------------------------
  load_state_max_age_sec, db_debounce_sec, db_periodic_sec, db_retry_sec, host_local_cache_ttl,
  bridge_subnets_cache_ttl, ovs_node_port_cache_ttl, expiry_grace_sec, ping_neighbours_interval,
  expired_entry_cleanup_sec, main_loop_interval, save_interval, expiry_check_interval,
  mesh_silence_restart, mesh_recv_max_size, mesh_recv_max_keys, mesh_recv_max_depth, mesh_recv_max_key_len.

Paths and state
---------------
  Config DB:  /var/lib/pve-cluster/config.db (read-only)
  State:      <state-dir>/state.json (saved every save_interval, default 13s)
  Registry:   /run/ovs-flow-registry (OVS flow cookie; compatible with ovs-flow-mgr.py)
  --no-load-state: do not load state.json on start (fresh run).
  --load-state-max-age-sec: if state.json is older than SEC, skip load and overwrite with fresh state (default 60; 0=always load).

Architecture (classes)
----------------------
  Config          All settings; from_args(argparse).
  IPEntry         Single IP→MAC entry; keyed by (ip, bridge, vlan). expired=timestamp when TTL elapsed; scope host = local (not exported).
  InstanceInfo    VM/LXC from DB: vmid, type, bridge, mac, vlan, tags.
  IPEntryStore    Thread-safe store keyed by (ip, bridge, vlan). Per (ip, bridge) one VLAN snooped at a time; get_entries_for_bridge_ip, get_any_active_for_bridge_ip.
  InstanceStore   Thread-safe MAC→InstanceInfo.
  FlowRegistry    Cookie from /run/ovs-flow-registry.
  InstanceWatcher Polls config.db; parses qemu-server/*.conf, lxc/*.conf.
  NetlinkInfo     Cached netlink: self/tap MACs, host-local, subnets, bridge identity (IP→MAC).
  PacketMonitor   Scapy ARP/DHCP per bridge; updates IPEntryStore; optional ARP reply/reinject. Per-VLAN snoop: one VLAN per (ip, bridge); no overwrite remote on local vlan; VM move same vlan → node=self. ARP reply: strict/no_vlan and arp_reply_remote_vlan (local=entry vlan, remote=tunnel vlan when set); reply_vlan used for packet and in_port. --snoop-vlans / --no-snoop-vlans filter.
  MeshBroadcaster UDP broadcast send/recv; merge remote into store. On receive: keeps node from payload (origin); only uses UDP sender if payload has no node.
  OVSManager      ovs-vsctl; TTL-cached remote_ip mapping.
  OFManager       ovs-ofctl; mirror flows, ARP responder per (bridge, ip, vlan) (sync from entries), del-flows.
  AsyncPacketSender  Async packet-out queue.
  StateManager    Load/save IPEntryStore JSON.
  ArbiterCore     Main loop: poll DB, expire, cleanup expired, save, mesh, flows. On load: drops entries with no node. Expired entries removed after expired_entry_cleanup_sec.

Node (origin) semantics
-----------------------
  entry.node = which node owns/has this IP (for ARP reply in_port → VXLAN port). Set only by: (1) snoop: node=self when we create the entry; (2) mesh receive: node from payload (origin), not UDP sender. Entries without node are dropped on load (invalid/legacy state).

State and mesh payload
----------------------
  State/mesh keys: "<ip>|<bridge>|<vlan>" (e.g. "192.168.12.1|vmbr0|99"); legacy plain "<ip>" supported on load.
  Value: { "ipv4", "mac", "bridge", "vmid", "type", "node", "vlan", "last_seen", ... }. Null keys omitted.
  to_mesh_dict() returns None for scope host or when is_host_local(ip); those entries are not exported.
  _node, _uptime: sender identity and uptime (seconds). Restart detected when remote uptime decreases; this node sends full payload once (throttled 60s) so restarted node gets fresh data.

Types (NewType / Literal)
-------------------------
  NewType: MACAddress, IPv4Address, BridgeName, InterfaceName, NodeID, VMID, OFPort, OVSCookie
  Literal: EntryType = "qemu"|"lxc"|"vm"|"bridge"; InstanceType = "qemu"|"lxc"; SnoopOrigin = "arp"|"dhcp"|"proxmox"

Dependencies
-------------
  scapy     Optional; packet snooping. Without it, PacketMonitor no-ops.
  pyroute2  Optional; host-local and self MAC/IP filtering.

Dev notes
---------
  Preserve CLI/JSON; extend, don’t break.   ARP reply: entry.node → OVSManager.get_bridge_node_to_ofport for VXLAN in_port; node=None or self → skip (no LOCAL port).
  Bridge-type entries: only accept MAC matching local bridge (NetlinkInfo.bridge_mac_for_ip).
  Known restriction: ARP responder and VLANs — OVS rules often don't see 802.1Q; requests served by process. Workarounds: match register (VLAN id) or push/pop_vlan.
  Test: --list-db, --list-neigh, --list-remote-ips, then --debug daemon.

Modules (LLM hints)
-------------------
  main.py             Entry point. Parses CLI, builds Config, runs ArbiterCore or list-mode dumps. No business logic.
  config.py           Config dataclass, Config.from_args(argparse), get_node_ip, set_process_name, registry path helpers.
  core.py             ArbiterCore: owns stores, watcher, OVS/OF/mesh/monitor; main loop (poll, expire, cleanup expired, save, mesh, flows). _expire_entries, _cleanup_expired_entries; _ping_neighbours_loop when ping_neighbours_interval > 0. State load: drops entries with no node.
  icmp_ping.py        send_icmp_echo(dest_ip, sock): native ICMP echo request (no subprocess, no reply wait); used by ping-neighbours.
  models.py           IPEntry (ip, bridge, vlan, node, scope); IPEntryKey=(ip,bridge,vlan); IPEntryStore keyed by IPEntryKey (get/set/update/discard/get_active/items/keys); _entry_key, _key_to_str, _str_to_key; InstanceStore (MAC→InstanceInfo).
  types.py            NewTypes (MACAddress, IPv4Address, BridgeName, NodeID, VMID, OFPort, OVSCookie); Literals (EntryType, SnoopOrigin); optional IPRoute/scapy.
  state.py            StateManager(load_into/save_from IPEntryStore), load_json, save_json.
  dump.py             dump_db, dump_peers, dump_neigh, dump_refreshers, dump_responders; take ArbiterCore; iterate (key, entry) for IPEntryStore.
  flow_registry.py    FlowRegistry: read/register cookie in /run/ovs-flow-registry; get_cookie() for OFManager.
  instance_watcher.py InstanceWatcher: poll(config.db) → InstanceStore; parses qemu-server/*.conf, lxc/*.conf (MAC, bridge, vlan, tags).
  netlink.py          NetlinkInfo (TTL-cached: self_macs, tap_macs, host_local, bridge_subnets, bridge_identity, is_bridge_mac); PeerTracker (ARP refresh peers).
  ttl_cache.py        TTLCache[T]: get(force_refresh), invalidate; used by NetlinkInfo, OVSManager.
  ovs_cmd.py          OVSCommand: run_vsctl (sync), run_ofctl / run_ofctl_async; subprocess wrapper, JSON parse.
  ovs_manager.py      OVSManager: list_table, iface_to_bridge; get_bridge_node_to_ofport(bridge) → node→(OFPort, name); TTL cache of remote_ip.
  of_manager.py       OFManager: ensure_flows, verify_and_restore_flows, sync_arp_responder_flows(..., desired=); compute_desired_responders(..., node_id, arp_reply_local, arp_responder_reply_local, arp_reply_strict_vlan, arp_reply_no_vlan, arp_reply_remote_vlan, for_responder=True) → set of (bridge, ip, mac, vlan); packet-out sync/async.
  packet_out.py       PacketOutRequest dataclass; AsyncPacketSender (enqueue, start/stop on event loop).
  packet_monitor.py   PacketMonitor: ARP/DHCP sniff per bridge, update IPEntryStore by (ip, bridge, vlan); ARP reply: match_vlan (local=entry, remote=arp_reply_remote_vlan or entry), reply_vlan for packet/in_port; snoop sets node=self on create, keeps cur.node on update; inject_config_ips(); ArpRefresher thread.
  mesh.py             PayloadValidator, HMACSigner; MeshBroadcaster: send keyed by _key_to_str(key); receive parses _str_to_key, keeps node from payload (origin); merge by (ip, bridge, vlan); get_node_last_seen(), get_last_recv_any() for silence watchdog; restart sends update once per 60s.
  logging_util.py     setup_logging(level, debug), DebugDedupFilter.
"""

import argparse
import fcntl
import logging
import os
import socket
import sys
import dataclasses
from datetime import datetime, timezone

from src.config import (
    Config,
    get_local_mesh_ip,
    parse_vlan_list,
    set_process_name,
    build_process_title,
    REGISTRY_FILE,
    SYSLOG_PROCNAME
)
from src.logging_util import setup_logging
from src.core import ArbiterCore
from src.ovs_manager import OVSManager
from src.state import load_json

# Global config instance (set in main)
_config = None
_daemon_lock_fd = None  # hold ref so daemon lock stays for process lifetime


def get_version_string() -> str:
    """Return zip mtime as ISO datetime when run from zip, else 'source'."""
    try:
        f = globals().get("__file__") or getattr(sys.modules.get("__main__"), "__file__", "")
        if not f or ".zip" not in f:
            return "source"
        zip_path = f.split(".zip", 1)[0] + ".zip"
        if not os.path.isfile(zip_path):
            return "source"
        mtime = os.path.getmtime(zip_path)
        return datetime.fromtimestamp(mtime, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return "unknown"


def build_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser with all Config options."""
    # Default config for default values
    d = Config()
    p = argparse.ArgumentParser(
        description="OVS VM Arbiter: instance discovery, ARP/DHCP snooping, mesh, flows"
    )
    # Core settings
    p.add_argument("--bridges", nargs="+", default=d.bridges,
                   help=f"OVS bridges to monitor (default: {' '.join(d.bridges)})")
    p.add_argument("--service", action="store_true",
                   help="Run as long-lived daemon (required unless using --list-* / --test / --version)")
    p.add_argument("--db-path", default=d.db_path,
                   help=f"Proxmox config.db path (default: {d.db_path})")
    p.add_argument("--state-dir", default=d.state_dir,
                   help=f"State JSON directory (default: {d.state_dir})")
    p.add_argument("--no-load-state", action="store_true", default=d.no_load_state,
                   help=f"Skip loading old state on start (default: {d.no_load_state})")
    p.add_argument("--load-state-max-age-sec", type=float, default=d.load_state_max_age_sec, metavar="SEC",
                   help=f"Skip load if state file older than SEC; write fresh; 0=no check (default: {d.load_state_max_age_sec})")

    # Mesh networking
    p.add_argument("--port", type=int, default=d.mesh_port,
                   help=f"UDP mesh port (default: {d.mesh_port})")
    p.add_argument("--mesh-ttl", type=float, default=d.mesh_ttl,
                   help=f"Entry TTL seconds (default: {d.mesh_ttl})")
    p.add_argument("--mesh-interval", type=float, default=d.mesh_interval,
                   help=f"Seconds between send attempts after change (default: {d.mesh_interval})")
    p.add_argument("--mesh-send-on-change", action=argparse.BooleanOptionalAction, default=d.mesh_send_on_change,
                   help=f"Only send when entries changed (default: {d.mesh_send_on_change})")
    p.add_argument("--mesh-recv-dedup-sec", type=float, default=d.mesh_recv_dedup_sec, metavar="SEC",
                   help=f"Dedup window for same sender; 0=off (default: {d.mesh_recv_dedup_sec})")
    p.add_argument("--mesh-send-max-interval", type=float, default=d.mesh_send_max_interval, metavar="SEC",
                   help=f"Max seconds without mesh send when unchanged; 0=off (default: {d.mesh_send_max_interval})")
    p.add_argument("--mesh-keepalive-interval", type=float, default=d.mesh_keepalive_interval, metavar="SEC",
                   help=f"Keepalive when 0 entries; 0=off (default: {d.mesh_keepalive_interval})")
    p.add_argument("--mesh-silence-restart", action=argparse.BooleanOptionalAction, default=d.mesh_silence_restart,
                   help=f"Warn and restart mesh if no message for 10*keepalive (default: {d.mesh_silence_restart})")
    p.add_argument("--mesh-sign-key", default=d.mesh_sign_key, metavar="KEY",
                   help="HMAC-SHA256 signing key (default: none)")
    p.add_argument("--mesh-sign-key-file", default=d.mesh_sign_key_file, metavar="PATH",
                   help="Read signing key from file (default: none)")
    p.add_argument("--mesh-recv-max-size", type=int, default=d.mesh_recv_max_size, metavar="BYTES",
                   help=f"Max incoming payload bytes (default: {d.mesh_recv_max_size})")
    p.add_argument("--mesh-recv-max-keys", type=int, default=d.mesh_recv_max_keys, metavar="N",
                   help=f"Max MAC entries per payload (default: {d.mesh_recv_max_keys})")
    p.add_argument("--mesh-recv-max-depth", type=int, default=d.mesh_recv_max_depth, metavar="N",
                   help=f"Max JSON nesting depth (default: {d.mesh_recv_max_depth})")
    p.add_argument("--mesh-recv-max-key-len", type=int, default=d.mesh_recv_max_key_len, metavar="N",
                   help=f"Max key string length (default: {d.mesh_recv_max_key_len})")
    p.add_argument("--broadcast-iface", default=d.broadcast_iface,
                   help="Interface for UDP broadcast (default: none)")
    p.add_argument("--node", default=d.node,
                   help="Node ID for mesh (default: none = auto-detect from broadcast iface or hostname)")

    # Snooping
    p.add_argument("--snoop-bridge", action=argparse.BooleanOptionalAction, default=d.snoop_bridge,
                   help=f"Snoop bridge/host addresses type=bridge (default: {d.snoop_bridge})")
    p.add_argument("--snoop-host-local", action=argparse.BooleanOptionalAction, default=d.snoop_host_local,
                   help=f"Snoop scope=host IPs and create ARP responder; not sent to mesh (default: {d.snoop_host_local})")
    p.add_argument("--exclude-subnet", nargs="*", default=d.exclude_subnets, metavar="CIDR",
                   help="Exclude IP subnets from snooping (default: none)")
    p.add_argument("--snoop-vlans", "--snoop-vlan", default=d.snoop_vlans, metavar="VLANS",
                   help="Snoop only on these VLANs: list and/or ranges, e.g. 20,30-50,99 (default: all)")
    p.add_argument("--no-snoop-vlans", "--no-snoop-vlan", default=d.no_snoop_vlans, metavar="VLANS",
                   help="Do not snoop on these VLANs: list and/or ranges, e.g. 1,2,3 (default: none)")
    p.add_argument("--flood-min-interval", type=float, default=d.flood_min_interval, metavar="SEC",
                   help=f"Anti-flood interval per MAC (default: {d.flood_min_interval})")
    p.add_argument("--snoop-takeover-sec", type=float, default=d.snoop_takeover_sec, metavar="SEC",
                   help="Local snoop can claim remote owner after SEC since remote last_seen (default: mesh_ttl/10)")
    p.add_argument("--verify-local-migration", action=argparse.BooleanOptionalAction, default=d.verify_local_migration,
                   help=f"Allow local takeover only when PVE DB confirms local MAC move (default: {d.verify_local_migration})")
    p.add_argument("--verify-remote-migration", action=argparse.BooleanOptionalAction, default=d.verify_remote_migration,
                   help=f"Allow remote takeover only when sender claim and PVE DB cluster confirmation match (default: {d.verify_remote_migration})")
    p.add_argument("--arp-reply", action=argparse.BooleanOptionalAction, default=d.arp_reply,
                   help=f"Reply to ARP for known IPs (default: {d.arp_reply})")
    p.add_argument("--arp-reinject", action=argparse.BooleanOptionalAction, default=d.arp_reinject,
                   help=f"Re-inject unknown ARP requests to flood (default: {d.arp_reinject})")
    p.add_argument("--arp-reply-local-fallback", action=argparse.BooleanOptionalAction,
                   default=d.arp_reply_local_fallback,
                   help=f"Allow LOCAL in_port fallback for ARP reply if VXLAN port not found (default: {d.arp_reply_local_fallback})")
    p.add_argument("--arp-reply-local", action=argparse.BooleanOptionalAction, default=d.arp_reply_local,
                   help=f"Reply to ARP for IPs on this node (default: {d.arp_reply_local})")
    p.add_argument("--arp-reply-strict-vlan", action=argparse.BooleanOptionalAction, default=d.arp_reply_strict_vlan,
                   help=f"Reply only when request vlan matches snooped vlan (default: {d.arp_reply_strict_vlan})")
    p.add_argument("--arp-reply-no-vlan", action=argparse.BooleanOptionalAction, default=d.arp_reply_no_vlan,
                   help=f"Reply when request has no vlan / untagged (default: {d.arp_reply_no_vlan})")
    p.add_argument("--arp-reply-remote-vlan", type=int, default=None, metavar="VLAN",
                   help="Tunnel VLAN for inter-host (VXLAN): match/reply for remote IPs on this VLAN only; local IPs use real vlan")
    p.add_argument("--tunnel-vlan", "--tunnel-vlans", default=None, metavar="VLANS",
                   help="Shortcut: no-snoop these VLAN(s) (avoids attributing remote traffic to local node) and set arp-reply-remote-vlan if single VLAN")
    p.add_argument("--arp-reply-set-register", type=int, default=d.arp_reply_set_register, metavar="VALUE",
                   help=f"On ARP reply packet-out load VALUE into NXM_NX_REG0[]; 0=off (default: {d.arp_reply_set_register})")
    p.add_argument("--arp-reply-localize-vlan", action=argparse.BooleanOptionalAction,
                   default=d.arp_reply_localize_vlan,
                   help=f"When strict vlan is on, treat remote entries whose vlan is local as local (use entry vlan instead of arp-reply-remote-vlan) (default: {d.arp_reply_localize_vlan})")
    p.add_argument("--arp-refresh", action=argparse.BooleanOptionalAction, default=d.arp_refresh,
                   help=f"Refresh remote MACs in FDB for active peers (default: {d.arp_refresh})")
    p.add_argument("--arp-refresh-interval", type=float, default=d.arp_refresh_interval, metavar="SEC",
                   help=f"Base interval between refresh cycles; ±5s jitter (default: {d.arp_refresh_interval})")
    p.add_argument("--arp-peer-timeout", type=float, default=d.arp_peer_timeout, metavar="SEC",
                   help=f"Peer inactive after N seconds (default: {d.arp_peer_timeout})")
    p.add_argument("--arp-peer-limit", type=int, default=d.arp_peer_limit, metavar="N",
                   help=f"Max peers to track per VM (default: {d.arp_peer_limit})")
    p.add_argument("--arp-global-limit", type=int, default=d.arp_global_limit, metavar="N",
                   help=f"Max total ARP/MAC pairs to keep for refresh (default: {d.arp_global_limit})")
    p.add_argument("--arp-flood-threshold", type=int, default=d.arp_flood_threshold, metavar="N",
                   help=f"ARP flood warning threshold per bridge pkt/sec; 0=off (default: {d.arp_flood_threshold})")
    p.add_argument("--arp-responder", action=argparse.BooleanOptionalAction, default=d.arp_responder,
                   help=f"Install per-IP OpenFlow rules to answer ARP who-has in datapath (default: {d.arp_responder})")
    p.add_argument("--arp-responder-priority", type=int, default=d.arp_responder_priority, metavar="N",
                   help=f"Priority for ARP responder flows; must be > of-priority (default: {d.arp_responder_priority})")
    p.add_argument("--arp-responder-mirror", action=argparse.BooleanOptionalAction,
                   default=d.arp_responder_mirror,
                   help=f"Mirror ARP request to LOCAL when responding so snooping still sees it (default: {d.arp_responder_mirror})")
    p.add_argument("--arp-responder-forward-normal", action=argparse.BooleanOptionalAction,
                   default=d.arp_responder_forward_normal,
                   help=f"Also output reply to NORMAL for FDB/port learning (default: {d.arp_responder_forward_normal})")
    p.add_argument("--arp-responder-learning", action=argparse.BooleanOptionalAction,
                   default=d.arp_responder_learning,
                   help=f"Use learn() action so bridge learns response MAC on node port; reply to IN_PORT (default: {d.arp_responder_learning})")
    p.add_argument("--arp-responder-sync-interval", type=float, default=d.arp_responder_sync_interval,
                   metavar="SEC", help=f"Reconcile ARP responder flows with entries every SEC (default: {d.arp_responder_sync_interval})")
    p.add_argument("--arp-responder-local-iface", nargs="*", default=d.arp_responder_local_iface, metavar="IFACE",
                   help="Interfaces/bridges to scan for host-local IPs that get ARP replies; empty = use --bridges (default: empty)")
    p.add_argument("--arp-responder-reply-local", action=argparse.BooleanOptionalAction,
                   default=None, dest="arp_responder_reply_local",
                   help="Install responder for local IPs (snooped/local-iface); default: same as --arp-reply-local. Reply only when both true.")
    p.add_argument("--arp-responder-vlan-register", type=int, default=None, metavar="N",
                   help="Match VLAN by NXM_NX_REG<N>[]=vlan instead of vlan_tci (N=0-7; unset=use vlan_tci); use when OVS doesn't see 802.1Q")

    # OpenFlow
    p.add_argument("--of-install", action=argparse.BooleanOptionalAction, default=d.of_install,
                   help=f"Install OpenFlow rules for ARP/DHCP mirror (default: {d.of_install})")
    p.add_argument("--of-table", type=int, default=d.of_table, metavar="N",
                   help=f"OpenFlow table (default: {d.of_table})")
    p.add_argument("--of-priority", type=int, default=d.of_priority, metavar="N",
                   help=f"OpenFlow priority (default: {d.of_priority})")
    p.add_argument("--of-verify-interval", type=float, default=d.of_verify_interval, metavar="SEC",
                   help=f"Check flows every SEC, re-add if missing; 0=off (default: {d.of_verify_interval})")
    p.add_argument("--of-action", default=d.of_action, metavar="ACTION",
                   help=f"Default action for mirror flows; use 'no' for output:LOCAL only (default: {d.of_action})")
    p.add_argument("--of-arp-action", default=d.of_arp_action, metavar="ACTION",
                   help="Override action for ARP mirror flows (default: none)")
    p.add_argument("--of-dhcp-action", default=d.of_dhcp_action, metavar="ACTION",
                   help="Override action for DHCP mirror flows (default: none)")
    p.add_argument("--packet-out-max-queue", type=int, default=d.packet_out_max_queue, metavar="N",
                   help=f"Max queued packet-out requests (default: {d.packet_out_max_queue})")

    # Instance watcher timing
    p.add_argument("--db-debounce-sec", type=float, default=d.db_debounce_sec, metavar="SEC",
                   help=f"DB poll debounce interval (default: {d.db_debounce_sec})")
    p.add_argument("--db-force-debounce-sec", type=float, default=d.db_force_debounce_sec, metavar="SEC",
                   help=f"Minimum debounce for forced DB reads (default: {d.db_force_debounce_sec})")
    p.add_argument("--db-periodic-sec", type=float, default=d.db_periodic_sec, metavar="SEC",
                   help=f"DB force re-read interval (default: {d.db_periodic_sec})")
    p.add_argument("--db-retry-sec", type=float, default=d.db_retry_sec, metavar="SEC",
                   help=f"DB retry interval on failure (default: {d.db_retry_sec})")
    p.add_argument("--db-unavail-log-sec", type=float, default=d.db_unavail_log_sec, metavar="SEC",
                   help=f"Log DB unavailable every N seconds (default: {d.db_unavail_log_sec})")
    p.add_argument("--db-stat-optimization", action=argparse.BooleanOptionalAction, default=d.db_stat_optimization,
                   help=f"Skip DB read when config.db mtime is unchanged (default: {d.db_stat_optimization})")

    # Cache TTLs
    p.add_argument("--host-local-cache-ttl", type=float, default=d.host_local_cache_ttl, metavar="SEC",
                   help=f"Host-local address cache TTL (default: {d.host_local_cache_ttl})")
    p.add_argument("--bridge-subnets-cache-ttl", type=float, default=d.bridge_subnets_cache_ttl, metavar="SEC",
                   help=f"Bridge subnet cache TTL (default: {d.bridge_subnets_cache_ttl})")
    p.add_argument("--ovs-node-port-cache-ttl", type=float, default=d.ovs_node_port_cache_ttl, metavar="SEC",
                   help=f"OVS remote_ip cache TTL (default: {d.ovs_node_port_cache_ttl})")

    # Expiry/timing
    p.add_argument("--expiry-grace-sec", type=float, default=d.expiry_grace_sec, metavar="SEC",
                   help=f"Grace period before expiring loaded state (default: {d.expiry_grace_sec})")
    p.add_argument("--expired-entry-cleanup-sec", type=float, default=d.expired_entry_cleanup_sec, metavar="SEC",
                   help=f"Delete expired IP/MAC entries from db after SEC; 0=off (default: {d.expired_entry_cleanup_sec})")
    p.add_argument("--main-loop-interval", type=float, default=d.main_loop_interval, metavar="SEC",
                   help=f"Main loop sleep interval (default: {d.main_loop_interval})")
    p.add_argument("--save-interval", type=float, default=d.save_interval, metavar="SEC",
                   help=f"State save interval (default: {d.save_interval})")
    p.add_argument("--expiry-check-interval", type=float, default=d.expiry_check_interval, metavar="SEC",
                   help=f"Expiry check interval (default: {d.expiry_check_interval})")
    p.add_argument("--snoop-silence-warn-after-sec", type=float, default=d.snoop_silence_warn_after_sec, metavar="SEC",
                   help=f"First WARNING if no IP snooped for SEC; 0=off (default: {d.snoop_silence_warn_after_sec})")
    p.add_argument("--snoop-silence-warn-interval-sec", type=float, default=d.snoop_silence_warn_interval_sec,
                   metavar="SEC",
                   help=f"Repeat WARNING while silent; 0=once (default: {d.snoop_silence_warn_interval_sec})")
    p.add_argument("--snoop-silence-restart-sec", type=float, default=d.snoop_silence_restart_sec, metavar="SEC",
                   help=f"ERROR+restart if still no snoop after SEC; 0=off (default: {d.snoop_silence_restart_sec})")
    p.add_argument("--ping-neighbours", type=float, default=d.ping_neighbours_interval, metavar="SEC",
                   dest="ping_neighbours_interval",
                   help=f"Ping mesh neighbours from host every SEC (no wait for reply); 0=off (default: {d.ping_neighbours_interval})")
    p.add_argument("--migration-invalidates-fdb", action=argparse.BooleanOptionalAction,
                   default=d.migration_invalidates_fdb,
                   help=f"Invalidate local FDB and kernel ARP on ownership change (default: {d.migration_invalidates_fdb})")
    p.add_argument("--prometheus-metrics", action=argparse.BooleanOptionalAction,
                   default=d.prometheus_metrics,
                   help=f"Enable Prometheus/OpenMetrics endpoint (default: {d.prometheus_metrics})")
    p.add_argument("--prometheus-metrics-extra", action=argparse.BooleanOptionalAction,
                   default=d.prometheus_metrics_extra,
                   help=f"Enable high-cardinality entry mapping metrics (default: {d.prometheus_metrics_extra})")
    p.add_argument("--prometheus-port", type=int, default=d.prometheus_port, metavar="PORT",
                   help=f"Prometheus/OpenMetrics HTTP port (default: {d.prometheus_port})")
    p.add_argument("--prometheus-host", default=d.prometheus_host, metavar="HOST",
                   help=f"Prometheus/OpenMetrics HTTP host bind (default: {d.prometheus_host})")

    # Logging/debug
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    p.add_argument("--debug-flags", type=int, default=d.debug_flags, metavar="MASK",
                   help=f"Debug flags bitmask; 0=off (default: {d.debug_flags})")
    p.add_argument("--debug-arp-reply", action="store_true",
                   help="Enable verbose ARP reply debug logging (sets debug-flags bit 0)")
    p.add_argument("--log-level", choices=("debug", "info", "warning", "error"), default=d.log_level,
                   help=f"Log level (default: {d.log_level})")

    # List mode flags
    p.add_argument("--list-db", action="store_true", help="Dump instance cache and exit")
    p.add_argument("--list-pve-db", action="store_true", help="Dump only parsed PVE DB instances and exit")
    p.add_argument("--list-peers", action="store_true", help="List mesh peers and exit")
    p.add_argument("--list-neigh", "--list-neighbours", "--list-n", dest="list_neigh",
                   action="store_true", help="List neighbours and exit")
    p.add_argument("--list-remote", "--list-remote-ips", dest="list_remote_ips",
                   action="store_true", help="List VXLAN remote_ip per bridge and exit")
    p.add_argument("--list-local", dest="list_local_ips", action="store_true",
                   help="List local IPs (connected bridges with IPs, patch ports) and exit")
    p.add_argument("--list-refreshers", dest="list_refreshers", action="store_true",
                   help="List ARP refresh peers: LOCAL, REMOTE, VLAN, PORT, TTL")
    p.add_argument("--list-responders", "--list-arp-responders", dest="list_responders", action="store_true",
                   help="List OFS ARP responder entries (bridge ip mac vlan node learn_port prio) and exit")
    p.add_argument("--list-vlans", action="store_true",
                   help="List VLANs with scope (local/remote) and assigned IPs")
    p.add_argument("--list-fdb", nargs="?", const="", metavar="BRIDGE", dest="list_fdb", default=None,
                   help="List FDB (port VLAN MAC age); optional bridge (default: first --bridges)")
    p.add_argument("--test", action="store_true", help="Run built-in tests and exit")
    p.add_argument("--version", action="store_true", help="Print zip timestamp as datetime and exit")

    return p


def _has_explicit_run_mode(args: argparse.Namespace) -> bool:
    """True if CLI selects daemon (--service), a list dump, --test, or --version."""
    if getattr(args, "version", False) or getattr(args, "test", False):
        return True
    if getattr(args, "service", False):
        return True
    if getattr(args, "list_db", False) or getattr(args, "list_pve_db", False):
        return True
    if getattr(args, "list_peers", False) or getattr(args, "list_neigh", False):
        return True
    if getattr(args, "list_remote_ips", False) or getattr(args, "list_local_ips", False):
        return True
    if getattr(args, "list_refreshers", False) or getattr(args, "list_responders", False):
        return True
    if getattr(args, "list_vlans", False):
        return True
    if getattr(args, "list_fdb", None) is not None:
        return True
    return False


def _acquire_daemon_lock(state_dir: str) -> tuple[object, str | None]:
    """Take exclusive lock file for single daemon instance. Returns (fd, None) or (None, error_msg)."""
    os.makedirs(state_dir, mode=0o755, exist_ok=True)
    lock_path = os.path.join(state_dir, "ovs-vm-arbiter.lock")
    try:
        fd = open(lock_path, "w")
    except OSError as e:
        return None, str(e)
    try:
        fcntl.flock(fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        fd.seek(0)
        fd.write(str(os.getpid()))
        fd.truncate()
        fd.flush()
    except BlockingIOError:
        fd.close()
        return None, "another instance already running (lock held)"
    except OSError as e:
        fd.close()
        return None, str(e)
    return fd, None


def main() -> int:
    global _config
    parser = build_parser()
    args = parser.parse_args()

    if getattr(args, "version", False):
        print(get_version_string())
        return 0

    if getattr(args, "test", False):
        from src.tests import run_tests
        return run_tests()

    if not _has_explicit_run_mode(args):
        parser.error(
            "specify --service for daemon mode, or a --list-* action, or --test / --version"
        )

    # tunnel-vlan(s): merge into no_snoop_vlans; set arp_reply_remote_vlan if single vlan
    tunnel_raw = getattr(args, "tunnel_vlans", None) or getattr(args, "tunnel_vlan", None)
    if tunnel_raw:
        tunnel_set = parse_vlan_list(tunnel_raw)
        no_set = parse_vlan_list(getattr(args, "no_snoop_vlans", None) or "") | tunnel_set
        args.no_snoop_vlans = ",".join(sorted(str(x) for x in no_set))
        if len(tunnel_set) == 1:
            args.arp_reply_remote_vlan = next(iter(tunnel_set))
        elif len(tunnel_set) > 1:
            sys.stderr.write("warning: multiple tunnel VLANs specified; set --arp-reply-remote-vlan manually if needed.\n")

    # Debug flags: convenience switch for ARP reply traces
    if getattr(args, "debug_arp_reply", False):
        current = getattr(args, "debug_flags", 0) or 0
        args.debug_flags = current | 1

    # Build config from args
    config = Config.from_args(args)
    _config = config

    # Nice name in ps (setproctitle) with args; prctl fallback for comm
    try:
        import setproctitle
        setproctitle.setproctitle(build_process_title(sys.argv[1:], base=SYSLOG_PROCNAME.decode()))
    except (ImportError, AttributeError):
        pass
    set_process_name(SYSLOG_PROCNAME)
    # Above-normal priority when not already set by systemd (Nice=-10)
    try:
        if os.getpriority(os.PRIO_PROCESS, 0) >= 0:
            os.nice(-10)
    except (OSError, PermissionError):
        pass

    log = setup_logging(config.log_level, debug=config.is_debug())

    if config.is_debug():
        log.debug("debug logging enabled")
        log.debug("version %s", get_version_string())

    # Handle list-remote-ips and list-local early (before ArbiterCore)
    if config.list_remote_ips:
        ovs = OVSManager(log, config)
        our_node = get_local_mesh_ip(config)
        mesh_seen_path = os.path.join(config.state_dir, "mesh_last_seen.json")
        ovs.dump_remote_ips(
            config.bridges,
            our_node=our_node,
            node_last_seen=load_json(mesh_seen_path, {}),
        )
        return 0
    if config.list_local_ips:
        OVSManager(log, config).dump_local_ips(config.bridges, config)
        return 0

    if not REGISTRY_FILE:
        log.warning("Registry path not configured; OVS flows will be skipped")

    # Single-instance lock for daemon mode (skip for list/test/version)
    is_list_mode = config.list_mode_mask != 0
    if not is_list_mode:
        global _daemon_lock_fd
        _daemon_lock_fd, lock_err = _acquire_daemon_lock(config.state_dir)
        if lock_err:
            log.error("daemon lock: %s", lock_err)
            return 1

    core = ArbiterCore(config, log)
    metrics_server = None
    if config.prometheus_metrics and not is_list_mode:
        try:
            from src.metrics import start_metrics_server
        except ModuleNotFoundError as e:
            if str(e).startswith("No module named 'prometheus_client'"):
                log.error("prometheus metrics enabled but python module missing: prometheus_client")
                log.error("install module and retry: apt install python3-prometheus-client")
                return 1
            raise
        metrics_server = start_metrics_server(core, config, log)
    try:
        core.run()
        return 0
    except Exception as e:
        log.exception("ovs-vm-arbiter failed: %s", e)
        return 1
    finally:
        if metrics_server is not None:
            metrics_server.stop()


if __name__ == "__main__":
    sys.exit(main())
