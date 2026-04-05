import logging
import random
import socket
import sys
import threading
import os
import time
import asyncio
from typing import Optional, Set, Tuple

from src.config import Config, get_local_mesh_ip
from src.icmp_ping import send_icmp_echo, raw_icmp_socket_ok
from src.models import IPEntryStore, IPEntry
from src.flow_registry import FlowRegistry
from src.instance_watcher import InstanceWatcher
from src.ovs_manager import OVSManager
from src.netlink import NetlinkInfo, PeerTracker
from src.of_manager import OFManager, compute_desired_responders
from src.state import StateManager, save_json, load_json
from src.packet_monitor import PacketMonitor, ArpRefresher
from src.mesh import MeshBroadcaster
from src.packet_out import AsyncPacketSender
from src.types import NodeID, BridgeName, MACAddress, IPv4Address, OFPort, RT_SCOPE_HOST
from src import dump
from src.of_manager import _ResponderKey


class ArbiterCore:
    """Orchestrate InstanceWatcher, PacketMonitor, MeshBroadcaster, OFManager, persistence.

    Owns IP entry store, OVS/OF managers, mesh; main loop: poll, expire, cleanup expired, save, sync ARP responder flows.
    Expiry: entries idle past mesh_ttl get expired=now; after expired_entry_cleanup_sec they are removed from store (0=disable).
    """

    def __init__(self, config: Config, log: logging.Logger) -> None:
        self.config = config
        self.log = log
        self._entries = IPEntryStore()
        self._registry = FlowRegistry(description="VM/LXC ARP arbiter")
        self._watcher = InstanceWatcher(config.db_path, log, config)
        self._node_id = get_local_mesh_ip(config)
        self._ovs = OVSManager(log, config)
        self._netlink = NetlinkInfo(config.bridges, config)
        self._of = OFManager(
            self._registry,
            config.bridges,
            log,
            of_table=config.of_table,
            of_priority=config.of_priority,
            of_action=config.of_action,
            of_arp_action=config.of_arp_action,
            of_dhcp_action=config.of_dhcp_action,
            arp_responder_priority=config.arp_responder_priority,
            arp_responder_mirror=config.arp_responder_mirror,
            arp_responder_forward_normal=config.arp_responder_forward_normal,
            arp_responder_vlan_register=config.arp_responder_vlan_register,
        )
        self._state_mgr = StateManager(config.state_dir)
        self._load_persisted_node_id()
        if not self._is_list_mode():
            self._persist_node_id()
        self._peer_tracker: Optional[PeerTracker] = None
        if config.arp_refresh:
            self._peer_tracker = PeerTracker(
                config.arp_peer_timeout,
                config.arp_peer_limit,
                config.arp_global_limit,
            )
        self._monitor = PacketMonitor(
            self._watcher.poll(),
            self._entries,
            self.log,
            ovs_manager=self._ovs,
            of_manager=self._of,
            config=config,
            node_id=NodeID(self._node_id),
            peer_tracker=self._peer_tracker,
            netlink=self._netlink,
            get_local_vlans=lambda: self._get_local_vlans(),
            is_local_migration_confirmed=self._is_local_migration_confirmed,
            on_owner_change=self._on_migration_invalidate_fdb,
        )
        self._refresher: Optional[ArpRefresher] = None
        if config.arp_refresh:
            self._refresher = ArpRefresher(
                self._peer_tracker,
                self._entries,
                config,
                self.log,
                monitor=self._monitor,
            )
        self._mesh = MeshBroadcaster(
            self._entries,
            self.log,
            config=config,
            node_id=self._node_id,
            netlink=self._netlink,
            is_remote_migration_confirmed=self._is_remote_migration_confirmed,
            on_owner_change=self._on_migration_invalidate_fdb,
        )
        self._monitor_threads: list[threading.Thread] = []
        self._stop = threading.Event()
        self._start_time: float = 0
        self._async_sender: Optional[AsyncPacketSender] = None
        self._ping_thread: Optional[threading.Thread] = None
        self._migration_invalidation_queue: Optional[
            "asyncio.Queue[Tuple[IPv4Address, BridgeName, Optional[int], Optional[NodeID], Optional[NodeID]]]"
        ] = None
        self._migration_invalidation_worker_task: Optional[asyncio.Task[None]] = None
        self._event_loop: Optional[asyncio.AbstractEventLoop] = None
        self._owner_changes_count: int = 0
        self._entries_expired_count: int = 0
        self._entries_cleaned_count: int = 0
        self._last_loop_tick: float = 0.0
        self._last_snoop_silence_warn_ts: float = 0.0

    def _is_list_mode(self) -> bool:
        """True when running in one-shot list mode (no daemon)."""
        return self.config.list_mode_mask != 0

    def _load_persisted_node_id(self) -> None:
        """Override node_id from state_dir when persisted (for list modes)."""
        try:
            path = os.path.join(self.config.state_dir, "node_info.json")
            data = load_json(path, {})
            node = data.get("node_id")
            if isinstance(node, str) and node:
                self._node_id = node
        except (OSError, AttributeError, TypeError, ValueError) as e:
            self.log.debug("load persisted node_id failed: %s", e)

    def _persist_node_id(self) -> None:
        """Persist current node_id to state_dir for later list-mode runs."""
        try:
            path = os.path.join(self.config.state_dir, "node_info.json")
            os.makedirs(self.config.state_dir, mode=0o755, exist_ok=True)
            save_json(path, {"node_id": self._node_id})
        except OSError as e:
            self.log.debug("persist node_id failed: %s", e)

    def _get_local_vlans(self) -> frozenset[int]:
        """VLAN IDs that are considered local on this node.

        Conservative definition: VLANs for entries owned by this node in the snoop DB.
        """
        vlans: set[int] = set()
        mesh_self = self._node_id
        for (_ip, _br, _vlan), entry in self._entries.items():
            if entry.vlan is None or not entry.node:
                continue
            if str(entry.node) != mesh_self:
                continue
            try:
                vlans.add(int(entry.vlan))
            except (TypeError, ValueError):
                continue
        return frozenset(vlans)

    def _update_instances(self) -> None:
        """Poll for instance changes; inject LXC config IPs into snoop store."""
        store = self._watcher.poll()
        self._monitor.instances = store
        self._monitor.inject_config_ips()

    def _is_local_migration_confirmed(self, mac: MACAddress) -> bool:
        """Confirm MAC is local by forcing a fresh PVE DB read.

        Args:
            mac: Candidate MAC for local ownership takeover.

        Returns:
            True when MAC exists in local instance view.
        """
        store = self._watcher.poll(force_refresh=True)
        self._monitor.instances = store
        return store.get(mac) is not None

    def _is_remote_migration_confirmed(self, mac: MACAddress, sender: NodeID) -> bool:
        """Confirm remote owner by forcing fresh cluster PVE DB read.

        Args:
            mac: Candidate migrated MAC.
            sender: Claimed owner node id from mesh payload.

        Returns:
            True when cluster mapping shows MAC owned by sender.
        """
        store = self._watcher.poll(force_refresh=True)
        owner = store.get_node_for_mac(mac)
        return owner == sender

    def _inject_local_iface_entries(self) -> None:
        """Inject one IPEntry per local iface IP (scope from netlink; host = not exported)."""
        cfg = self.config
        ifaces = cfg.arp_responder_local_iface or cfg.bridges
        if not ifaces:
            return
        raw = self._netlink.get_iface_ips(ifaces)
        if not raw:
            self.log.debug("no IPs on %s", ifaces)
        now = time.time()
        for iface_name, ip_str, scope, mac_str in raw:
            if not mac_str:
                self.log.debug("skip %s %s: no MAC", iface_name, ip_str)
                continue
            ip = IPv4Address(ip_str)
            mac = MACAddress(mac_str)
            br = BridgeName(iface_name)
            entry = IPEntry(
                ipv4=ip,
                mac=mac,
                bridge=br,
                type="bridge",
                node=NodeID(self._node_id),
                last_seen=now,
                scope=scope,
            )
            self._entries.set(entry)
            self.log.debug("inject local iface: iface=%s ip=%s mac=%s scope=%s", iface_name, ip_str, mac_str, scope)

    def _get_responder_learning_port(
        self, bridge: BridgeName, ip: IPv4Address
    ) -> Optional[OFPort]:
        """OF port where (bridge, ip) lives so ARP reply can go there for FDB learning.

        Uses active entry for (bridge, ip) → entry.node, then OVS node→port map
        (same logic as packet_monitor ARP reply).

        Returns:
            OFPort for node's port (e.g. VXLAN) if found, else None.
        """
        now = time.time()
        entry = self._entries.get_any_active_for_bridge_ip(ip, bridge, now, self.config.mesh_ttl)
        if entry and entry.node:
            node_map = self._ovs.get_bridge_node_to_ofport(str(bridge))
            ofport, _name = self._ovs.resolve_node_port(node_map, entry.node)
            if ofport is not None:
                return OFPort(str(ofport))
        return None

    def _on_migration_invalidate_fdb(
        self,
        ip: IPv4Address,
        bridge: BridgeName,
        vlan: Optional[int],
        old_owner: Optional[NodeID],
        new_owner: Optional[NodeID],
    ) -> None:
        """Queue async invalidation on owner change."""
        if not self.config.migration_invalidates_fdb:
            return
        if old_owner == new_owner:
            return
        self._owner_changes_count += 1
        if self._event_loop is None:
            return
        self._event_loop.call_soon_threadsafe(
            self._enqueue_migration_invalidation,
            ip,
            bridge,
            vlan,
            old_owner,
            new_owner,
        )

    def _enqueue_migration_invalidation(
        self,
        ip: IPv4Address,
        bridge: BridgeName,
        vlan: Optional[int],
        old_owner: Optional[NodeID],
        new_owner: Optional[NodeID],
    ) -> None:
        """Enqueue owner change on asyncio queue."""
        if self._migration_invalidation_queue is None:
            return
        try:
            self._migration_invalidation_queue.put_nowait((ip, bridge, vlan, old_owner, new_owner))
        except asyncio.QueueFull:
            self.log.warning(
                "migration invalidate queue full ip=%s bridge=%s vlan=%s owner=%s->%s",
                ip,
                bridge,
                vlan,
                old_owner,
                new_owner,
            )

    def _process_migration_invalidation(
        self,
        ip: IPv4Address,
        bridge: BridgeName,
        vlan: Optional[int],
        old_owner: Optional[NodeID],
        new_owner: Optional[NodeID],
    ) -> None:
        """Invalidate FDB and kernel ARP."""
        if old_owner == new_owner:
            return
        entry = self._entries.get(ip, bridge, vlan)
        if entry is None:
            return
        fdb_invalidated = self._ovs.invalidate_local_fdb_mac(bridge, entry.mac, vlan=vlan)
        arp_invalidated = self._netlink.invalidate_kernel_arp(ip, bridge, mac=entry.mac)
        if fdb_invalidated or arp_invalidated:
            self.log.info(
                "migration invalidate ip=%s mac=%s bridge=%s vlan=%s fdb=%s arp=%s owner=%s->%s",
                ip,
                entry.mac,
                bridge,
                vlan,
                fdb_invalidated,
                arp_invalidated,
                old_owner,
                new_owner,
            )

    async def _migration_invalidation_worker_loop(self) -> None:
        """Process owner changes async."""
        if self._migration_invalidation_queue is None:
            return
        loop = asyncio.get_running_loop()
        while True:
            try:
                item = await self._migration_invalidation_queue.get()
            except asyncio.CancelledError:
                break
            try:
                await loop.run_in_executor(
                    None,
                    self._process_migration_invalidation,
                    *item,
                )
            except Exception as e:
                self.log.warning("migration invalidate failed: %s", e, exc_info=True)

    def _sync_arp_responder_flows_once(self) -> None:
        """Inject local iface IPs and sync OFS ARP responder flows with store."""
        self._inject_local_iface_entries()
        desired = self.get_desired_responders()
        get_port = self._get_responder_learning_port if self.config.arp_responder_learning else None
        self._of.sync_arp_responder_flows(desired=desired, get_learning_port=get_port)

    def get_desired_responders(self) -> Set[_ResponderKey]:
        """Set of (bridge, ip, mac, vlan) that should have ARP responder flows."""
        cfg = self.config
        local_vlans = self._get_local_vlans() if cfg.arp_reply_localize_vlan else None
        return compute_desired_responders(
            self._entries,
            cfg.mesh_ttl,
            self._of.bridges,
            node_id=self._node_id,
            arp_reply_local=cfg.arp_reply_local,
            arp_responder_reply_local=cfg.arp_responder_reply_local,
            arp_reply_strict_vlan=cfg.arp_reply_strict_vlan,
            arp_reply_no_vlan=cfg.arp_reply_no_vlan,
            arp_reply_remote_vlan=cfg.arp_reply_remote_vlan,
            for_responder=True,
            local_vlans=local_vlans,
            arp_reply_localize_vlan=cfg.arp_reply_localize_vlan,
        )

    def _expire_entries(self, now: float) -> None:
        """Mark entries as expired when TTL elapsed."""
        if (now - self._start_time) < self.config.expiry_grace_sec:
            return
        for key, entry in self._entries.items():
            if entry.expired is not None:
                continue
            last = entry.last_activity()
            if last and (now - last) > self.config.mesh_ttl:
                self._entries.update(key, expired=now)
                self._entries_expired_count += 1
                self.log.debug("db ip expired ip=%s mac=%s", entry.ipv4, entry.mac)
                self.log.info("expired ip=%s mac=%s last=%.0f", entry.ipv4, entry.mac, last)

    def _cleanup_expired_entries(self, now: float) -> None:
        """Remove entries that have been expired longer than cleanup threshold."""
        sec = self.config.expired_entry_cleanup_sec
        if sec <= 0:
            return
        to_drop = [
            (key, entry)
            for key, entry in self._entries.items()
            if entry.expired is not None and (now - entry.expired) >= sec
        ]
        for key, entry in to_drop:
            self._entries.discard(key)
            self._entries_cleaned_count += 1
            self.log.info("cleanup ip=%s mac=%s", entry.ipv4, entry.mac)
        if to_drop:
            self.log.debug("cleaned %d expired entries from db", len(to_drop))

    def _restart_process(self, msg: str) -> None:
        """Log error, stop/start mesh, then exit so supervisor restarts process."""
        self.log.error("%s; restarting process", msg)
        self._mesh.stop()
        self._mesh.start()
        sys.exit(1)

    def _check_snoop_silence(self, now: float) -> None:
        """Warn periodically on snoop idle (idle node is OK); restart only after restart_sec."""
        wafter = self.config.snoop_silence_warn_after_sec
        wint = self.config.snoop_silence_warn_interval_sec
        rsec = self.config.snoop_silence_restart_sec
        if wafter <= 0 and rsec <= 0:
            return
        last = self._monitor.get_last_snoop_time()
        if last <= 0:
            return
        silence = now - last
        if wafter > 0 and silence < wafter:
            self._last_snoop_silence_warn_ts = 0.0
            return
        if rsec > 0 and silence >= rsec:
            self._restart_process("no IP snooped for %.0fs (>= %.0fs); restart threshold" % (silence, rsec))
        if wafter <= 0:
            return
        last_emit = self._last_snoop_silence_warn_ts
        should_emit = last_emit <= 0.0 or (wint > 0 and (now - last_emit) >= wint)
        if should_emit:
            rtxt = ("; restart after %.0fs silent" % rsec) if rsec > 0 else ""
            self.log.warning(
                "no IP snooped for %.0fs (>= %.0fs); idle node may be OK%s",
                silence,
                wafter,
                rtxt,
            )
            self._last_snoop_silence_warn_ts = now

    def _ping_neighbours_loop(self) -> None:
        """Daemon: every interval ping all mesh neighbours (random order, 0–50ms between)."""
        cfg = self.config
        interval = max(0.01, cfg.ping_neighbours_interval)
        while not self._stop.wait(interval):
            node_last_seen = self._mesh.get_node_last_seen()
            neighbours = [n for n in node_last_seen if n != self._node_id]
            if not neighbours:
                continue
            random.shuffle(neighbours)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            except OSError as e:
                self.log.debug("ping neighbours: raw socket: %s", e)
                continue
            try:
                for ip in neighbours:
                    try:
                        send_icmp_echo(ip, sock)
                    except OSError as e:
                        self.log.debug("ping %s: %s", ip, e)
                    time.sleep(random.uniform(0, 0.05))
            finally:
                try:
                    sock.close()
                except Exception:
                    pass

    @property
    def _peers_path(self) -> str:
        return os.path.join(self.config.state_dir, "arp_refresh_peers.json")

    @property
    def _mesh_seen_path(self) -> str:
        return os.path.join(self.config.state_dir, "mesh_last_seen.json")

    def _save_all_state(self) -> None:
        """Persist entries, mesh last-seen, peer tracker."""
        self._state_mgr.save_from(self._entries)
        save_json(self._mesh_seen_path, self._mesh.get_node_last_seen())
        if self._peer_tracker:
            save_json(self._peers_path, self._peer_tracker.to_dict())

    def _start_ping_thread_if_enabled(self) -> None:
        """Start neighbour ping thread only when enabled and allowed."""
        if self.config.ping_neighbours_interval <= 0:
            return
        if not raw_icmp_socket_ok():
            self.log.warning(
                "ping neighbours disabled: missing CAP_NET_RAW (cannot open raw ICMP socket)"
            )
            return
        self._ping_thread = threading.Thread(target=self._ping_neighbours_loop, daemon=True)
        self._ping_thread.start()

    def run(self) -> None:
        """Main entry point: run async loop or sync fallback."""
        cfg = self.config
        self._update_instances()
        _LIST_DISPATCH = [
            ("list_db", dump.dump_db),
            ("list_pve_db", dump.dump_pve_db),
            ("list_peers", dump.dump_peers),
            ("list_neigh", dump.dump_neigh),
            ("list_refreshers", dump.dump_refreshers),
            ("list_responders", dump.dump_responders),
            ("list_vlans", dump.dump_vlans),
        ]
        for attr, func in _LIST_DISPATCH:
            if getattr(cfg, attr):
                func(self)
                return
        if cfg.list_fdb is not None:
            bridge = (cfg.list_fdb or cfg.bridges[0]) if cfg.bridges else "vmbr0"
            dump.dump_fdb(self, bridge)
            return

        # Run async main loop
        try:
            asyncio.run(self._run_async())
        except KeyboardInterrupt:
            pass
        except Exception as e:
            self.log.exception("main loop failed: %s", e)
            raise  # let main() catch and exit with 1

    def last_loop_tick(self) -> float:
        """Return unix time of the latest main-loop tick.

        Args:
            None.

        Returns:
            Last loop tick timestamp, or 0.0 before loop starts.
        """
        return self._last_loop_tick

    def runtime_counters(self) -> dict[str, int]:
        """Return runtime event counters for metrics.

        Args:
            None.

        Returns:
            Dict with owner/expiry lifecycle counters.
        """
        return {
            "owner_changes": self._owner_changes_count,
            "entries_expired": self._entries_expired_count,
            "entries_cleaned": self._entries_cleaned_count,
        }

    def entry_counts(self) -> dict[str, int]:
        """Return total, active and inactive entry counts.

        Args:
            None.

        Returns:
            Dict with keys: total, active, inactive.
        """
        total = 0
        active = 0
        inactive = 0
        for _key, entry in self._entries.items():
            total += 1
            if entry.expired is None:
                active += 1
            else:
                inactive += 1
        return {"total": total, "active": active, "inactive": inactive}

    async def _run_async(self) -> None:
        """Async main loop: poll instances, persist, mesh broadcast, OVS ensure."""
        cfg = self.config
        instances = self._watcher.poll()
        n_inst = len(instances)
        self.log.info(
            "started bridges=%s db=%s state_dir=%s instances=%d",
            cfg.bridges, cfg.db_path, cfg.state_dir, n_inst,
        )
        for mac, info in instances.items():
            tags_str = ",".join(info.tags) if info.tags else "-"
            self.log.info(
                "discovered vmid=%s type=%s mac=%s bridge=%s tags=%s",
                info.vmid, info.type, mac, info.bridge, tags_str,
            )
        if n_inst == 0:
            self.log.warning("no VM/LXC MACs from DB; snooping will record nothing until instances exist")

        # Restore state; on failure start clean and log
        if cfg.no_load_state:
            self.log.info("skipping state load (--no-load-state)")
        else:
            try:
                max_age = cfg.load_state_max_age_sec if cfg.load_state_max_age_sec > 0 else None
                self._state_mgr.load_into(self._entries, max_age_sec=max_age)
                self.log.debug("db loaded %d entries from state", len(self._entries))
                # Drop entries with no node (origin unknown); must come from snoop or mesh.
                dropped = [key for key, entry in self._entries.items() if not entry.node]
                for key in dropped:
                    self._entries.discard(key)
                if dropped:
                    self.log.warning("dropped %d entries with no node (state invalid or legacy)", len(dropped))
            except Exception as e:
                self.log.error("state load failed, starting clean: %s", e)
                # Clear any partial load so we start clean
                for key in list(self._entries.keys()):
                    self._entries.discard(key)

        if cfg.arp_refresh and self._peer_tracker:
            self._peer_tracker.load_from_dict(load_json(self._peers_path, {}))

        self._start_time = time.time()
        if cfg.of_install:
            self._of.ensure_flows()
            if cfg.arp_responder:
                self._sync_arp_responder_flows_once()
        else:
            self.log.info(
                "OpenFlow rule installation disabled (--no-of-install); not installing or verifying flows"
            )

        # Start async packet sender
        loop = asyncio.get_running_loop()
        self._event_loop = loop
        self._async_sender = AsyncPacketSender(self.log, max_queue=cfg.packet_out_max_queue)
        self._async_sender.start(loop)
        self._of.set_async_sender(self._async_sender)

        self._mesh.start()
        self._monitor_threads = self._monitor.start()
        self._migration_invalidation_queue = asyncio.Queue(maxsize=2048)
        self._migration_invalidation_worker_task = loop.create_task(self._migration_invalidation_worker_loop())
        if self._refresher:
            self._refresher.start()
        self._start_ping_thread_if_enabled()
        last_save = last_mesh = last_expiry = last_of_verify = last_arp_responder_sync = last_mesh_silence = time.time()
        try:
            while not self._stop.is_set():
                await asyncio.sleep(cfg.main_loop_interval)
                self._last_loop_tick = time.time()
                self._update_instances()
                now = time.time()
                # If no mesh message for 10*keepalive: warn and restart mesh (optional)
                if (
                    cfg.mesh_silence_restart
                    and cfg.mesh_keepalive_interval > 0
                    and (now - last_mesh_silence) >= cfg.expiry_check_interval
                ):
                    last_mesh_silence = now
                    last_recv = self._mesh.get_last_recv_any()
                    if last_recv > 0:
                        silence_sec = 10.0 * cfg.mesh_keepalive_interval
                        if (now - last_recv) >= silence_sec:
                            self._restart_process(
                                "no mesh message received for %.0fs (>= %.0fs)" % (now - last_recv, silence_sec)
                            )
                if now - last_expiry >= cfg.expiry_check_interval:
                    self._expire_entries(now)
                    self._cleanup_expired_entries(now)
                    self._check_snoop_silence(now)
                    last_expiry = now
                if (
                    cfg.of_install
                    and cfg.of_verify_interval > 0
                    and (now - last_of_verify) >= cfg.of_verify_interval
                ):
                    await self._of.verify_and_restore_flows()
                    last_of_verify = now
                if (
                    cfg.of_install
                    and cfg.arp_responder
                    and (now - last_arp_responder_sync) >= cfg.arp_responder_sync_interval
                ):
                    self._sync_arp_responder_flows_once()
                    last_arp_responder_sync = now
                if now - last_save >= cfg.save_interval:
                    self._save_all_state()
                    last_save = now
                if now - last_mesh >= cfg.mesh_interval:
                    self._mesh.send_once()
                    last_mesh = now
        finally:
            self.log.info("stopping")
            self._stop.set()
            if self._migration_invalidation_worker_task:
                self._migration_invalidation_worker_task.cancel()
                try:
                    await self._migration_invalidation_worker_task
                except asyncio.CancelledError:
                    pass
            self._migration_invalidation_worker_task = None
            self._migration_invalidation_queue = None
            self._event_loop = None
            if self._ping_thread and self._ping_thread.is_alive():
                self._ping_thread.join(timeout=3)
            self._monitor.stop()
            if self._refresher:
                self._refresher.stop()
                self._refresher.join(timeout=2)
            self._mesh.stop()
            if self._async_sender:
                try:
                    await self._async_sender.stop()
                except Exception as e:
                    self.log.debug("async_sender stop: %s", e)
            try:
                self._save_all_state()
            except Exception as e:
                self.log.warning("save state on shutdown: %s", e)
            if cfg.of_install:
                try:
                    self._of.del_flows()
                except Exception as e:
                    self.log.debug("del_flows on shutdown: %s", e)
