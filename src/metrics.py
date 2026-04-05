"""Prometheus/OpenMetrics exporter for ovs-vm-arbiter."""
from __future__ import annotations

import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from src.config import Config, ROLE
from src.core import ArbiterCore
from src.main import get_version_string


class ArbiterMetricsCollector:
    """Collector that snapshots arbiter state at scrape time."""

    def __init__(self, core: ArbiterCore, config: Config, extra: bool) -> None:
        self._core = core
        self._config = config
        self._extra = extra

    def collect(self) -> Any:
        """Yield metric families from current state."""
        from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily  # type: ignore[import-not-found]

        now = time.time()
        counters = self._core.runtime_counters()
        watcher = self._core._watcher
        mesh = self._core._mesh
        ofm = self._core._of
        monitor = self._core._monitor
        peer_tracker = self._core._peer_tracker

        build = GaugeMetricFamily(
            "ovs_vm_arbiter_build_info",
            "Build and role info.",
            labels=["version", "role"],
        )
        build.add_metric([str(get_version_string()), str(ROLE)], 1)
        yield build

        cfg_info = GaugeMetricFamily(
            "ovs_vm_arbiter_config_info",
            "Runtime config info.",
            labels=["node", "bridges_count", "arp_responder_enabled"],
        )
        cfg_info.add_metric(
            [str(self._core._node_id), str(len(self._config.bridges)), "1" if self._config.arp_responder else "0"],
            1,
        )
        yield cfg_info

        yield GaugeMetricFamily(
            "ovs_vm_arbiter_mesh_sign_enabled",
            "Mesh signing enabled flag.",
            value=1 if self._config.get_sign_key() else 0,
        )

        pve_instances = GaugeMetricFamily(
            "ovs_vm_arbiter_pve_instances",
            "Parsed PVE instances.",
            labels=["type"],
        )
        pve_counts = {"qemu": 0, "lxc": 0}
        for _mac, info in self._core._monitor.instances.items():
            t = str(info.type)
            if t in pve_counts:
                pve_counts[t] += 1
        pve_instances.add_metric(["qemu"], pve_counts["qemu"])
        pve_instances.add_metric(["lxc"], pve_counts["lxc"])
        yield pve_instances

        yield GaugeMetricFamily(
            "ovs_vm_arbiter_pve_config_db_ok",
            "PVE config.db health flag.",
            value=1 if watcher.db_ok() else 0,
        )
        yield GaugeMetricFamily(
            "ovs_vm_arbiter_pve_config_db_last_success_unixtime",
            "Last successful PVE config.db read time.",
            value=watcher.last_db_success_time(),
        )

        entries = self._core.entry_counts()
        yield GaugeMetricFamily("ovs_vm_arbiter_entries_total", "Current entries.", value=entries["total"])
        yield GaugeMetricFamily("ovs_vm_arbiter_entries_active_total", "Active entries.", value=entries["active"])
        yield GaugeMetricFamily("ovs_vm_arbiter_entries_inactive_total", "Inactive entries.", value=entries["inactive"])

        yield GaugeMetricFamily(
            "ovs_vm_arbiter_process_uptime_seconds",
            "Process uptime seconds.",
            value=max(0.0, now - self._core._start_time),
        )
        last_snoop = self._core._monitor.get_last_snoop_time()
        snoop_age = -1.0 if last_snoop <= 0 else max(0.0, now - last_snoop)
        yield GaugeMetricFamily("ovs_vm_arbiter_last_snoop_age_seconds", "Last snoop age.", value=snoop_age)
        yield GaugeMetricFamily(
            "ovs_vm_arbiter_main_loop_tick_unixtime",
            "Last main loop tick timestamp.",
            value=self._core.last_loop_tick(),
        )

        yield GaugeMetricFamily(
            "ovs_vm_arbiter_mesh_known_nodes",
            "Known mesh nodes.",
            value=len(mesh.get_node_last_seen()),
        )
        peer_ttl = GaugeMetricFamily(
            "ovs_vm_arbiter_mesh_peer_ttl_seconds",
            "Remaining peer TTL by mesh peer id.",
            labels=["peer_ip"],
        )
        for peer, last_seen in sorted(mesh.get_node_last_seen().items()):
            ttl_val = max(0.0, float(self._config.mesh_ttl) - max(0.0, now - float(last_seen)))
            peer_ttl.add_metric([str(peer)], ttl_val)
        yield peer_ttl
        last_recv = mesh.get_last_recv_any()
        peer_age = -1.0 if last_recv <= 0 else max(0.0, now - last_recv)
        yield GaugeMetricFamily(
            "ovs_vm_arbiter_mesh_peer_messages_age_seconds",
            "Age since last peer message.",
            value=peer_age,
        )

        refresh_peers = 0
        if peer_tracker is not None:
            refresh_peers = len(peer_tracker.get_active_peers_with_ttl())
        yield GaugeMetricFamily(
            "ovs_vm_arbiter_arp_refresh_peers_total",
            "Active ARP refresh peer pairs.",
            value=refresh_peers,
        )

        yield GaugeMetricFamily(
            "ovs_vm_arbiter_arp_responder_flows_total",
            "Installed ARP responder flows.",
            value=ofm.arp_responder_flow_count(),
        )
        per_bridge = GaugeMetricFamily(
            "ovs_vm_arbiter_arp_responder_flows",
            "ARP responder flows by bridge.",
            labels=["bridge"],
        )
        for br, cnt in sorted(ofm.arp_responder_flows_by_bridge().items()):
            per_bridge.add_metric([br], cnt)
        yield per_bridge

        mesh_counters = mesh.get_mesh_counters()
        mesh_migrations = mesh.get_migration_counters()
        monitor_migrations = monitor.migration_counters()
        yield CounterMetricFamily(
            "ovs_vm_arbiter_mesh_rx_messages_total",
            "Mesh RX messages.",
            value=mesh_counters["rx"],
        )
        yield CounterMetricFamily(
            "ovs_vm_arbiter_mesh_tx_messages_total",
            "Mesh TX messages.",
            value=mesh_counters["tx"],
        )
        yield CounterMetricFamily(
            "ovs_vm_arbiter_mesh_rx_invalid_total",
            "Invalid mesh RX messages.",
            value=mesh_counters["rx_invalid"],
        )

        owner = CounterMetricFamily(
            "ovs_vm_arbiter_owner_changes_total",
            "Ownership changes.",
            labels=["reason"],
        )
        owner.add_metric(["migration"], counters["owner_changes"])
        yield owner
        yield CounterMetricFamily(
            "ovs_vm_arbiter_entries_expired_total",
            "Expired entries.",
            value=counters["entries_expired"],
        )
        yield CounterMetricFamily(
            "ovs_vm_arbiter_entries_cleaned_total",
            "Cleaned expired entries.",
            value=counters["entries_cleaned"],
        )
        yield CounterMetricFamily(
            "ovs_vm_arbiter_ip_migrations_total",
            "IP ownership migrations.",
            value=counters["owner_changes"],
        )
        migration_refused = CounterMetricFamily(
            "ovs_vm_arbiter_migration_refused_total",
            "Refused migration decisions.",
            labels=["reason"],
        )
        migration_refused.add_metric(
            ["local_confirm_failed"],
            monitor_migrations.get("local_refused", 0),
        )
        yield migration_refused
        migration_confirmed = CounterMetricFamily(
            "ovs_vm_arbiter_migration_confirmed_total",
            "Migration confirmations.",
            labels=["reason"],
        )
        migration_confirmed.add_metric(
            ["local_confirmed"],
            monitor_migrations.get("local_confirmed", 0),
        )
        yield migration_confirmed
        if self._config.verify_remote_migration:
            yield CounterMetricFamily(
                "ovs_vm_arbiter_remote_migration_confirmed_total",
                "Remote migration confirmations.",
                value=mesh_migrations.get("remote_confirmed", 0),
            )
            yield CounterMetricFamily(
                "ovs_vm_arbiter_remote_migration_refused_total",
                "Remote migration refusals.",
                value=mesh_migrations.get("remote_refused", 0),
            )

        db_polls = watcher.db_poll_counts()
        db_poll_counter = CounterMetricFamily(
            "ovs_vm_arbiter_db_polls_total",
            "DB poll results.",
            labels=["result"],
        )
        for k in ("ok", "fail", "skipped"):
            db_poll_counter.add_metric([k], db_polls.get(k, 0))
        yield db_poll_counter

        sync = ofm.arp_responder_sync_counts()
        sync_counter = CounterMetricFamily(
            "ovs_vm_arbiter_arp_responder_sync_total",
            "ARP responder sync results.",
            labels=["result"],
        )
        sync_counter.add_metric(["ok"], sync.get("ok", 0))
        sync_counter.add_metric(["error"], sync.get("error", 0))
        yield sync_counter
        yield CounterMetricFamily(
            "ovs_vm_arbiter_arp_responder_flows_added_total",
            "ARP responder flow adds.",
            value=sync.get("added", 0),
        )
        yield CounterMetricFamily(
            "ovs_vm_arbiter_arp_responder_flows_removed_total",
            "ARP responder flow removals.",
            value=sync.get("removed", 0),
        )
        arp_cnt = monitor.arp_counters()
        yield CounterMetricFamily(
            "ovs_vm_arbiter_arp_reply_attempts_total",
            "ARP reply attempts.",
            value=arp_cnt.get("reply_attempt", 0),
        )
        yield CounterMetricFamily(
            "ovs_vm_arbiter_arp_reply_sent_total",
            "ARP replies sent.",
            value=arp_cnt.get("reply_sent", 0),
        )
        yield CounterMetricFamily(
            "ovs_vm_arbiter_arp_reply_failed_total",
            "ARP replies failed at send.",
            value=arp_cnt.get("reply_failed", 0),
        )
        yield CounterMetricFamily(
            "ovs_vm_arbiter_arp_reply_skipped_total",
            "ARP replies skipped.",
            value=arp_cnt.get("reply_skipped", 0),
        )
        yield CounterMetricFamily(
            "ovs_vm_arbiter_arp_reinject_sent_total",
            "ARP reinject sends.",
            value=arp_cnt.get("reinject_sent", 0),
        )
        yield CounterMetricFamily(
            "ovs_vm_arbiter_arp_reinject_failed_total",
            "ARP reinject send failures.",
            value=arp_cnt.get("reinject_failed", 0),
        )

        if self._extra:
            info = GaugeMetricFamily(
                "ovs_vm_arbiter_entry_mapping_info",
                "Entry mapping info.",
                labels=["ip", "mac", "bridge", "vlan", "node", "snoop_origin"],
            )
            ttl = GaugeMetricFamily(
                "ovs_vm_arbiter_entry_mapping_ttl_seconds",
                "Entry mapping TTL seconds.",
                labels=["ip", "mac", "bridge", "vlan", "node"],
            )
            for (_k, entry) in self._core._entries.items():
                ip_s = str(entry.ipv4)
                mac_s = str(entry.mac)
                br_s = str(entry.bridge) if entry.bridge is not None else "-"
                vlan_s = str(entry.vlan) if entry.vlan is not None else "-"
                node_s = str(entry.node) if entry.node is not None else "-"
                origin = ",".join(entry.snoop_origin or []) if entry.snoop_origin else "-"
                info.add_metric([ip_s, mac_s, br_s, vlan_s, node_s, origin], 1)
                if entry.expired is not None:
                    ttl_val = 0.0
                else:
                    last = entry.last_activity() or 0.0
                    ttl_val = max(0.0, self._config.mesh_ttl - (now - last)) if last > 0 else 0.0
                ttl.add_metric([ip_s, mac_s, br_s, vlan_s, node_s], ttl_val)
            yield info
            yield ttl


class PrometheusMetricsServer:
    """HTTP server that exposes Prometheus and OpenMetrics."""

    def __init__(self, core: ArbiterCore, config: Config, host: str = "localhost") -> None:
        self._core = core
        self._config = config
        self._host = host
        self._http: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start metrics HTTP server in background thread."""
        from prometheus_client import CollectorRegistry, generate_latest  # type: ignore[import-not-found]
        from prometheus_client import CONTENT_TYPE_LATEST as PROM_CONTENT_TYPE  # type: ignore[import-not-found]
        from prometheus_client.openmetrics.exposition import CONTENT_TYPE_LATEST as OPENMETRICS_CONTENT_TYPE  # type: ignore[import-not-found]
        from prometheus_client.openmetrics.exposition import generate_latest as generate_openmetrics  # type: ignore[import-not-found]

        collector = ArbiterMetricsCollector(self._core, self._config, self._config.prometheus_metrics_extra)

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                if self.path != "/metrics":
                    self.send_response(HTTPStatus.NOT_FOUND)
                    self.end_headers()
                    return
                registry = CollectorRegistry(auto_describe=True)
                registry.register(collector)
                accept = self.headers.get("Accept", "")
                if "application/openmetrics-text" in accept:
                    body = generate_openmetrics(registry)
                    content_type = OPENMETRICS_CONTENT_TYPE
                else:
                    body = generate_latest(registry)
                    content_type = PROM_CONTENT_TYPE
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, _format: str, *_args: object) -> None:
                return

        self._http = ThreadingHTTPServer((self._host, int(self._config.prometheus_port)), _Handler)
        self._thread = threading.Thread(target=self._http.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop metrics HTTP server."""
        if self._http is None:
            return
        self._http.shutdown()
        self._http.server_close()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=2)
        self._http = None
        self._thread = None


def start_metrics_server(core: ArbiterCore, config: Config, log: Any) -> PrometheusMetricsServer:
    """Start Prometheus/OpenMetrics exporter server.

    Args:
        core: Arbiter core instance.
        config: Runtime config instance.
        log: Logger-like object.

    Returns:
        Started PrometheusMetricsServer.
    """
    server = PrometheusMetricsServer(core, config, host=config.prometheus_host)
    server.start()
    log.info(
        "prometheus metrics enabled on %s:%s/metrics",
        config.prometheus_host,
        config.prometheus_port,
    )
    return server
