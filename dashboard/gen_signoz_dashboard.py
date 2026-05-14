#!/usr/bin/env python3
"""Emit SigNoz v5 dashboard JSON for ovs-vm-arbiter (stdout)."""
from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass, field
from typing import Any

DASH_UUID = "8d2a1f3c-6b4e-5a7d-9e0f-1a2b3c4d5e6f"


def qid(seed: str) -> str:
    h = hashlib.md5(seed.encode(), usedforsecurity=False).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def tag_filter(key: str) -> dict[str, Any]:
    return {"key": {"dataType": "string", "key": key, "type": "tag"}, "op": "IN", "value": f"${key}"}


def filters_host() -> dict[str, Any]:
    return {"items": [tag_filter("host")], "op": "AND"}


def filters_host_peer() -> dict[str, Any]:
    return {"items": [tag_filter("host"), tag_filter("peer_ip")], "op": "AND"}


def filters_host_bridge() -> dict[str, Any]:
    return {"items": [tag_filter("host"), tag_filter("bridge")], "op": "AND"}


SELECTED_LOG_FIELDS = [
    {"fieldContext": "log", "name": "timestamp", "signal": "logs", "type": "log"},
    {"fieldContext": "log", "name": "body", "signal": "logs", "type": "log"},
]

SELECTED_TRACES_FIELDS = [
    {"fieldContext": "resource", "fieldDataType": "string", "name": "service.name", "signal": "traces"},
    {"fieldContext": "span", "fieldDataType": "string", "name": "name", "signal": "traces"},
    {"fieldContext": "span", "name": "duration_nano", "signal": "traces"},
]

EMPTY_QUERY = {"builder": {"queryData": [], "queryFormulas": []}, "id": "", "queryType": "builder"}


def base_widget(
    wid: str,
    title: str,
    panel: str,
    query: dict[str, Any],
    *,
    desc: str = "",
    legend_pos: str | None = None,
    null_zero: str = "transparent",
    soft_max: Any = None,
    soft_min: Any = None,
    y_unit: str = "short",
    opacity: str = "1",
    time_pref: str = "GLOBAL_TIME",
) -> dict[str, Any]:
    w: dict[str, Any] = {
        "contextLinks": {"linksData": []},
        "description": desc,
        "id": wid,
        "nullZeroValues": null_zero,
        "opacity": opacity,
        "panelTypes": panel,
        "query": query,
        "selectedLogFields": SELECTED_LOG_FIELDS,
        "selectedTracesFields": SELECTED_TRACES_FIELDS,
        "softMax": soft_max,
        "softMin": soft_min,
        "title": title,
    }
    if legend_pos is not None:
        w["legendPosition"] = legend_pos
    if panel in ("graph", "value"):
        w["timePreferance"] = time_pref
    if panel == "graph":
        w["yAxisUnit"] = y_unit
    return w


def row_widget(wid: str, title: str) -> dict[str, Any]:
    return base_widget(wid, title, "row", EMPTY_QUERY, soft_max=None, soft_min=None)


def metric_query(
    seed: str,
    metric: str,
    time_agg: str,
    space_agg: str,
    filt: dict[str, Any],
    *,
    group_by: list[dict[str, Any]],
    legend: str = "",
    step: int = 60,
) -> dict[str, Any]:
    return {
        "builder": {
            "queryData": [
                {
                    "aggregations": [
                        {
                            "metricName": metric,
                            "spaceAggregation": space_agg,
                            "temporality": "unspecified",
                            "timeAggregation": time_agg,
                        }
                    ],
                    "dataSource": "metrics",
                    "expression": "A",
                    "filters": filt,
                    "functions": [],
                    "groupBy": group_by,
                    "legend": legend,
                    "orderBy": [],
                    "queryName": "A",
                    "selectColumns": [],
                    "stepInterval": step,
                }
            ],
            "queryFormulas": [],
        },
        "id": qid(seed),
        "queryType": "builder",
    }


def graph_panel(
    wid: str,
    title: str,
    metric: str,
    time_agg: str,
    space_agg: str,
    filt: dict[str, Any],
    group_by: list[dict[str, Any]],
    *,
    legend: str = "",
    desc: str = "",
    y_unit: str = "short",
    null_zero: str | None = None,
    legend_pos: str = "bottom",
    step: int = 60,
) -> dict[str, Any]:
    if null_zero is None:
        null_zero = "zero" if time_agg == "rate" else "transparent"
    q = metric_query(wid, metric, time_agg, space_agg, filt, group_by=group_by, legend=legend, step=step)
    smax = 0 if null_zero == "zero" else None
    smin = 0 if null_zero == "zero" else None
    return base_widget(
        wid,
        title,
        "graph",
        q,
        desc=desc,
        legend_pos=legend_pos,
        null_zero=null_zero,
        soft_max=smax,
        soft_min=smin,
        y_unit=y_unit,
    )


def value_panel(
    wid: str,
    title: str,
    metric: str,
    filt: dict[str, Any],
    *,
    space_agg: str = "max",
    group_by: list | None = None,
    desc: str = "",
) -> dict[str, Any]:
    gb = group_by if group_by is not None else []
    q = metric_query(wid, metric, "latest", space_agg, filt, group_by=gb, legend="")
    q["builder"]["queryData"][0]["reduceTo"] = "last"
    return base_widget(wid, title, "value", q, desc=desc, null_zero="zero")


def gb(*keys: str) -> list[dict[str, Any]]:
    return [{"dataType": "string", "key": k, "type": "tag"} for k in keys]


@dataclass
class Dash:
    layout: list[dict[str, Any]] = field(default_factory=list)
    widgets: list[dict[str, Any]] = field(default_factory=list)
    y: int = 0

    def row(self, wid: str, title: str) -> None:
        self.layout.append({"h": 1, "i": wid, "w": 12, "x": 0, "y": self.y})
        self.widgets.append(row_widget(wid, title))
        self.y += 1

    def cells(self, items: list[tuple[str, int, int, int, dict[str, Any]]]) -> None:
        """Each item: id, w, h, x, widget dict. Same grid row (shared y)."""
        y0 = self.y
        max_h = 0
        for wid, w, h, x, widget in items:
            self.layout.append({"h": h, "i": wid, "w": w, "x": x, "y": y0})
            self.widgets.append(widget)
            max_h = max(max_h, h)
        self.y = y0 + max_h


def main() -> None:
    d = Dash()
    oh = 5

    d.row("row_overview", "Overview")
    d.cells(
        [
            ("v_ent", 3, 3, 0, value_panel("v_ent", "Entries (total)", "ovs_vm_arbiter_entries_total", filters_host())),
            ("v_ea", 3, 3, 3, value_panel("v_ea", "Entries active", "ovs_vm_arbiter_entries_active_total", filters_host())),
            ("v_ei", 3, 3, 6, value_panel("v_ei", "Entries inactive", "ovs_vm_arbiter_entries_inactive_total", filters_host())),
            ("v_nodes", 3, 3, 9, value_panel("v_nodes", "Mesh known nodes", "ovs_vm_arbiter_mesh_known_nodes", filters_host())),
        ]
    )
    d.cells(
        [
            (
                "g_uptime",
                4,
                oh,
                0,
                graph_panel(
                    "g_uptime",
                    "Process uptime (s)",
                    "ovs_vm_arbiter_process_uptime_seconds",
                    "latest",
                    "max",
                    filters_host(),
                    [],
                    null_zero="transparent",
                ),
            ),
            (
                "g_snoop",
                4,
                oh,
                4,
                graph_panel(
                    "g_snoop",
                    "Last snoop age (s)",
                    "ovs_vm_arbiter_last_snoop_age_seconds",
                    "latest",
                    "max",
                    filters_host(),
                    [],
                    null_zero="transparent",
                ),
            ),
            (
                "g_pmsg",
                4,
                oh,
                8,
                graph_panel(
                    "g_pmsg",
                    "Mesh peer messages age (s)",
                    "ovs_vm_arbiter_mesh_peer_messages_age_seconds",
                    "latest",
                    "max",
                    filters_host(),
                    [],
                    null_zero="transparent",
                ),
            ),
        ]
    )
    d.cells(
        [
            (
                "g_build",
                6,
                oh,
                0,
                graph_panel(
                    "g_build",
                    "Build info (latest)",
                    "ovs_vm_arbiter_build_info",
                    "latest",
                    "avg",
                    filters_host(),
                    gb("version", "role"),
                    legend="{{version}} / {{role}}",
                    desc="Gauge 1 with version and role labels.",
                ),
            ),
            (
                "g_cfg",
                6,
                oh,
                6,
                graph_panel(
                    "g_cfg",
                    "Config info (latest)",
                    "ovs_vm_arbiter_config_info",
                    "latest",
                    "avg",
                    filters_host(),
                    gb("node", "bridges_count", "arp_responder_enabled"),
                    legend="{{node}} br={{bridges_count}} arp={{arp_responder_enabled}}",
                ),
            ),
        ]
    )
    d.cells(
        [
            (
                "g_tick",
                4,
                oh,
                0,
                graph_panel(
                    "g_tick",
                    "Main loop tick (unix time)",
                    "ovs_vm_arbiter_main_loop_tick_unixtime",
                    "latest",
                    "max",
                    filters_host(),
                    [],
                    desc="Unix timestamp of last tick; flat line suggests stalled loop.",
                ),
            ),
            (
                "g_msign",
                4,
                oh,
                4,
                graph_panel(
                    "g_msign",
                    "Mesh signing enabled",
                    "ovs_vm_arbiter_mesh_sign_enabled",
                    "latest",
                    "max",
                    filters_host(),
                    [],
                ),
            ),
            (
                "g_nwarn",
                4,
                oh,
                8,
                graph_panel(
                    "g_nwarn",
                    "Network warnings (gauge)",
                    "ovs_vm_arbiter_network_warnings_total",
                    "latest",
                    "max",
                    filters_host(),
                    [],
                    desc="Spikes indicate aggregated warning/error events.",
                ),
            ),
        ]
    )

    d.row("row_mesh", "Mesh")
    d.cells(
        [
            (
                "g_mesh_rx",
                4,
                6,
                0,
                graph_panel(
                    "g_mesh_rx",
                    "Mesh RX messages (rate)",
                    "ovs_vm_arbiter_mesh_rx_messages_total",
                    "rate",
                    "sum",
                    filters_host(),
                    [],
                    y_unit="ops",
                ),
            ),
            (
                "g_mesh_tx",
                4,
                6,
                4,
                graph_panel(
                    "g_mesh_tx",
                    "Mesh TX messages (rate)",
                    "ovs_vm_arbiter_mesh_tx_messages_total",
                    "rate",
                    "sum",
                    filters_host(),
                    [],
                    y_unit="ops",
                ),
            ),
            (
                "g_mesh_inv",
                4,
                6,
                8,
                graph_panel(
                    "g_mesh_inv",
                    "Mesh RX invalid (rate)",
                    "ovs_vm_arbiter_mesh_rx_invalid_total",
                    "rate",
                    "sum",
                    filters_host(),
                    [],
                    y_unit="ops",
                ),
            ),
        ]
    )
    d.cells(
        [
            (
                "g_ttl",
                12,
                6,
                0,
                graph_panel(
                    "g_ttl",
                    "Peer TTL remaining (s)",
                    "ovs_vm_arbiter_mesh_peer_ttl_seconds",
                    "latest",
                    "avg",
                    filters_host_peer(),
                    gb("peer_ip"),
                    legend="{{peer_ip}}",
                    desc="Filter peer_ip for series.",
                ),
            )
        ]
    )

    d.row("row_ent", "Entries & migrations")
    d.cells(
        [
            (
                "g_own",
                6,
                6,
                0,
                graph_panel(
                    "g_own",
                    "Owner changes by reason (rate)",
                    "ovs_vm_arbiter_owner_changes_total",
                    "rate",
                    "sum",
                    filters_host(),
                    gb("reason"),
                    legend="{{reason}}",
                ),
            ),
            (
                "g_ipmig",
                6,
                6,
                6,
                graph_panel(
                    "g_ipmig",
                    "IP migrations (rate)",
                    "ovs_vm_arbiter_ip_migrations_total",
                    "rate",
                    "sum",
                    filters_host(),
                    [],
                    desc="May mirror owner change semantics; rate shown as requested.",
                ),
            ),
        ]
    )
    d.cells(
        [
            (
                "g_exp",
                6,
                6,
                0,
                graph_panel(
                    "g_exp",
                    "Entries expired (rate)",
                    "ovs_vm_arbiter_entries_expired_total",
                    "rate",
                    "sum",
                    filters_host(),
                    [],
                ),
            ),
            (
                "g_clean",
                6,
                6,
                6,
                graph_panel(
                    "g_clean",
                    "Entries cleaned (rate)",
                    "ovs_vm_arbiter_entries_cleaned_total",
                    "rate",
                    "sum",
                    filters_host(),
                    [],
                ),
            ),
        ]
    )
    d.cells(
        [
            (
                "g_mcref",
                6,
                6,
                0,
                graph_panel(
                    "g_mcref",
                    "Migration confirmed by reason (rate)",
                    "ovs_vm_arbiter_migration_confirmed_total",
                    "rate",
                    "sum",
                    filters_host(),
                    gb("reason"),
                    legend="{{reason}}",
                ),
            ),
            (
                "g_mcref2",
                6,
                6,
                6,
                graph_panel(
                    "g_mcref2",
                    "Migration refused by reason (rate)",
                    "ovs_vm_arbiter_migration_refused_total",
                    "rate",
                    "sum",
                    filters_host(),
                    gb("reason"),
                    legend="{{reason}}",
                ),
            ),
        ]
    )
    d.cells(
        [
            (
                "g_rmok",
                6,
                6,
                0,
                graph_panel(
                    "g_rmok",
                    "Remote migration confirmed (rate)",
                    "ovs_vm_arbiter_remote_migration_confirmed_total",
                    "rate",
                    "sum",
                    filters_host(),
                    [],
                    desc="Emitted when verify_remote_migration is enabled.",
                ),
            ),
            (
                "g_rmno",
                6,
                6,
                6,
                graph_panel(
                    "g_rmno",
                    "Remote migration refused (rate)",
                    "ovs_vm_arbiter_remote_migration_refused_total",
                    "rate",
                    "sum",
                    filters_host(),
                    [],
                    desc="Emitted when verify_remote_migration is enabled.",
                ),
            ),
        ]
    )

    d.row("row_pve", "PVE & DB polling")
    d.cells(
        [
            (
                "g_pve_i",
                6,
                6,
                0,
                graph_panel(
                    "g_pve_i",
                    "PVE instances by type (latest)",
                    "ovs_vm_arbiter_pve_instances",
                    "latest",
                    "sum",
                    filters_host(),
                    gb("type"),
                    legend="{{type}}",
                ),
            ),
            (
                "g_pve_db",
                3,
                6,
                6,
                value_panel("g_pve_db", "PVE config.db OK", "ovs_vm_arbiter_pve_config_db_ok", filters_host()),
            ),
            (
                "g_pve_ts",
                3,
                6,
                9,
                graph_panel(
                    "g_pve_ts",
                    "PVE config.db last success (unix)",
                    "ovs_vm_arbiter_pve_config_db_last_success_unixtime",
                    "latest",
                    "max",
                    filters_host(),
                    [],
                ),
            ),
        ]
    )
    d.cells(
        [
            (
                "g_dbpoll",
                12,
                6,
                0,
                graph_panel(
                    "g_dbpoll",
                    "DB polls by result (rate)",
                    "ovs_vm_arbiter_db_polls_total",
                    "rate",
                    "sum",
                    filters_host(),
                    gb("result"),
                    legend="{{result}}",
                ),
            )
        ]
    )

    d.row("row_arp", "ARP responder & flows")
    d.cells(
        [
            (
                "g_arpp",
                3,
                3,
                0,
                value_panel("g_arpp", "ARP refresh peers", "ovs_vm_arbiter_arp_refresh_peers_total", filters_host()),
            ),
            (
                "g_arft",
                3,
                3,
                3,
                value_panel(
                    "g_arft",
                    "ARP responder flows (total)",
                    "ovs_vm_arbiter_arp_responder_flows_total",
                    filters_host(),
                ),
            ),
            (
                "g_arsync",
                6,
                3,
                6,
                graph_panel(
                    "g_arsync",
                    "ARP responder sync by result (rate)",
                    "ovs_vm_arbiter_arp_responder_sync_total",
                    "rate",
                    "sum",
                    filters_host(),
                    gb("result"),
                    legend="{{result}}",
                ),
            ),
        ]
    )
    d.cells(
        [
            (
                "g_brflow",
                12,
                6,
                0,
                graph_panel(
                    "g_brflow",
                    "ARP flows by bridge (latest)",
                    "ovs_vm_arbiter_arp_responder_flows",
                    "latest",
                    "sum",
                    filters_host_bridge(),
                    gb("bridge"),
                    legend="{{bridge}}",
                    desc="Filter bridge variable for series.",
                ),
            )
        ]
    )
    d.cells(
        [
            (
                "g_fadd",
                6,
                5,
                0,
                graph_panel(
                    "g_fadd",
                    "Flows added (rate)",
                    "ovs_vm_arbiter_arp_responder_flows_added_total",
                    "rate",
                    "sum",
                    filters_host(),
                    [],
                ),
            ),
            (
                "g_frem",
                6,
                5,
                6,
                graph_panel(
                    "g_frem",
                    "Flows removed (rate)",
                    "ovs_vm_arbiter_arp_responder_flows_removed_total",
                    "rate",
                    "sum",
                    filters_host(),
                    [],
                ),
            ),
        ]
    )
    arp_rates = [
        ("g_arpa", "ARP reply attempts (rate)", "ovs_vm_arbiter_arp_reply_attempts_total"),
        ("g_arps", "ARP replies sent (rate)", "ovs_vm_arbiter_arp_reply_sent_total"),
        ("g_arpf", "ARP replies failed (rate)", "ovs_vm_arbiter_arp_reply_failed_total"),
        ("g_arpsk", "ARP replies skipped (rate)", "ovs_vm_arbiter_arp_reply_skipped_total"),
        ("g_rein", "ARP reinject sent (rate)", "ovs_vm_arbiter_arp_reinject_sent_total"),
        ("g_reif", "ARP reinject failed (rate)", "ovs_vm_arbiter_arp_reinject_failed_total"),
    ]
    for row_start in (0, 3):
        chunk = arp_rates[row_start : row_start + 3]
        d.cells(
            [
                (
                    wid,
                    4,
                    5,
                    i * 4,
                    graph_panel(wid, title, m, "rate", "sum", filters_host(), []),
                )
                for i, (wid, title, m) in enumerate(chunk)
            ]
        )

    d.row("row_x", "Extra mappings (--prometheus-metrics-extra)")
    d.cells(
        [
            (
                "g_minfo",
                12,
                7,
                0,
                graph_panel(
                    "g_minfo",
                    "Entry mapping info (high cardinality)",
                    "ovs_vm_arbiter_entry_mapping_info",
                    "latest",
                    "avg",
                    filters_host(),
                    gb("ip", "mac", "bridge", "vlan", "node"),
                    legend="{{ip}} {{mac}}",
                    desc="Only with prometheus_metrics_extra. Heavy series count.",
                ),
            )
        ]
    )
    d.cells(
        [
            (
                "g_mttl",
                12,
                7,
                0,
                graph_panel(
                    "g_mttl",
                    "Entry mapping TTL (s)",
                    "ovs_vm_arbiter_entry_mapping_ttl_seconds",
                    "latest",
                    "avg",
                    filters_host(),
                    gb("ip", "mac", "bridge"),
                    legend="{{ip}} @{{bridge}}",
                ),
            )
        ]
    )

    out = {
        "title": "ovs-vm-arbiter",
        "description": "Open vSwitch / Proxmox arbiter metrics (Prometheus scrape via signoz-agent). "
        "Panels filter host with IN $host. peer_ip / bridge variables apply where metrics carry those labels.",
        "tags": ["ovs", "openvswitch", "prometheus", "proxmox"],
        "version": "v5",
        "uploadedGrafana": False,
        "uuid": DASH_UUID,
        "variables": {
            "host": {
                "allSelected": True,
                "description": "Host scraping this exporter (signoz-agent)",
                "dynamicVariablesAttribute": "host",
                "dynamicVariablesSource": "Metrics",
                "id": "var_host",
                "multiSelect": True,
                "name": "host",
                "order": 0,
                "showALLOption": True,
                "sort": "ASC",
                "type": "DYNAMIC",
            },
            "peer_ip": {
                "allSelected": True,
                "description": "Mesh peer_ip label",
                "dynamicVariablesAttribute": "peer_ip",
                "dynamicVariablesSource": "Metrics",
                "id": "var_peer_ip",
                "multiSelect": True,
                "name": "peer_ip",
                "order": 1,
                "showALLOption": True,
                "sort": "ASC",
                "type": "DYNAMIC",
            },
            "bridge": {
                "allSelected": True,
                "description": "OVS bridge name",
                "dynamicVariablesAttribute": "bridge",
                "dynamicVariablesSource": "Metrics",
                "id": "var_bridge",
                "multiSelect": True,
                "name": "bridge",
                "order": 2,
                "showALLOption": True,
                "sort": "ASC",
                "type": "DYNAMIC",
            },
        },
        "layout": d.layout,
        "widgets": d.widgets,
    }
    json.dump(out, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
