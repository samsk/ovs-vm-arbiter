"""SigNoz provisioned dashboard JSON sanity checks."""
from __future__ import annotations

import json
from pathlib import Path

from src.test import _test_assert

_DASH = Path(__file__).resolve().parents[2] / "dashboard" / "signoz.json"


def test_signoz_dashboard_v5_schema() -> None:
    """Load dashboard JSON; v5, stable uuid, host filter on metric panels."""
    raw = json.loads(_DASH.read_text(encoding="utf-8"))
    _test_assert(raw.get("version") == "v5", "version must be v5")
    _test_assert(raw.get("uuid") == "8d2a1f3c-6b4e-5a7d-9e0f-1a2b3c4d5e6f", "stable uuid for upserts")
    _test_assert("host" in (raw.get("variables") or {}), "host variable required")
    for w in raw.get("widgets") or []:
        if w.get("panelTypes") == "row":
            continue
        items = (
            w.get("query", {})
            .get("builder", {})
            .get("queryData", [{}])[0]
            .get("filters", {})
            .get("items")
        )
        _test_assert(items is not None, f"panel {w.get('id')} missing filters")
        has_host = any(
            isinstance(it, dict) and it.get("key", {}).get("key") == "host" and it.get("value") == "$host"
            for it in items
        )
        _test_assert(has_host, f"panel {w.get('id')} must filter host IN $host")
