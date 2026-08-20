"""Per-outlet PDU watts (unpoller via Prometheus) behind the dashboard toggle.

A display-only poller reads the unpoller per-outlet power metric from
Prometheus in one instant query and the snapshot maps configured
(ups -> [PDU outlet]) references to {name, watts, stale} rows for the
power-feed diagram. Fail-soft everywhere, exactly like the circuit-power
poller: Prometheus being down never raises, never triggers any engine
action, and keeps the last value flagged stale.

Run with: pytest tests/test_pdu_loads.py
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from app.outlets import PduOutletPoller, PduPowerConfig, parse_prom_outlets

T0 = datetime(2026, 8, 20, 13, 0, 0, tzinfo=timezone.utc)


def _prom(results):
    return {"status": "success", "data": {"result": results}}


def _series(device, index, name, watts):
    return {
        "metric": {
            "__name__": "unpoller_device_outlet_outlet_power",
            "name": device,
            "outlet_index": str(index),
            "outlet_name": name,
            "site_name": "Default (default)",
        },
        "value": [1755694800.0, str(watts)],
    }


PAYLOAD = _prom([
    _series("Net Rack PDU Pro", 6, "Dream Machine Special Edition", "45.916"),
    _series("Net Rack PDU Pro", 5, "USW Pro Max 16", "10.271"),
    _series("Beast PDU Pro", 17, "PDU Switch", "40.415"),
])

MAPPING = {
    "ups2": [
        {"device": "Net Rack PDU Pro", "outlet": 6, "label": None},
        {"device": "Net Rack PDU Pro", "outlet": 5, "label": None},
    ],
    "ups4": [{"device": "Beast PDU Pro", "outlet": 17, "label": "XG10 Backhaul"}],
}


def _cfg(**kw) -> PduPowerConfig:
    base = dict(prometheus_url="http://prom.test:9090")
    base.update(kw)
    return PduPowerConfig(**base)


# -- pure parsing ------------------------------------------------------------

def test_parse_maps_device_and_index_to_name_and_watts():
    out = parse_prom_outlets(PAYLOAD)
    assert out[("Net Rack PDU Pro", 6)] == ("Dream Machine Special Edition", 45.916)
    assert out[("Beast PDU Pro", 17)] == ("PDU Switch", 40.415)


def test_parse_skips_garbage_series():
    out = parse_prom_outlets(_prom([
        {"metric": {"name": "P", "outlet_index": "x", "outlet_name": "n"}, "value": [0, "1"]},
        {"metric": {"outlet_index": "1", "outlet_name": "n"}, "value": [0, "1"]},  # no device
        {"metric": {"name": "P", "outlet_index": "2", "outlet_name": "n"}, "value": [0, "NaN-ish"]},
        _series("P", 3, "good", "7.5"),
    ]))
    assert out == {("P", 3): ("good", 7.5)}


def test_parse_empty_on_error_status_or_malformed():
    assert parse_prom_outlets({"status": "error"}) == {}
    assert parse_prom_outlets({}) == {}


def test_parse_falls_back_to_outlet_number_when_unnamed():
    out = parse_prom_outlets(_prom([
        {"metric": {"name": "P", "outlet_index": "4"}, "value": [0, "2"]},
    ]))
    assert out[("P", 4)] == ("Outlet 4", 2.0)


# -- poller ------------------------------------------------------------------

def test_poll_and_snapshot_map_refs_to_rows():
    async def fetch() -> dict:
        return PAYLOAD

    p = PduOutletPoller(_cfg(), fetch=fetch)
    asyncio.run(p.poll(T0))
    snap = p.snapshot(T0, MAPPING)
    assert snap["ups2"][0] == {"name": "Dream Machine Special Edition", "watts": 45.916, "stale": False}
    assert snap["ups2"][1]["watts"] == 10.271
    # explicit label overrides the live outlet name
    assert snap["ups4"][0]["name"] == "XG10 Backhaul"
    assert snap["ups4"][0]["watts"] == 40.415


def test_configured_outlet_missing_from_prom_renders_stale_row():
    async def fetch() -> dict:
        return PAYLOAD

    p = PduOutletPoller(_cfg(), fetch=fetch)
    asyncio.run(p.poll(T0))
    snap = p.snapshot(T0, {"u": [{"device": "Ghost PDU", "outlet": 1, "label": None}]})
    row = snap["u"][0]
    assert row["watts"] is None
    assert row["stale"] is True
    assert "Ghost PDU" in row["name"]  # deterministic fallback name


def test_poll_failure_is_soft_and_keeps_last_value():
    calls = {"n": 0}

    async def fetch() -> dict:
        calls["n"] += 1
        if calls["n"] > 1:
            raise OSError("prom down")
        return PAYLOAD

    p = PduOutletPoller(_cfg(), fetch=fetch)
    asyncio.run(p.poll(T0))
    asyncio.run(p.poll(T0 + timedelta(seconds=60)))  # must not raise
    snap = p.snapshot(T0 + timedelta(seconds=60), MAPPING)
    assert snap["ups2"][0]["watts"] == 45.916  # last good retained
    assert snap["ups2"][0]["stale"] is False  # 60s old at default 30s: not yet stale


def test_snapshot_goes_stale_when_data_ages_out():
    async def fetch() -> dict:
        return PAYLOAD

    p = PduOutletPoller(_cfg(), fetch=fetch)
    asyncio.run(p.poll(T0))
    late = T0 + timedelta(seconds=1000)  # > 4 * 30s
    assert p.snapshot(late, MAPPING)["ups2"][0]["stale"] is True


def test_maybe_poll_respects_interval():
    calls = {"n": 0}

    async def fetch() -> dict:
        calls["n"] += 1
        return PAYLOAD

    p = PduOutletPoller(_cfg(poll_interval_s=30), fetch=fetch)
    asyncio.run(p.maybe_poll(T0))
    asyncio.run(p.maybe_poll(T0 + timedelta(seconds=10)))  # within interval: skipped
    asyncio.run(p.maybe_poll(T0 + timedelta(seconds=40)))
    assert calls["n"] == 2


def test_snapshot_empty_when_disabled_or_unmapped():
    p = PduOutletPoller(PduPowerConfig())  # no prometheus_url -> disabled
    assert p.snapshot(T0, MAPPING) == {}
    p2 = PduOutletPoller(_cfg())
    assert p2.snapshot(T0, {}) == {}


def test_config_enabled_property():
    assert PduPowerConfig().enabled is False
    assert _cfg().enabled is True


# -- topology -> engine mapping ----------------------------------------------

def test_sync_topology_populates_engine_pdu_loads_mapping(tmp_path):
    """UpsSpec.pdu_loads flows through sync_topology_into_engine keyed by the
    upstream UPS id (via NutConfig.ups_name), preserving outlet order; UPSes
    without pdu_loads (or without a matching NUT source) are simply absent."""
    from pathlib import Path

    from app.config import AppConfig, NutConfig
    from app.engine import Engine
    from app.nutctl import routes as nutctl_routes

    topo_text = Path(__file__).parent.joinpath(
        "fixtures/nutctl/example-topology.yaml"
    ).read_text(encoding="utf-8")
    topo_text = topo_text.replace(
        'circuit: "B", driver:',
        'circuit: "B", pdu_loads: ['
        '{ device: "Net Rack PDU Pro", outlet: 6 }, '
        '{ device: "Net Rack PDU Pro", outlet: 5, label: "ProMax16" }], driver:',
    )
    topo_path = tmp_path / "topo.yaml"
    topo_path.write_text(topo_text, encoding="utf-8")

    cfg = AppConfig(
        observer_mode=True,
        nutctl_topology_path=str(topo_path),
        ups=[
            NutConfig(id="u-alpha", name="alpha", ups_name="alpha", host="127.0.0.1"),
            NutConfig(id="u-beta", name="beta", ups_name="beta", host="127.0.0.1"),
        ],
    )
    eng = Engine(cfg)
    nutctl_routes.sync_topology_into_engine(eng)
    assert eng.nutctl_ups_pdu_loads == {
        "u-alpha": [
            {"device": "Net Rack PDU Pro", "outlet": 6, "label": None},
            {"device": "Net Rack PDU Pro", "outlet": 5, "label": "ProMax16"},
        ]
    }
