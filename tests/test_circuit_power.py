"""Measured circuit power (Emporia via Home Assistant) on the dashboard.

A display-only poller reads whole-circuit watts from HA's REST API and the
snapshot carries them per physical circuit letter, next to the per-UPS
estimates. Fail-soft everywhere: HA being down never raises, never triggers
any engine action, and keeps the last value flagged stale.

Run with: pytest tests/test_circuit_power.py
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from app.circuits import CircuitPowerConfig, CircuitPowerPoller, parse_ha_watts

T0 = datetime(2026, 8, 19, 15, 0, 0, tzinfo=timezone.utc)


def _cfg(**kw) -> CircuitPowerConfig:
    base = dict(
        ha_url="http://ha.test:8123",
        ha_token="tok",
        entities={"A": "sensor.circ_a", "B": "sensor.circ_b"},
    )
    base.update(kw)
    return CircuitPowerConfig(**base)


# -- pure parsing ------------------------------------------------------------

def test_parse_ha_watts_reads_numeric_state():
    assert parse_ha_watts({"state": "1098.737"}) == 1098.737


def test_parse_ha_watts_none_on_unavailable_or_garbage():
    assert parse_ha_watts({"state": "unavailable"}) is None
    assert parse_ha_watts({"state": "unknown"}) is None
    assert parse_ha_watts({"state": ""}) is None
    assert parse_ha_watts({}) is None


# -- poller ------------------------------------------------------------------

def test_poll_maps_circuits_to_fetched_watts():
    async def fetch(entity: str) -> dict:
        return {"state": {"sensor.circ_a": "1100.5", "sensor.circ_b": "700.25"}[entity]}

    p = CircuitPowerPoller(_cfg(), fetch=fetch)
    asyncio.run(p.poll(T0))
    snap = p.snapshot(T0)
    assert snap["A"]["watts"] == 1100.5
    assert snap["B"]["watts"] == 700.25
    assert snap["A"]["stale"] is False


def test_poll_failure_is_soft_and_keeps_last_value():
    calls = {"n": 0}

    async def fetch(entity: str) -> dict:
        calls["n"] += 1
        if calls["n"] > 2:
            raise OSError("ha down")
        return {"state": "500"}

    p = CircuitPowerPoller(_cfg(), fetch=fetch)
    asyncio.run(p.poll(T0))
    # second round: both fetches fail; poll() must not raise
    asyncio.run(p.poll(T0 + timedelta(seconds=60)))
    snap = p.snapshot(T0 + timedelta(seconds=60))
    assert snap["A"]["watts"] == 500.0  # last good value retained
    assert snap["A"]["stale"] is False  # 60s old at default 30s interval: not yet stale


def test_snapshot_goes_stale_when_data_ages_out():
    async def fetch(entity: str) -> dict:
        return {"state": "500"}

    p = CircuitPowerPoller(_cfg(), fetch=fetch)
    asyncio.run(p.poll(T0))
    late = T0 + timedelta(seconds=1000)  # > 4x poll interval
    assert p.snapshot(late)["A"]["stale"] is True


def test_never_fetched_reports_none_watts():
    async def fetch(entity: str) -> dict:  # pragma: no cover - never called
        raise AssertionError("should not fetch in snapshot()")

    p = CircuitPowerPoller(_cfg(), fetch=fetch)
    snap = p.snapshot(T0)
    assert snap["A"]["watts"] is None
    assert snap["A"]["stale"] is True


def test_poller_throttles_to_interval():
    calls = {"n": 0}

    async def fetch(entity: str) -> dict:
        calls["n"] += 1
        return {"state": "1"}

    p = CircuitPowerPoller(_cfg(poll_interval_s=30), fetch=fetch)
    asyncio.run(p.maybe_poll(T0))
    asyncio.run(p.maybe_poll(T0 + timedelta(seconds=5)))  # too soon: skipped
    assert calls["n"] == 2  # one round, two entities
    asyncio.run(p.maybe_poll(T0 + timedelta(seconds=31)))
    assert calls["n"] == 4


# -- config + engine wiring --------------------------------------------------

def test_config_disabled_until_fully_specified():
    from app.config import AppConfig

    cfg = AppConfig()
    assert cfg.circuit_power.enabled is False
    assert _cfg().enabled is True
    assert _cfg(ha_token="").enabled is False
    assert _cfg(entities={}).enabled is False


def test_engine_snapshot_carries_circuit_power():
    from app.config import AppConfig
    from app.engine import Engine

    cfg = AppConfig(configured=True, observer_mode=True)
    cfg.circuit_power = _cfg()
    eng = Engine(cfg)

    async def fetch(entity: str) -> dict:
        return {"state": {"sensor.circ_a": "1099", "sensor.circ_b": "701"}[entity]}

    eng.circuit_power = CircuitPowerPoller(cfg.circuit_power, fetch=fetch)
    asyncio.run(eng.circuit_power.poll(T0))
    snap = eng.snapshot()
    assert snap["circuit_power"]["A"]["watts"] == 1099.0
    assert snap["circuit_power"]["B"]["watts"] == 701.0


def test_ha_token_is_masked_in_sanitized_config():
    assert _cfg().model_dump(mode="json")["ha_token"] == "**********"


def test_merge_config_keeps_ha_token_on_masked_roundtrip():
    from app.config import AppConfig
    from app.main import _merge_config, _sanitized_config

    existing = AppConfig(configured=True)
    existing.circuit_power = _cfg(ha_token="real-secret")
    incoming = _sanitized_config(existing)  # ha_token arrives masked
    merged = _merge_config(incoming, existing)
    assert merged.circuit_power.ha_token.get_secret_value() == "real-secret"
    assert merged.circuit_power.entities == {"A": "sensor.circ_a", "B": "sensor.circ_b"}


def test_merge_config_carries_circuit_power_when_form_omits_it():
    from app.config import AppConfig
    from app.main import _merge_config, _sanitized_config

    existing = AppConfig(configured=True)
    existing.circuit_power = _cfg(ha_token="real-secret")
    incoming = _sanitized_config(existing)
    incoming.pop("circuit_power")  # settings form doesn't render the block
    merged = _merge_config(incoming, existing)
    assert merged.circuit_power.ha_token.get_secret_value() == "real-secret"
    assert merged.circuit_power.entities == {"A": "sensor.circ_a", "B": "sensor.circ_b"}


def test_engine_snapshot_empty_circuit_power_when_disabled():
    from app.config import AppConfig
    from app.engine import Engine

    eng = Engine(AppConfig(configured=True, observer_mode=True))
    assert eng.snapshot()["circuit_power"] == {}
