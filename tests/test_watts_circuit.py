"""Output-watts estimate (ups.load x ups.realpower.nominal) and the
per-UPS physical circuit label (nutctl topology metadata) on the dashboard
snapshot.

Run with: pytest tests/test_watts_circuit.py
"""
from __future__ import annotations

from pathlib import Path

from app.nut import _apply_variables
from app.nutctl.topology import load_topology
from app.ups import UpsState

FIX = Path(__file__).parent / "fixtures" / "nutctl"


def _state(vars_: dict[str, str]) -> UpsState:
    st = UpsState(reachable=True)
    base = {"ups.status": "OL"}
    base.update(vars_)
    _apply_variables(st, base)
    return st


def test_nut_source_parses_load_and_nominal_watts():
    st = _state({"ups.load": "49", "ups.realpower.nominal": "1200"})
    assert st.load_pct == 49
    assert st.realpower_nominal_w == 1200
    assert st.output_watts_estimated == 588


def test_watts_estimate_none_when_either_variable_missing():
    assert _state({"ups.load": "49"}).output_watts_estimated is None
    assert _state({"ups.realpower.nominal": "900"}).output_watts_estimated is None
    assert _state({}).load_pct is None


def test_topology_circuit_field_loads():
    topo = load_topology(FIX / "example-topology.yaml")
    assert topo.ups["alpha"].circuit == "B"
    assert topo.ups["beta"].circuit is None


def test_snapshot_carries_load_watts_and_circuit():
    from app.config import AppConfig, NutConfig
    from app.engine import Engine

    cfg = AppConfig(
        configured=True,
        observer_mode=True,
        ups=[NutConfig(id="u1", host="192.0.2.10", ups_name="alpha")],
    )
    eng = Engine(cfg)
    eng.nutctl_ups_circuits = {"u1": "B"}
    eng.ups_rt["u1"].state = _state({"ups.load": "60", "ups.realpower.nominal": "900"})
    snap = eng.snapshot()
    card = snap["ups"][0]
    assert card["load_pct"] == 60
    assert card["output_watts_estimated"] == 540
    assert card["circuit"] == "B"


def test_snapshot_circuit_empty_when_unmapped():
    from app.config import AppConfig, NutConfig
    from app.engine import Engine

    cfg = AppConfig(
        configured=True,
        ups=[NutConfig(id="u1", host="192.0.2.10", ups_name="alpha")],
    )
    eng = Engine(cfg)
    snap = eng.snapshot()
    assert snap["ups"][0]["circuit"] == ""
    assert snap["ups"][0]["load_pct"] is None
