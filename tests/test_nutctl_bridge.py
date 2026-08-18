"""Tests for nutctl.bridge: Topology -> upstream engine host list, and the
observer-mode guard in Engine._fire_host that makes acting on it inert.
"""
from pathlib import Path

import pytest

from app.config import AppConfig, SnmpConfig, Thresholds
from app.nutctl.bridge import synthesize_hosts
from app.nutctl.topology import load_topology
from app.ups import UpsState
from app import engine as engine_mod
from app.engine import Engine

FIX = Path(__file__).parent / "fixtures" / "nutctl"


@pytest.fixture(autouse=True)
def _isolated_engine_state(tmp_path, monkeypatch):
    """Same isolation as test_basic.py: never touch the real engine-state.json."""
    monkeypatch.setattr(engine_mod, "STATE_PATH", tmp_path / "engine-state.json")


def test_synthesize_maps_feeds_and_policy():
    topo = load_topology(FIX / "example-topology.yaml")
    hosts = synthesize_hosts(topo, {"alpha": "u1", "beta": "u2"})

    node2 = next(h for h in hosts if h.name == "node2")
    assert set(node2.ups_ids) == {"u1", "u2"}
    assert node2.ups_policy == "all"

    # Display-only hosts (vendor GUI clients) are INCLUDED, not filtered out: observer
    # mode makes every synthesized host inert, so nas2 still belongs in the feed map.
    assert any(h.name == "nas2" for h in hosts)
    nas2 = next(h for h in hosts if h.name == "nas2")
    assert nas2.ups_ids == ["u2"]

    # Every topology host round-trips 1:1, in the topology's own order.
    assert [h.name for h in hosts] == list(topo.hosts.keys())
    assert [h.order for h in hosts] == list(range(len(topo.hosts)))

    # Inert placeholder wiring: no real Proxmox credential, no this_host.
    for h in hosts:
        assert h.api_url
        assert h.token_id == ""
        assert h.token_secret.get_secret_value() == ""
        assert h.this_host is False


@pytest.mark.asyncio
async def test_observer_mode_never_calls_proxmox(monkeypatch):
    async def boom(*a, **k):
        raise AssertionError("proxmox touched in observer mode")

    monkeypatch.setattr(engine_mod.proxmox, "shutdown_node", boom)

    topo = load_topology(FIX / "example-topology.yaml")
    hosts = synthesize_hosts(topo, {"alpha": "u", "beta": "u2"})  # "u2" unmapped on purpose

    th = Thresholds(on_battery_seconds=None, runtime_below_minutes=5,
                    charge_below_percent=None, on_battery_low=False)
    cfg = AppConfig(
        observer_mode=True,
        dry_run=False,
        ups=[SnmpConfig(id="u", host="10.0.0.1")],
        hosts=hosts,
        thresholds=th,
    )
    eng = Engine(cfg)
    eng.ups_rt["u"].state = UpsState(reachable=True, power_source="battery",
                                     runtime_remaining_min=3)
    await eng._evaluate()  # arms + evaluates node1's single feed ("u") in one pass

    assert eng.host_fired["node1"] is True
    assert eng.shutdown_triggered is True
