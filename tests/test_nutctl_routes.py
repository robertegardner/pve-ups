"""Tests for the nutctl REST control plane (app/nutctl/routes.py) and its wiring
into app.main (require_auth, lifespan, the observer-mode SSH fleet probe).

Uses FastAPI's TestClient against the real `app.main.app`, with every path
(config file, event db, engine state file, nutctl topology/secrets/repo) pointed
into a per-test tmp_path -- no real SSH, no real filesystem outside tmp_path.
`AsyncsshTransport` is monkeypatched at the routes-module seam
(`app.nutctl.routes.AsyncsshTransport`) with a `FakeTransport`, exactly like
tests/test_nutctl_deploy.py and tests/test_nutctl_probe.py do for the lower
layers -- no real network ever touched. The patch is always applied BEFORE the
`TestClient` context is entered: the app's background nutctl probe loop can run
its first tick concurrently with test setup (a separate background thread via
the anyio portal), so a monkeypatch applied only after `with TestClient(...)`
has already started would race it -- see fix-round-1, I3.

Run with: pytest tests/test_nutctl_routes.py
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient
from passlib.context import CryptContext

from app import config as config_mod
from app import db as db_mod
from app import engine as engine_mod
from app import main as main_mod
from app.config import AppConfig, SnmpConfig
from app.nutctl import routes as nutctl_routes
from app.nutctl.probe import SERVER_KEY, ProbeResult
from app.nutctl.render import render_host, render_server
from app.nutctl.topology import SshSpec, load_topology
from app.ups import UpsState

FIX = Path(__file__).parent / "fixtures" / "nutctl"
VALID_TOPO_TEXT = (FIX / "example-topology.yaml").read_text(encoding="utf-8")

PASSWORD = "testpass123"
SECRETS = {"nutnode_pass": "s3cret", "monuser_pass": "m4ster"}

_pwd_ctx = CryptContext(schemes=["argon2"], deprecated="auto")


def _quorum_violating_topology() -> str:
    """Same mutation as test_nutctl_topology.py's invariant test: node3's T2/
    lowbatt terminating tier becomes an onbatt/T1 one, so only node2 (1 vote) +
    qdevice (1 vote) = 2 survive past T1 -- below the 5-vote fixture's quorum
    (need >= 3)."""
    return VALID_TOPO_TEXT.replace(
        "tiers: [ { tier: T2, trigger: lowbatt, action: node-shutdown } ]\n  nas1:",
        "tiers: [ { tier: T1, trigger: onbatt, after_s: 240, action: node-shutdown } ]\n  nas1:",
    )


class FakeTransport:
    """Records every call; returns the first scripted response whose key the
    command starts with, else `default` -- a flat cmd-prefix -> response map
    (like tests/test_nutctl_deploy.py's FakeTransport), since these tests only
    ever need host-agnostic command shapes (systemctl is-active, tee, cp, ls)."""

    def __init__(self, responses: dict[str, tuple[int, str, str]] | None = None,
                 default: tuple[int, str, str] = (0, "", "")) -> None:
        self.responses = responses or {}
        self.default = default
        self.calls: list[tuple[SshSpec, str, str | None]] = []

    async def run(self, ssh: SshSpec, cmd: str, stdin: str | None = None) -> tuple[int, str, str]:
        self.calls.append((ssh, cmd, stdin))
        for prefix, resp in self.responses.items():
            if cmd.startswith(prefix):
                return resp
        return self.default

    @property
    def cmds(self) -> list[str]:
        return [c for _, c, _ in self.calls]


def _fake_transport_factory(responses: dict | None = None):
    """Matches the AsyncsshTransport(key_path) call signature at the seam."""
    made: dict = {}

    def factory(key_path: str) -> FakeTransport:
        t = FakeTransport(responses)
        made["transport"] = t
        return t

    factory.made = made
    return factory


_ACTIVE_RESPONSES = {"true": (0, "", ""), "systemctl is-active": (0, "active\n", "")}


@pytest.fixture(autouse=True)
def _reset_nutctl_module_state():
    """`_last_probe` is process-global state in routes.py; never let one test's
    fleet-probe result leak into the next."""
    nutctl_routes.set_last_probe({}, None)
    yield
    nutctl_routes.set_last_probe({}, None)


@pytest.fixture
def paths(tmp_path, monkeypatch):
    """Point every path the app touches into tmp_path, before the app ever
    starts (module-level constants are read at import time upstream, so these
    have to be monkeypatched directly rather than via env vars)."""
    monkeypatch.setattr(config_mod, "CONFIG_PATH", tmp_path / "config.yaml")
    monkeypatch.setattr(db_mod, "DB_PATH", tmp_path / "state" / "events.db")
    monkeypatch.setattr(engine_mod, "STATE_PATH", tmp_path / "state" / "engine-state.json")
    monkeypatch.setattr(main_mod, "STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(main_mod, "AGENT_DIR", main_mod.STATE_DIR / "agent")
    monkeypatch.setattr(main_mod, "AGENT_QUEUE", main_mod.AGENT_DIR / "queue")
    monkeypatch.setattr(main_mod, "AGENT_RESULT", main_mod.AGENT_DIR / "result.json")
    monkeypatch.setattr(main_mod, "AGENT_SEEN", main_mod.AGENT_DIR / "result.seen")
    monkeypatch.setattr(main_mod, "AGENT_LAST_JOB", main_mod.AGENT_DIR / "last_job")
    monkeypatch.setattr(main_mod, "AGENT_LOG", main_mod.AGENT_DIR / "agent.log")
    monkeypatch.setattr(main_mod, "UPDATE_DIR", main_mod.STATE_DIR / "updates")

    topo_path = tmp_path / "nut-topology.yaml"
    topo_path.write_text(VALID_TOPO_TEXT, encoding="utf-8")
    secrets_path = tmp_path / "nutctl-secrets.yaml"
    secrets_path.write_text(yaml.safe_dump(SECRETS), encoding="utf-8")
    return {
        "tmp_path": tmp_path,
        "topo_path": topo_path,
        "secrets_path": secrets_path,
        "repo_dir": tmp_path / "repo",
        "key_path": tmp_path / "id_ed25519_nutctl",
    }


def _write_cfg(paths, **overrides) -> AppConfig:
    kwargs = dict(
        configured=True,
        ui_password_hash=_pwd_ctx.hash(PASSWORD),
        observer_mode=True,
        nutctl_topology_path=str(paths["topo_path"]),
        nutctl_key_path=str(paths["key_path"]),
        nutctl_secrets_path=str(paths["secrets_path"]),
        nutctl_repo_dir=str(paths["repo_dir"]),
    )
    kwargs.update(overrides)
    cfg = AppConfig(**kwargs)
    config_mod.save_config(cfg, config_mod.CONFIG_PATH)
    return cfg


@pytest.fixture
def client(paths, monkeypatch):
    _write_cfg(paths)
    # Pre-patch BEFORE the app starts (see module docstring / I3): the
    # background probe loop's first tick can otherwise race a per-test patch
    # applied after `with TestClient(...)` has already begun.
    monkeypatch.setattr(nutctl_routes, "AsyncsshTransport", _fake_transport_factory())
    with TestClient(main_mod.app) as c:
        yield c


def _login(client) -> None:
    resp = client.post("/api/login", json={"password": PASSWORD})
    assert resp.status_code == 200, resp.text


def _add_healthy_ups(id_: str = "u1") -> None:
    """Give the live `main_mod.engine` one reachable, not-on-battery UPS, so
    the on-battery/no-telemetry deploy interlock (I6) doesn't block a test
    that isn't specifically exercising that interlock. Must be called AFTER
    the app has already started (appending to cfg.ups in the initial config
    would make the engine's very first poll-loop tick attempt a real SNMP
    poll against the fake 10.0.0.1 host)."""
    cfg = main_mod.engine.cfg
    cfg.ups.append(SnmpConfig(id=id_, host="10.0.0.1"))
    main_mod.engine.update_config(cfg)
    main_mod.engine.ups_rt[id_].state = UpsState(reachable=True, power_source="mains")


# --- auth: every new route requires a session --------------------------------

@pytest.mark.parametrize(
    "method,path",
    [
        ("get", "/api/nutctl/topology"),
        ("put", "/api/nutctl/topology"),
        ("get", "/api/nutctl/preview"),
        ("post", "/api/nutctl/deploy/node1"),
        ("post", "/api/nutctl/deploy-fleet"),
        ("post", "/api/nutctl/revert/node1"),
        ("get", "/api/nutctl/fleet"),
    ],
)
def test_unauthenticated_request_gets_401(client, method, path):
    kwargs = {"json": {"yaml": ""}} if method == "put" else {}
    resp = getattr(client, method)(path, **kwargs)
    assert resp.status_code == 401


# --- I4: bootstrap state (no UI password set) --------------------------------

def test_write_routes_403_in_bootstrap_state_no_ui_password(paths, monkeypatch):
    _write_cfg(paths, ui_password_hash="")
    monkeypatch.setattr(nutctl_routes, "AsyncsshTransport", _fake_transport_factory())
    with TestClient(main_mod.app) as client:
        # No login at all -- upstream's bootstrap semantics treat "no password
        # set yet" as authenticated so the setup wizard can run. Read routes
        # keep that (harmless: they return detail, not actions).
        resp = client.get("/api/nutctl/topology")
        assert resp.status_code == 200
        resp = client.get("/api/nutctl/preview")
        assert resp.status_code in (200, 409)  # topology-dependent, never 401/403
        resp = client.get("/api/nutctl/fleet")
        assert resp.status_code == 200

        # Every WRITE must refuse outright.
        resp = client.put("/api/nutctl/topology", json={"yaml": VALID_TOPO_TEXT})
        assert resp.status_code == 403
        resp = client.post("/api/nutctl/deploy/node1")
        assert resp.status_code == 403
        resp = client.post("/api/nutctl/deploy-fleet")
        assert resp.status_code == 403
        resp = client.post("/api/nutctl/revert/node1")
        assert resp.status_code == 403


def test_write_routes_ok_once_a_ui_password_exists(client):
    """Sanity check paired with the bootstrap test: the ordinary configured
    state (the `client` fixture's default) must NOT trip the new I4 guard."""
    _login(client)
    resp = client.put("/api/nutctl/topology", json={"yaml": VALID_TOPO_TEXT})
    assert resp.status_code == 200


# --- GET/PUT topology --------------------------------------------------------

def test_get_topology_missing_file_reports_absence(client):
    _login(client)
    # Fresh cfg pointing at a topology file that was never written.
    resp = client.get("/api/nutctl/topology")
    assert resp.status_code == 200
    body = resp.json()
    assert body["yaml"] == VALID_TOPO_TEXT  # written by the `paths` fixture
    assert body["errors"] == []


def test_get_topology_reports_no_file_when_absent(paths, monkeypatch):
    paths["topo_path"].unlink()
    _write_cfg(paths)
    monkeypatch.setattr(nutctl_routes, "AsyncsshTransport", _fake_transport_factory())
    with TestClient(main_mod.app) as client:
        _login(client)
        resp = client.get("/api/nutctl/topology")
        assert resp.status_code == 200
        body = resp.json()
        assert body["yaml"] == ""
        assert body["errors"]  # notes the absence


def test_put_invalid_topology_is_409_with_quorum_message(client):
    _login(client)
    resp = client.put("/api/nutctl/topology", json={"yaml": _quorum_violating_topology()})
    assert resp.status_code == 409
    body = resp.json()
    assert "errors" in body
    assert any("quorum" in e.lower() for e in body["errors"])
    # the rejected write must never have touched disk
    assert Path(config_mod.load_config(config_mod.CONFIG_PATH).nutctl_topology_path).read_text(
        encoding="utf-8"
    ) == VALID_TOPO_TEXT


def test_put_malformed_yaml_is_409(client):
    _login(client)
    resp = client.put("/api/nutctl/topology", json={"yaml": "not: [valid, yaml: :::"})
    assert resp.status_code == 409
    assert "errors" in resp.json()


def test_put_valid_topology_writes_file_and_resyncs_engine(client, paths):
    _login(client)
    # A trivially-different-but-still-valid document (rename nas2's note) proves
    # the PUT actually wrote through, not just validated.
    new_text = VALID_TOPO_TEXT.replace("note: vendor GUI client", "note: renamed")

    resp = client.put("/api/nutctl/topology", json={"yaml": new_text})
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    assert paths["topo_path"].read_text(encoding="utf-8") == new_text

    # resync happened: the engine's synthesized host list reflects the topology
    # (all hosts unmapped here since cfg.ups is empty -- so the list is empty,
    # but set_nutctl_hosts must have been called at all, not left at the
    # pre-PUT default of None).
    assert main_mod.engine.nutctl_hosts is not None


# --- I5: sync_topology_into_engine / _ordered_hosts gated on observer_mode --

def test_sync_topology_into_engine_installs_hosts_only_in_observer_mode(paths):
    from app.engine import Engine

    cfg_on = AppConfig(observer_mode=True, nutctl_topology_path=str(paths["topo_path"]))
    eng_on = Engine(cfg_on)
    nutctl_routes.sync_topology_into_engine(eng_on)
    assert eng_on.nutctl_hosts is not None

    cfg_off = AppConfig(observer_mode=False, nutctl_topology_path=str(paths["topo_path"]))
    eng_off = Engine(cfg_off)
    nutctl_routes.sync_topology_into_engine(eng_off)
    assert eng_off.nutctl_hosts is None


def test_sync_topology_into_engine_clears_a_stale_synthesized_list(paths):
    """Flipping observer_mode off must clear a previously-synthesized list, not
    just skip re-synthesizing (an operator toggling it back and forth must not
    resurrect a stale nutctl_hosts by accident)."""
    from app.engine import Engine

    cfg = AppConfig(observer_mode=True, nutctl_topology_path=str(paths["topo_path"]))
    eng = Engine(cfg)
    nutctl_routes.sync_topology_into_engine(eng)
    assert eng.nutctl_hosts is not None

    eng.cfg = eng.cfg.model_copy(update={"observer_mode": False})
    nutctl_routes.sync_topology_into_engine(eng)
    assert eng.nutctl_hosts is None


def test_ordered_hosts_ignores_stale_nutctl_hosts_when_observer_mode_is_false(paths):
    """Second, independent safety net (I5): even if nutctl_hosts is stale (left
    over from observer_mode=True, e.g. because nothing re-ran the sync seam),
    Engine._ordered_hosts() must never let it override a non-observer
    appliance's real, armed host list."""
    from app.config import HostConfig
    from app.engine import Engine

    real_host = HostConfig(name="real-pve01", api_url="https://10.0.0.10:8006")
    cfg = AppConfig(observer_mode=False, hosts=[real_host])
    eng = Engine(cfg)
    eng.nutctl_hosts = [HostConfig(name="synthesized-ghost", api_url="https://observer.invalid:8006")]

    names = [h.name for h in eng._ordered_hosts()]
    assert names == ["real-pve01"]


# --- C1: preview never leaks a secret value, even a DIVERGED live one -------

def test_preview_never_contains_a_secret_value(client, monkeypatch):
    _login(client)
    monkeypatch.setattr(nutctl_routes, "AsyncsshTransport", _fake_transport_factory())

    resp = client.get("/api/nutctl/preview")
    assert resp.status_code == 200
    raw = resp.text
    for value in SECRETS.values():
        assert value not in raw


def test_preview_structural_redaction_masks_a_divergent_live_secret(client, monkeypatch):
    """C1: a live value that has DIVERGED from the local secrets file (a
    rotation, or a host still on install-client.sh's original password) must
    still never reach the response -- the old value-substitution-only masking
    let exactly this leak through."""
    _login(client)
    topo = load_topology(FIX / "example-topology.yaml")
    live_upsmon = (
        f"MONITOR alpha@{topo.nut_server.host} 1 nutnode OLD-LIVE-PASSWORD slave\n"
        "MINSUPPLIES 1\n"
    )
    live_upsd_users = (
        "[monuser]\n  password = OLD-MASTER-PW\n  upsmon master\n\n"
        "[nutnode]\n  password = ANOTHER-OLD-PW\n  upsmon slave\n"
    )
    responses = dict(_ACTIVE_RESPONSES)
    responses["cat -- /etc/nut/upsmon.conf"] = (0, live_upsmon, "")
    responses["cat -- /etc/nut/upsd.users"] = (0, live_upsd_users, "")
    monkeypatch.setattr(nutctl_routes, "AsyncsshTransport", _fake_transport_factory(responses))

    resp = client.get("/api/nutctl/preview")
    assert resp.status_code == 200
    raw = resp.text
    for leaked in ("OLD-LIVE-PASSWORD", "OLD-MASTER-PW", "ANOTHER-OLD-PW"):
        assert leaked not in raw
    for value in SECRETS.values():
        assert value not in raw
    assert "@SECRET:nutnode_pass@" in raw
    assert "@SECRET:monuser_pass@" in raw


def test_preview_reports_drift_for_a_never_deployed_fleet(client, monkeypatch):
    _login(client)
    # FakeTransport with no scripted responses -> every `cat` returns the
    # default (rc=0, empty stdout), which never matches a real rendered file.
    monkeypatch.setattr(nutctl_routes, "AsyncsshTransport", _fake_transport_factory())

    resp = client.get("/api/nutctl/preview")
    assert resp.status_code == 200
    body = resp.json()
    assert body["node1"]["drift"] is True
    assert body[SERVER_KEY]["drift"] is True


def test_preview_with_secrets_missing_still_redacts_structurally(paths, monkeypatch):
    """Structural redaction (C1) needs no knowledge of the real secret value at
    all, so a missing secrets file is no longer a special "withhold the diff"
    case -- it just diffs normally and safely (replaces the old withheld-note
    fallback mechanism, which structural redaction makes unnecessary)."""
    paths["secrets_path"].unlink()
    _write_cfg(paths)
    live_upsd_users = "[monuser]\n  password = REAL-LIVE-PW\n  upsmon master\n\n[nutnode]\n  password = OTHER-REAL-PW\n  upsmon slave\n"
    responses = dict(_ACTIVE_RESPONSES)
    responses["cat -- /etc/nut/upsd.users"] = (0, live_upsd_users, "")
    monkeypatch.setattr(nutctl_routes, "AsyncsshTransport", _fake_transport_factory(responses))

    with TestClient(main_mod.app) as client2:
        _login(client2)
        resp = client2.get("/api/nutctl/preview")
        assert resp.status_code == 200
        raw = resp.text
        assert "REAL-LIVE-PW" not in raw
        assert "OTHER-REAL-PW" not in raw
        assert "@SECRET:monuser_pass@" in raw
        assert "@SECRET:nutnode_pass@" in raw


# --- I2: a partially populated secrets file must never 500 -----------------

def test_preview_with_partial_secrets_never_500s_and_never_leaks(paths, monkeypatch):
    paths["secrets_path"].write_text(yaml.safe_dump({"nutnode_pass": "s3cret"}), encoding="utf-8")
    _write_cfg(paths)
    monkeypatch.setattr(nutctl_routes, "AsyncsshTransport", _fake_transport_factory())
    with TestClient(main_mod.app) as client2:
        _login(client2)
        resp = client2.get("/api/nutctl/preview")
        assert resp.status_code == 200
        for value in SECRETS.values():
            assert value not in resp.text


def test_deploy_refuses_when_secrets_partially_configured(paths, monkeypatch):
    paths["secrets_path"].write_text(yaml.safe_dump({"nutnode_pass": "s3cret"}), encoding="utf-8")
    _write_cfg(paths)
    monkeypatch.setattr(nutctl_routes, "AsyncsshTransport", _fake_transport_factory())
    with TestClient(main_mod.app) as client2:
        _login(client2)
        _add_healthy_ups()

        resp = client2.post("/api/nutctl/deploy/node1")
        assert resp.status_code == 409
        body = resp.json()
        assert "secrets" in body["detail"].lower()
        assert body["missing_keys"] == ["monuser_pass"]

        resp = client2.post("/api/nutctl/deploy-fleet")
        assert resp.status_code == 409
        assert resp.json()["missing_keys"] == ["monuser_pass"]


def test_deploy_refuses_when_secrets_not_configured(paths, monkeypatch):
    paths["secrets_path"].unlink()
    _write_cfg(paths)
    monkeypatch.setattr(nutctl_routes, "AsyncsshTransport", _fake_transport_factory())
    with TestClient(main_mod.app) as client2:
        _login(client2)
        _add_healthy_ups()

        resp = client2.post("/api/nutctl/deploy/node1")
        assert resp.status_code == 409
        assert "secrets" in resp.json()["detail"].lower()


# --- I3: the probe never constructs a real transport in tests --------------

async def test_probe_resolves_transport_through_the_single_nutctl_routes_seam(client, monkeypatch):
    """The background probe (app.main._maybe_run_nutctl_probe) must resolve
    its transport through `nutctl_routes.AsyncsshTransport` -- the one seam
    every test patches -- not a separately imported binding of the real class,
    which would silently bypass any monkeypatch and dial real SSH."""
    from app.nutctl import deploy as deploy_mod

    # main_mod's probe-slot latch is process-global state that can already be
    # set from an earlier test's background probe tick in this same session --
    # reset it so this call is guaranteed to actually run, not skip as "same
    # slot, already probed".
    monkeypatch.setattr(main_mod, "_nutctl_last_probe_slot", None)

    def _boom(*a, **k):
        raise AssertionError("real app.nutctl.deploy.AsyncsshTransport constructed -- I3 regression")

    monkeypatch.setattr(deploy_mod, "AsyncsshTransport", _boom)

    calls: list[str] = []

    def fake_factory(key_path: str) -> FakeTransport:
        calls.append(key_path)
        return FakeTransport(dict(_ACTIVE_RESPONSES))

    monkeypatch.setattr(nutctl_routes, "AsyncsshTransport", fake_factory)

    await main_mod._maybe_run_nutctl_probe()

    assert calls  # the seam WAS used -- proves the probe didn't need deploy_mod's real class


# --- I6: on-battery / no-telemetry interlock --------------------------------

def test_deploy_refuses_with_409_when_a_ups_is_on_battery(client, monkeypatch):
    _login(client)
    monkeypatch.setattr(nutctl_routes, "AsyncsshTransport", _fake_transport_factory())

    # Give the live engine one UPS and put it on battery.
    cfg = main_mod.engine.cfg
    cfg.ups.append(SnmpConfig(id="u1", host="10.0.0.1"))
    main_mod.engine.update_config(cfg)
    main_mod.engine.ups_rt["u1"].state = UpsState(reachable=True, power_source="battery")

    resp = client.post("/api/nutctl/deploy/node1")
    assert resp.status_code == 409
    assert resp.json()["detail"] == "on battery"

    resp = client.post("/api/nutctl/deploy-fleet")
    assert resp.status_code == 409
    assert resp.json()["detail"] == "on battery"


def test_deploy_refuses_when_no_ups_telemetry_at_all(client, monkeypatch):
    """An appliance with no UPS configured/mapped at all must REFUSE deploys
    (fail closed), not pass the interlock vacuously via any([]) == False."""
    _login(client)
    monkeypatch.setattr(nutctl_routes, "AsyncsshTransport", _fake_transport_factory())
    assert main_mod.engine.ups_rt == {}

    resp = client.post("/api/nutctl/deploy/node1")
    assert resp.status_code == 409
    assert "telemetry" in resp.json()["detail"].lower()

    resp = client.post("/api/nutctl/deploy-fleet")
    assert resp.status_code == 409
    assert "telemetry" in resp.json()["detail"].lower()


def test_deploy_fleet_stops_remaining_hosts_when_interlock_trips_mid_run(client, monkeypatch):
    """The battery/telemetry predicate is re-evaluated before EACH host, not
    just once up front: a fleet deploy is many sequential SSH round trips, and
    the interlock tripping partway through must stop the hosts not yet
    started, not just gate the very first one."""
    _login(client)
    monkeypatch.setattr(nutctl_routes, "AsyncsshTransport", _fake_transport_factory(dict(_ACTIVE_RESPONSES)))

    calls = {"n": 0}

    def flip_after_server(eng):
        calls["n"] += 1
        # call 1: the pre-loop check. call 2: the server's per-host re-check.
        # Both clear; node1 (the next host) onward sees the tripped interlock.
        return None if calls["n"] <= 2 else "on battery"

    monkeypatch.setattr(nutctl_routes, "_fleet_battery_refusal", flip_after_server)

    resp = client.post("/api/nutctl/deploy-fleet")
    assert resp.status_code == 200
    body = resp.json()
    assert body[SERVER_KEY]["ok"] is True
    assert body["node1"]["ok"] is False
    assert "refused" in body["node1"]["detail"].lower()
    # the loop stopped -- hosts after node1 were never attempted at all
    assert "node2" not in body
    assert "node3" not in body
    assert "nas1" not in body


# --- deploy: happy path never touches real SSH, writes a redacted repo copy --

def test_deploy_one_host_uses_fake_transport_and_writes_redacted_repo_snapshot(client, paths, monkeypatch):
    _login(client)
    _add_healthy_ups()
    factory = _fake_transport_factory(dict(_ACTIVE_RESPONSES))
    monkeypatch.setattr(nutctl_routes, "AsyncsshTransport", factory)

    resp = client.post("/api/nutctl/deploy/node1")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True

    # never touched real asyncssh -- only our FakeTransport
    t = factory.made["transport"]
    assert any(c.startswith("tee -- ") for c in t.cmds)

    snapshot_dir = paths["repo_dir"] / "nut" / "rendered" / "node1"
    written = (snapshot_dir / "upsmon.conf").read_text(encoding="utf-8")
    assert "@SECRET:nutnode_pass@" in written
    for value in SECRETS.values():
        assert value not in written


def test_deploy_fleet_deploys_server_and_every_non_display_host(client, paths, monkeypatch):
    _login(client)
    _add_healthy_ups()
    factory = _fake_transport_factory(dict(_ACTIVE_RESPONSES))
    monkeypatch.setattr(nutctl_routes, "AsyncsshTransport", factory)

    resp = client.post("/api/nutctl/deploy-fleet")
    assert resp.status_code == 200
    body = resp.json()
    assert set(body) == {"node1", "node2", "node3", "nas1", SERVER_KEY}
    assert all(v["ok"] for v in body.values())

    for name in ("node1", "node2", "node3", "nas1", SERVER_KEY):
        assert (paths["repo_dir"] / "nut" / "rendered" / name).is_dir()


def test_deploy_unknown_host_is_404(client, monkeypatch):
    _login(client)
    monkeypatch.setattr(nutctl_routes, "AsyncsshTransport", _fake_transport_factory())
    resp = client.post("/api/nutctl/deploy/does-not-exist")
    assert resp.status_code == 404


def test_deploy_display_only_host_is_400(client, monkeypatch):
    _login(client)
    monkeypatch.setattr(nutctl_routes, "AsyncsshTransport", _fake_transport_factory())
    resp = client.post("/api/nutctl/deploy/nas2")
    assert resp.status_code == 400


# --- I9: nut-server reload semantics -----------------------------------

def test_deploy_server_reloads_nut_server_when_only_ups_conf_changed(client, monkeypatch):
    """upsd only learns about added/removed ups.conf stanzas on start/reload --
    a ups.conf-only change must still reload nut-server, in addition to the
    per-UPS driver bounce, with the driver restarts running first."""
    _login(client)
    _add_healthy_ups()
    topo = load_topology(FIX / "example-topology.yaml")
    real_users = render_server(topo, SECRETS)["/etc/nut/upsd.users"]

    responses = dict(_ACTIVE_RESPONSES)
    responses["cat -- /etc/nut/ups.conf"] = (0, "DRIFTED\n", "")
    responses["cat -- /etc/nut/upsd.users"] = (0, real_users, "")
    factory = _fake_transport_factory(responses)
    monkeypatch.setattr(nutctl_routes, "AsyncsshTransport", factory)

    resp = client.post(f"/api/nutctl/deploy/{SERVER_KEY}")
    assert resp.status_code == 200
    assert resp.json()["ok"] is True

    cmds = factory.made["transport"].cmds
    assert "systemctl reload nut-server" in cmds
    assert cmds.count("systemctl reload nut-server") == 1  # never duplicated
    stop_idx = next(i for i, c in enumerate(cmds) if c.startswith("upsdrvctl stop"))
    reload_idx = cmds.index("systemctl reload nut-server")
    assert stop_idx < reload_idx  # driver restarts first, then reload (I9 order)


# --- revert -------------------------------------------------------------

def test_revert_uses_fake_transport(client, monkeypatch):
    _login(client)
    # A stash for every path node1's client render carries, so the revert is
    # fully "ok" (one path with no scripted stash would fail the whole thing).
    responses: dict[str, tuple[int, str, str]] = {
        "systemctl is-active": (0, "active\n", ""),
        "cp -a --": (0, "", ""),
    }
    topo = load_topology(FIX / "example-topology.yaml")
    for path in render_host(topo, "node1", None):
        stash = f"{path}.pre-nutctl.100"
        responses[f"ls -1 -- {path}.pre-nutctl.*"] = (0, f"{stash}\n", "")

    factory = _fake_transport_factory(responses)
    monkeypatch.setattr(nutctl_routes, "AsyncsshTransport", factory)

    resp = client.post("/api/nutctl/revert/node1")
    assert resp.status_code == 200
    assert resp.json()["ok"] is True
    t = factory.made["transport"]
    assert any(c.startswith("cp -a --") for c in t.cmds)


def test_revert_works_without_a_ups_configured(client, monkeypatch):
    """Revert is deliberately NOT gated by the on-battery/telemetry interlock
    (see deploy.py's revert_host docstring): reverting a bad push is exactly
    the kind of thing you'd want to do mid-outage, or with no UPS telemetry."""
    _login(client)
    assert main_mod.engine.ups_rt == {}
    responses: dict[str, tuple[int, str, str]] = {
        "systemctl is-active": (0, "active\n", ""),
        "cp -a --": (0, "", ""),
    }
    topo = load_topology(FIX / "example-topology.yaml")
    for path in render_host(topo, "node1", None):
        stash = f"{path}.pre-nutctl.100"
        responses[f"ls -1 -- {path}.pre-nutctl.*"] = (0, f"{stash}\n", "")
    monkeypatch.setattr(nutctl_routes, "AsyncsshTransport", _fake_transport_factory(responses))

    resp = client.post("/api/nutctl/revert/node1")
    assert resp.status_code == 200
    assert resp.json()["ok"] is True


# --- I7: audit trail ------------------------------------------------------

def test_deploy_and_topology_put_write_audit_events(client, monkeypatch):
    _login(client)
    _add_healthy_ups()
    monkeypatch.setattr(nutctl_routes, "AsyncsshTransport", _fake_transport_factory(dict(_ACTIVE_RESPONSES)))

    new_text = VALID_TOPO_TEXT.replace("note: vendor GUI client", "note: renamed")
    resp = client.put("/api/nutctl/topology", json={"yaml": new_text})
    assert resp.status_code == 200
    resp = client.post("/api/nutctl/deploy/node1")
    assert resp.status_code == 200

    events = db_mod.recent_events(limit=20)
    subjects = [e["event"] for e in events]
    assert "nutctl topology updated" in subjects
    assert "nutctl deploy node1" in subjects

    topo_event = next(e for e in events if e["event"] == "nutctl topology updated")
    assert "sha256=" in topo_event["detail"]
    assert topo_event["severity"] == db_mod.INFO

    deploy_event = next(e for e in events if e["event"] == "nutctl deploy node1")
    assert "ok=True" in deploy_event["detail"]
    assert deploy_event["severity"] == db_mod.INFO


def test_refused_deploy_still_writes_an_audit_event(client, monkeypatch):
    _login(client)
    monkeypatch.setattr(nutctl_routes, "AsyncsshTransport", _fake_transport_factory())
    # no UPS at all -> refused by the I6 telemetry gate
    resp = client.post("/api/nutctl/deploy/node1")
    assert resp.status_code == 409

    events = db_mod.recent_events(limit=20)
    deploy_event = next(e for e in events if e["event"] == "nutctl deploy node1")
    assert "refused" in deploy_event["detail"].lower()
    assert deploy_event["severity"] == db_mod.INFO


# --- fleet: empty then populated ----------------------------------------

def test_fleet_is_empty_before_the_first_probe_and_populated_after(client):
    _login(client)

    resp = client.get("/api/nutctl/fleet")
    assert resp.status_code == 200
    assert resp.json() == {}

    nutctl_routes.set_last_probe(
        {
            "node1": ProbeResult(ssh_ok=True, upsmon_active=True, config_match=True, detail="ok"),
            SERVER_KEY: ProbeResult(ssh_ok=True, upsmon_active=True, config_match=True, detail="ok"),
        },
        "2026-08-18T00:00:00+00:00",
    )

    resp = client.get("/api/nutctl/fleet")
    assert resp.status_code == 200
    body = resp.json()
    assert body["at"] == "2026-08-18T00:00:00+00:00"
    assert body["hosts"]["node1"]["ssh_ok"] is True
    assert body["hosts"][SERVER_KEY]["config_match"] is True
