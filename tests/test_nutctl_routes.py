"""Tests for the nutctl REST control plane (app/nutctl/routes.py) and its wiring
into app.main (require_auth, lifespan, the observer-mode SSH fleet probe).

Uses FastAPI's TestClient against the real `app.main.app`, with every path
(config file, event db, engine state file, nutctl topology/secrets/repo) pointed
into a per-test tmp_path -- no real SSH, no real filesystem outside tmp_path.
`AsyncsshTransport` is monkeypatched at the routes-module seam
(`app.nutctl.routes.AsyncsshTransport`) with a `FakeTransport`, exactly like
tests/test_nutctl_deploy.py and tests/test_nutctl_probe.py do for the lower
layers -- no real network ever touched.

Run with: pytest tests/test_nutctl_routes.py
"""
from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient
from passlib.context import CryptContext

from app import config as config_mod
from app import db as db_mod
from app import engine as engine_mod
from app import main as main_mod
from app.config import AppConfig
from app.nutctl import routes as nutctl_routes
from app.nutctl.probe import SERVER_KEY, ProbeResult
from app.nutctl.topology import SshSpec
from app.ups import UpsState

FIX = Path(__file__).parent / "fixtures" / "nutctl"
VALID_TOPO_TEXT = (FIX / "example-topology.yaml").read_text(encoding="utf-8")

PASSWORD = "testpass123"
SECRETS = {"nutnode_pass": "s3cret", "monuser_pass": "m4ster", "synology_pass": "syn0"}

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
def client(paths):
    _write_cfg(paths)
    with TestClient(main_mod.app) as c:
        yield c


def _login(client) -> None:
    resp = client.post("/api/login", json={"password": PASSWORD})
    assert resp.status_code == 200, resp.text


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


# --- preview: never leaks a secret value -------------------------------------

def test_preview_never_contains_a_secret_value(client, monkeypatch):
    _login(client)
    monkeypatch.setattr(nutctl_routes, "AsyncsshTransport", _fake_transport_factory())

    resp = client.get("/api/nutctl/preview")
    assert resp.status_code == 200
    raw = resp.text
    for value in SECRETS.values():
        assert value not in raw


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


def test_preview_withholds_secret_bearing_diff_when_secrets_missing(client, paths, monkeypatch):
    paths["secrets_path"].unlink()
    _write_cfg(paths)
    with TestClient(main_mod.app) as client2:
        _login(client2)
        monkeypatch.setattr(nutctl_routes, "AsyncsshTransport", _fake_transport_factory())

        resp = client2.get("/api/nutctl/preview")
        assert resp.status_code == 200
        body = resp.json()
        assert "withheld" in body[SERVER_KEY]["files"]["/etc/nut/upsd.users"].lower()


# --- deploy: on-battery interlock --------------------------------------------

def test_deploy_refuses_with_409_when_a_ups_is_on_battery(client, monkeypatch):
    _login(client)
    monkeypatch.setattr(nutctl_routes, "AsyncsshTransport", _fake_transport_factory())

    # Give the live engine one UPS and put it on battery.
    from app.config import SnmpConfig
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


def test_deploy_refuses_when_secrets_not_configured(client, paths, monkeypatch):
    paths["secrets_path"].unlink()
    _write_cfg(paths)
    with TestClient(main_mod.app) as client2:
        _login(client2)
        monkeypatch.setattr(nutctl_routes, "AsyncsshTransport", _fake_transport_factory())

        resp = client2.post("/api/nutctl/deploy/node1")
        assert resp.status_code == 409
        assert "secrets" in resp.json()["detail"].lower()


# --- deploy: happy path never touches real SSH, writes a redacted repo copy --

def test_deploy_one_host_uses_fake_transport_and_writes_redacted_repo_snapshot(client, paths, monkeypatch):
    _login(client)
    factory = _fake_transport_factory({
        "true": (0, "", ""),
        "systemctl is-active": (0, "active\n", ""),
    })
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
    factory = _fake_transport_factory({
        "true": (0, "", ""),
        "systemctl is-active": (0, "active\n", ""),
    })
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


# --- revert -------------------------------------------------------------

def test_revert_uses_fake_transport(client, monkeypatch):
    from app.nutctl.render import render_host

    _login(client)
    # A stash for every path node1's client render carries, so the revert is
    # fully "ok" (one path with no scripted stash would fail the whole thing).
    responses: dict[str, tuple[int, str, str]] = {
        "systemctl is-active": (0, "active\n", ""),
        "cp -a --": (0, "", ""),
    }
    from app.nutctl.topology import load_topology
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
