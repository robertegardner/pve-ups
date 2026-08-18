"""nutctl REST routes: the fleet control-plane API, mounted under ``/api/nutctl``.

Every route here is wired into ``app.main`` behind upstream's ``require_auth``
dependency (applied once, at ``app.include_router(...)`` time -- see main.py) --
there is deliberately no per-route auth exception, including ``GET`` endpoints:
the topology file, the live-vs-rendered preview and the fleet probe results are
all fleet-operational detail, not public status.

Module-import seam
------------------
This module must never import ``app.main`` (main.py imports *this* module to
build the router, so the reverse import would be circular). Instead:

- ``set_engine`` / ``get_engine`` -- main.py's lifespan calls ``set_engine``
  once the global ``Engine`` exists; every route below reads it back through
  ``get_engine``.
- ``set_last_probe`` / the module-level ``_last_probe`` -- main.py's
  background probe task (see the "nutctl: observer-mode SSH fleet probe"
  section of main.py) writes results here after each sweep; ``GET /fleet``
  just reads them back. Empty until the first sweep completes.
- ``sync_topology_into_engine`` -- the one seam that rebuilds the engine's
  synthesized host list from the topology file. main.py calls it once at
  startup; ``PUT /topology`` calls it again after a successful write.

Secret handling
---------------
The nutnode/monuser passwords never round-trip to the
browser. ``GET /preview`` diffs the *redacted* render (secrets=None, i.e.
``@SECRET:x@`` placeholders) against the live file with any real secret
*values* substituted back to the same placeholders before the diff runs --
so an unchanged secret produces no diff noise, and a changed one shows up as
a placeholder-vs-placeholder no-op too (the value itself is simply never
rendered as text anywhere in the response). See ``_mask_secrets``.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

import yaml
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError

from ..config import AppConfig, HostConfig, NutConfig
from .bridge import synthesize_hosts
from .deploy import AsyncsshTransport, DeployResult, deploy_host, diff_files, fetch_live, revert_host
from .probe import SERVER_KEY, ProbeResult
from .render import render_host, render_server
from .topology import Topology, TopologyError, load_topology

log = logging.getLogger("pve-usv.nutctl.routes")

router = APIRouter(prefix="/api/nutctl", tags=["nutctl"])

#: Files that carry secret material, per render kind. Used only as a fallback
#: safety net when the local secrets file is missing (see ``_diff_host``):
#: with real secret values available, ``_mask_secrets`` already makes every
#: path safe to diff, regardless of which specific file happens to hold one.
_SECRET_BEARING_HOST_PATHS = {"/etc/nut/upsmon.conf"}
_SECRET_BEARING_SERVER_PATHS = {"/etc/nut/upsd.users"}
_WITHHELD_NOTE = (
    "(diff withheld: nutctl secrets are not configured locally, so a live value here "
    "cannot be safely masked before being shown)"
)

# --- engine seam (see module docstring) -------------------------------------
_engine = None


def set_engine(engine) -> None:
    global _engine
    _engine = engine


def get_engine():
    assert _engine is not None, "nutctl.routes.set_engine() was never called"
    return _engine


# --- last fleet-probe result (written by main.py's background probe task) --
_last_probe: dict[str, ProbeResult] = {}
_last_probe_at: Optional[str] = None


def set_last_probe(results: dict[str, ProbeResult], at: Optional[str]) -> None:
    global _last_probe, _last_probe_at
    _last_probe = results
    _last_probe_at = at


# --- secrets file -------------------------------------------------------
_SECRET_KEYS = ("nutnode_pass", "monuser_pass")


def load_secrets(path: str) -> dict[str, str]:
    """Best-effort read of the nutctl secrets file: ``{}`` if absent or unreadable.

    Format: YAML ``{nutnode_pass: ..., monuser_pass: ...}``.
    Callers must treat an empty result as "no secrets configured" and degrade
    safely (see ``_diff_host`` and the deploy routes' 409 when empty) -- never
    as "the secrets are the empty string".
    """
    p = Path(path)
    if not p.exists():
        return {}
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except Exception as exc:  # noqa: BLE001 - a broken secrets file must not crash a request
        log.warning("nutctl: could not read secrets file %s: %s", path, exc)
        return {}
    if not isinstance(data, dict):
        return {}
    return {k: str(data[k]) for k in _SECRET_KEYS if data.get(k)}


# --- topology -> engine host list (see sync_topology_into_engine) ----------
def _synthesize_hosts_for_engine(topo: Topology, ups: list) -> list[HostConfig]:
    """Map topology UPS names to upstream UPS ids via ``NutConfig.ups_name``,
    then synthesize the engine's host list -- skipping (with a warning) any
    host whose feeds are not *fully* mapped, rather than letting
    ``synthesize_hosts`` raise a KeyError for the whole fleet.
    """
    ups_id_by_nut_name = {u.ups_name: u.id for u in ups if isinstance(u, NutConfig) and u.ups_name}
    ok_hosts = {}
    for name, spec in topo.hosts.items():
        unmapped = [f for f in spec.feeds if f not in ups_id_by_nut_name]
        if unmapped:
            log.warning(
                "nutctl: host %s feeds %s have no matching NUT-source UPS (ups_name) "
                "in the appliance config -- excluded from the synthesized host list",
                name, unmapped,
            )
            continue
        ok_hosts[name] = spec
    filtered = topo.model_copy(update={"hosts": ok_hosts})
    return synthesize_hosts(filtered, ups_id_by_nut_name)


def sync_topology_into_engine(eng) -> None:
    """(Re)build ``eng``'s synthesized nutctl host list from the topology file.

    Best-effort: a missing or invalid topology file logs and leaves whatever
    the engine already has untouched -- covers first boot (no topology
    written yet) and a startup racing a bad hand-edit of the file on disk.
    """
    path = Path(eng.cfg.nutctl_topology_path)
    if not path.exists():
        log.info("nutctl: no topology file at %s yet -- engine host list unchanged", path)
        return
    try:
        topo = load_topology(path)
    except TopologyError as exc:
        log.warning("nutctl: topology at %s is invalid, engine host list unchanged: %s", path, exc)
        return
    eng.set_nutctl_hosts(_synthesize_hosts_for_engine(topo, eng.cfg.ups))


def _fleet_on_battery_or_alarm(eng) -> bool:
    """True if any configured UPS is on battery (or blind-but-still-timed) or in
    alarm -- the interlock that refuses a deploy while an outage is live."""
    return any(
        rt.state.on_battery or rt.on_battery_since is not None or rt.alarm_active
        for rt in eng.ups_rt.values()
    )


def _load_topology_or_409(eng) -> Topology:
    try:
        return load_topology(Path(eng.cfg.nutctl_topology_path))
    except TopologyError as exc:
        raise _Conflict([str(exc)]) from exc


class _Conflict(Exception):
    """Internal signal for a 409 {"errors": [...]} response (see the routes below)."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors


def _host_or_404(topo: Topology, name: str):
    if name == SERVER_KEY:
        return None
    if name not in topo.hosts:
        raise HTTPException(status_code=404, detail=f"unknown host: {name}")
    if topo.hosts[name].type == "display-only":
        raise HTTPException(status_code=400, detail=f"{name} is display-only, nothing to do")
    return topo.hosts[name]


# --- GET /topology -----------------------------------------------------------
@router.get("/topology")
async def get_topology():
    eng = get_engine()
    path = Path(eng.cfg.nutctl_topology_path)
    if not path.exists():
        return {"yaml": "", "errors": ["no topology file exists yet at " + str(path)]}
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    try:
        topo = Topology.model_validate(yaml.safe_load(text) or {})
        errors = topo.validate_invariants()
    except (ValidationError, yaml.YAMLError) as exc:
        errors = [str(exc)]
    return {"yaml": text, "errors": errors}


# --- PUT /topology -----------------------------------------------------------
class TopologyBody(BaseModel):
    yaml: str


@router.put("/topology")
async def put_topology(body: TopologyBody):
    try:
        data = yaml.safe_load(body.yaml) or {}
        topo = Topology.model_validate(data)
    except (ValidationError, yaml.YAMLError) as exc:
        return JSONResponse(status_code=409, content={"errors": [str(exc)]})

    errors = topo.validate_invariants()
    if errors:
        return JSONResponse(status_code=409, content={"errors": errors})

    eng = get_engine()
    path = Path(eng.cfg.nutctl_topology_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(body.yaml, encoding="utf-8")
    os.replace(tmp, path)

    sync_topology_into_engine(eng)
    return {"ok": True}


# --- GET /preview ------------------------------------------------------------
def _mask_secrets(text: Optional[str], secrets: dict[str, str]) -> Optional[str]:
    """Replace every occurrence of a real secret *value* in ``text`` with its
    ``@SECRET:key@`` placeholder, so it diffs clean against a redacted render.
    """
    if text is None:
        return None
    masked = text
    for key, value in secrets.items():
        if value:
            masked = masked.replace(value, f"@SECRET:{key}@")
    return masked


def _diff_per_file(live: dict[str, Optional[str]], rendered: dict[str, str]) -> dict[str, str]:
    """Per-path unified diffs (only paths that actually differ appear)."""
    files: dict[str, str] = {}
    for path in sorted(set(live) | set(rendered)):
        block = diff_files({path: live.get(path)}, {path: rendered.get(path)})
        if block:
            files[path] = block
    return files


async def _diff_named(t, topo: Topology, secrets: dict[str, str], name: str) -> dict:
    if name == SERVER_KEY:
        ssh = topo.nut_server.ssh
        rendered_secret = render_server(topo, secrets)
        rendered_redacted = render_server(topo, None)
        secret_paths = _SECRET_BEARING_SERVER_PATHS
    else:
        host = topo.hosts[name]
        assert host.ssh is not None  # display-only hosts are filtered out by the caller
        ssh = host.ssh
        rendered_secret = render_host(topo, name, secrets)
        rendered_redacted = render_host(topo, name, None)
        secret_paths = _SECRET_BEARING_HOST_PATHS

    live = await fetch_live(t, ssh, list(rendered_secret.keys()))
    masked_live = {p: _mask_secrets(c, secrets) for p, c in live.items()}
    files = _diff_per_file(masked_live, rendered_redacted)

    if not secrets:
        # No local secrets to mask with -- withhold any diff that could contain a
        # live secret value rather than ever show it (see module docstring).
        for p in secret_paths:
            if p in files:
                files[p] = _WITHHELD_NOTE

    return {"files": files, "drift": bool(files)}


@router.get("/preview")
async def get_preview():
    eng = get_engine()
    try:
        topo = _load_topology_or_409(eng)
    except _Conflict as exc:
        return JSONResponse(status_code=409, content={"errors": exc.errors})

    secrets = load_secrets(eng.cfg.nutctl_secrets_path)
    t = AsyncsshTransport(eng.cfg.nutctl_key_path)

    names = [SERVER_KEY] + [n for n, h in topo.hosts.items() if h.type != "display-only"]
    return {name: await _diff_named(t, topo, secrets, name) for name in names}


# --- deploy -------------------------------------------------------------
def _write_repo_snapshot(cfg: AppConfig, name: str, rendered_redacted: dict[str, str]) -> None:
    """Best-effort: mirror the REDACTED render tree into the repo, for review/diff
    history. Never touched when ``nutctl_repo_dir`` is unset (default: off)."""
    if not cfg.nutctl_repo_dir:
        return
    out_dir = Path(cfg.nutctl_repo_dir) / "nut" / "rendered" / name
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        for path, content in rendered_redacted.items():
            (out_dir / Path(path).name).write_text(content, encoding="utf-8")
    except Exception as exc:  # noqa: BLE001 - the deploy itself already succeeded
        log.warning("nutctl: could not write repo snapshot for %s under %s: %s",
                    name, cfg.nutctl_repo_dir, exc)


async def _deploy_server(t, topo: Topology, secrets: dict[str, str]) -> DeployResult:
    ssh = topo.nut_server.ssh
    rendered = render_server(topo, secrets)
    live = await fetch_live(t, ssh, list(rendered.keys()))

    # Driver bounce is only worth the (serialized, per-UPS) disruption when
    # ups.conf actually changed; upsd.users changing only needs upsd reloaded.
    reload_cmds: list[str] = []
    if live.get("/etc/nut/ups.conf") != rendered.get("/etc/nut/ups.conf"):
        for name in sorted(topo.ups):
            reload_cmds += [
                f"upsdrvctl stop {name}",
                f"upsdrvctl start {name}",
                f"upsc {name}@localhost",
            ]
    if live.get("/etc/nut/upsd.users") != rendered.get("/etc/nut/upsd.users"):
        reload_cmds.append("systemctl reload nut-server")

    return await deploy_host(t, ssh, rendered, reload_cmds=reload_cmds, on_battery=False)


async def _deploy_client(t, topo: Topology, secrets: dict[str, str], name: str) -> DeployResult:
    host = topo.hosts[name]
    assert host.ssh is not None
    rendered = render_host(topo, name, secrets)
    return await deploy_host(t, host.ssh, rendered, reload_cmds=["upsmon -c reload"], on_battery=False)


async def _deploy_named(t, topo: Topology, secrets: dict[str, str], name: str) -> DeployResult:
    if name == SERVER_KEY:
        return await _deploy_server(t, topo, secrets)
    return await _deploy_client(t, topo, secrets, name)


def _redacted_render(topo: Topology, name: str) -> dict[str, str]:
    return render_server(topo, None) if name == SERVER_KEY else render_host(topo, name, None)


class _Conflict409(Exception):
    def __init__(self, content: dict) -> None:
        self.content = content


async def _deploy_route(names: Optional[list[str]]) -> dict[str, dict]:
    """Shared body for /deploy/{host} (``names`` = a single host) and
    /deploy-fleet (``names=None`` -> every managed host + the server): on-battery
    interlock, secrets required, then one host at a time (stash/write/reload/
    verify each fully before moving to the next -- deploy_host already
    serializes its own reload_cmds; this just avoids running several hosts'
    pushes concurrently).
    """
    eng = get_engine()
    if _fleet_on_battery_or_alarm(eng):
        raise _Conflict409({"detail": "on battery"})

    cfg = eng.cfg
    secrets = load_secrets(cfg.nutctl_secrets_path)
    if not secrets:
        raise _Conflict409({"detail": "nutctl secrets not configured (nutctl_secrets_path is "
                                       "missing or empty) -- refusing to deploy placeholder "
                                       "text as a real password"})

    topo = _load_topology_or_409(eng)
    if names is None:
        names = [SERVER_KEY] + [n for n, h in topo.hosts.items() if h.type != "display-only"]
    else:
        for name in names:
            _host_or_404(topo, name)

    t = AsyncsshTransport(cfg.nutctl_key_path)
    out: dict[str, dict] = {}
    for name in names:
        result = await _deploy_named(t, topo, secrets, name)
        out[name] = {"ok": result.ok, "verified": result.verified, "detail": result.detail}
        if result.ok:
            _write_repo_snapshot(cfg, name, _redacted_render(topo, name))
    return out


@router.post("/deploy/{host}")
async def deploy_one(host: str):
    try:
        out = await _deploy_route([host])
    except _Conflict as exc:
        return JSONResponse(status_code=409, content={"errors": exc.errors})
    except _Conflict409 as exc:
        return JSONResponse(status_code=409, content=exc.content)
    return out[host]


@router.post("/deploy-fleet")
async def deploy_fleet():
    try:
        return await _deploy_route(None)
    except _Conflict as exc:
        return JSONResponse(status_code=409, content={"errors": exc.errors})
    except _Conflict409 as exc:
        return JSONResponse(status_code=409, content=exc.content)


# --- POST /revert/{host} -----------------------------------------------------
@router.post("/revert/{host}")
async def revert_one(host: str):
    eng = get_engine()
    try:
        topo = _load_topology_or_409(eng)
    except _Conflict as exc:
        return JSONResponse(status_code=409, content={"errors": exc.errors})

    _host_or_404(topo, host)
    if host == SERVER_KEY:
        ssh = topo.nut_server.ssh
        paths = list(render_server(topo, None).keys())
    else:
        host_spec = topo.hosts[host]
        assert host_spec.ssh is not None
        ssh = host_spec.ssh
        paths = list(render_host(topo, host, None).keys())

    t = AsyncsshTransport(eng.cfg.nutctl_key_path)
    result = await revert_host(t, ssh, paths)
    return {"ok": result.ok, "verified": result.verified, "detail": result.detail}


# --- GET /fleet ---------------------------------------------------------
@router.get("/fleet")
async def get_fleet():
    if not _last_probe:
        return {}
    return {
        "at": _last_probe_at,
        "hosts": {
            name: {
                "ssh_ok": r.ssh_ok,
                "upsmon_active": r.upsmon_active,
                "config_match": r.config_match,
                "detail": r.detail,
            }
            for name, r in _last_probe.items()
        },
    }
