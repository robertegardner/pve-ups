"""nutctl REST routes: the fleet control-plane API, mounted under ``/api/nutctl``.

Every route here is wired into ``app.main`` behind upstream's ``require_auth``
dependency (applied once, at ``app.include_router(...)`` time -- see main.py) --
there is deliberately no per-route auth exception, including ``GET`` endpoints:
the topology file, the live-vs-rendered preview and the fleet probe results are
all fleet-operational detail, not public status. WRITE routes (PUT topology,
deploy, deploy-fleet, revert) additionally require ``require_ui_password_
configured``: upstream's bootstrap semantics treat "no UI password set yet" as
authenticated (so the setup wizard can run), which would otherwise let an
unauthenticated caller run deploy-fleet against the whole fleet during that
window -- see the fix-round-1 report, I4.

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
- ``AsyncsshTransport`` -- re-exported from ``.deploy`` and referenced ONLY as
  ``nutctl_routes.AsyncsshTransport`` (an attribute lookup at call time) by
  BOTH this module's routes and main.py's background probe task. That is a
  deliberate single seam: a test that monkeypatches this one attribute
  intercepts every transport construction in the app, including the
  background probe loop -- a second, independently-imported binding of the
  same class (as main.py originally had) would silently bypass the patch and
  make real SSH connection attempts during the test suite (fix-round-1, I3).

Secret handling
---------------
The nutnode/monuser passwords never round-trip to the browser.
``GET /preview`` redacts secret-carrying lines of the fetched live content
STRUCTURALLY -- by line pattern, never by knowing the real secret value --
before diffing against the fully redacted render (secrets=None, i.e.
``@SECRET:x@`` placeholders). This is what makes the redaction correct even
when a live value has DIVERGED from the local secrets file (a password
rotation, or a host still carrying whatever ``install-client.sh`` originally
wrote): see ``_structural_redact`` and the fix-round-1 report, C1.
``_mask_secrets`` (substituting the real, currently-configured values) runs
as a second, redundant net on top of that -- it is not load-bearing for
correctness, only defense in depth.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
from pathlib import Path
from typing import Optional

import yaml
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError

from .. import db
from ..config import AppConfig, HostConfig, NutConfig
from .bridge import synthesize_hosts
from .deploy import (
    AsyncsshTransport,
    DeployRefused,
    DeployResult,
    deploy_host,
    diff_files,
    fetch_live,
    revert_host,
)
from .probe import SERVER_KEY, ProbeResult
from .render import render_host, render_server
from .topology import Topology, TopologyError, load_topology

log = logging.getLogger("pve-usv.nutctl.routes")

router = APIRouter(prefix="/api/nutctl", tags=["nutctl"])


# --- engine seam (see module docstring) -------------------------------------
_engine = None


def set_engine(engine) -> None:
    global _engine
    _engine = engine


def get_engine():
    assert _engine is not None, "nutctl.routes.set_engine() was never called"
    return _engine


# --- auth: WRITE routes additionally require a UI password (I4) -------------
async def require_ui_password_configured() -> None:
    """Extra guard for nutctl WRITE routes.

    Upstream's ``require_auth``/``_is_authenticated`` (app/main.py) treats the
    bootstrap state -- no UI password set yet -- as authenticated, specifically
    so the setup wizard can run unauthenticated. For the plain upstream app
    that window only exposes the appliance's own config. For nutctl it would
    also expose ``deploy-fleet``: hundreds of root-level remote commands across
    the whole fleet, with no session at all. Read routes keep the ordinary
    upstream bootstrap semantics (harmless: they return topology/preview/fleet
    detail, not actions); every write refuses outright until a password
    exists.
    """
    eng = get_engine()
    if not eng.cfg.ui_password_hash:
        raise HTTPException(status_code=403, detail="set a UI password first")


# --- last fleet-probe result (written by main.py's background probe task) --
_last_probe: dict[str, ProbeResult] = {}
_last_probe_at: Optional[str] = None


def set_last_probe(results: dict[str, ProbeResult], at: Optional[str]) -> None:
    global _last_probe, _last_probe_at
    _last_probe = results
    _last_probe_at = at


# --- secrets file -------------------------------------------------------
_SECRET_KEYS = ("nutnode_pass", "monuser_pass")


def _raw_secrets_data(path: str) -> dict:
    """The secrets file's parsed content, as-is (may be partial/empty/absent)."""
    p = Path(path)
    if not p.exists():
        return {}
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except Exception as exc:  # noqa: BLE001 - a broken secrets file must not crash a request
        log.warning("nutctl: could not read secrets file %s: %s", path, exc)
        return {}
    return data if isinstance(data, dict) else {}


def load_secrets(path: str) -> dict[str, str]:
    """Read the nutctl secrets file: ``{}`` unless EVERY key in ``_SECRET_KEYS``
    is present and non-empty.

    Format: YAML ``{nutnode_pass: ..., monuser_pass: ...}``. All-or-nothing on
    purpose (fix-round-1, I2): a partially populated file used to pass the
    truthiness check callers use for "are secrets configured", then blow up
    deep inside ``render.py`` with a ``KeyError`` on whichever key was typo'd
    or missing -- a 500 on both ``/preview`` and ``/deploy-fleet``. Treating a
    partial file exactly like an absent one means every caller's existing
    "not secrets -> degrade/refuse safely" path already handles it correctly,
    with no special-casing needed anywhere else.
    """
    data = _raw_secrets_data(path)
    values = {k: str(data[k]) for k in _SECRET_KEYS if data.get(k)}
    if len(values) != len(_SECRET_KEYS):
        return {}
    return values


def _missing_secret_keys(path: str) -> list[str]:
    """Which of ``_SECRET_KEYS`` the file is missing (for a helpful 409 detail)."""
    data = _raw_secrets_data(path)
    return [k for k in _SECRET_KEYS if not data.get(k)]


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

    Gated on ``cfg.observer_mode`` (fix-round-1, I5): a non-observer appliance
    holds REAL shutdown authority over ``cfg.hosts`` (armed PVE nodes with real
    API tokens); installing a synthesized, inert host list on top of that would
    silently stop it from ever evaluating or shutting down its actual fleet.
    When observer_mode is False, any previously-synthesized list is cleared
    (``set_nutctl_hosts(None)``) rather than left stale -- e.g. an operator who
    flips observer_mode off via ``/api/config`` without re-running this. As a
    second, independent safety net for that same stale-list case,
    ``Engine._ordered_hosts()`` ALSO re-checks ``observer_mode`` at read time
    and ignores ``nutctl_hosts`` whenever it is False, regardless of what this
    function last did.

    Otherwise best-effort: a missing or invalid topology file logs and leaves
    whatever the engine already has untouched -- covers first boot (no
    topology written yet) and a startup racing a bad hand-edit of the file.
    """
    if not eng.cfg.observer_mode:
        log.info(
            "nutctl: observer_mode is False -- this appliance holds real shutdown "
            "authority over cfg.hosts, so synthesized nutctl hosts are never "
            "installed (see fix-round-1 I5); clearing any stale synthesized list."
        )
        eng.set_nutctl_hosts(None)
        return
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


def _fleet_battery_refusal(eng) -> Optional[str]:
    """``None`` = clear to deploy. Otherwise the refusal detail string.

    Two distinct failure modes (fix-round-1, I6):

    - an active outage/alarm on a known UPS (the ordinary interlock: fresh
      on-battery, the blind-but-still-timed latch, or the unreachable alarm);
    - NO UPS telemetry at all. ``any(...)`` over an EMPTY ``ups_rt`` is
      ``False`` -- an appliance with no UPS configured/mapped would otherwise
      pass this check vacuously, which is a fail-OPEN bug during exactly the
      scenario the interlock exists for. Treated as a hard refusal, not a
      pass: deploying blind (no idea whether the fleet is currently riding out
      an outage) is not an acceptable default.
    """
    if not eng.ups_rt:
        return "no UPS telemetry (no UPS is configured/mapped) -- refusing to deploy blind"
    if any(
        rt.state.on_battery or rt.on_battery_since is not None or rt.alarm_active
        for rt in eng.ups_rt.values()
    ):
        return "on battery"
    return None


def _load_topology_or_409(eng) -> Topology:
    try:
        return load_topology(Path(eng.cfg.nutctl_topology_path))
    except TopologyError as exc:
        raise _Conflict([str(exc)]) from exc


class _Conflict(Exception):
    """Internal signal for a 409 {"errors": [...]} response (see the routes below)."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors


class _Conflict409(Exception):
    """Internal signal for a 409 response with an arbitrary JSON body."""

    def __init__(self, content: dict) -> None:
        self.content = content


def _host_or_404(topo: Topology, name: str):
    if name == SERVER_KEY:
        return None
    if name not in topo.hosts:
        raise HTTPException(status_code=404, detail=f"unknown host: {name}")
    if topo.hosts[name].type == "display-only":
        raise HTTPException(status_code=400, detail=f"{name} is display-only, nothing to do")
    return topo.hosts[name]


def _actor(request: Request) -> str:
    """Best-effort identity for the audit log (fix-round-1, I7).

    Upstream has no per-user accounts at all -- one shared UI password, and the
    signed session cookie carries no username, just "ok" (see
    app/main.py:api_login). There is no real identity to name. The closest
    thing "the session" exposes is the caller's remote address, so that is
    what gets logged; a future multi-user auth layer should replace this with
    the real identity it introduces.
    """
    return request.client.host if request.client else "unknown"


def _audit(subject: str, detail: str) -> None:
    """Quiet (no notify) INFO event -- the nutctl audit trail (fix-round-1, I7)."""
    try:
        db.log_event(subject, detail, db.INFO)
    except Exception as exc:  # noqa: BLE001 - the operation itself already happened
        log.warning("nutctl: audit log write failed for %r: %s", subject, exc)


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


@router.put("/topology", dependencies=[Depends(require_ui_password_configured)])
async def put_topology(body: TopologyBody, request: Request):
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
    content_hash = hashlib.sha256(body.yaml.encode("utf-8")).hexdigest()[:12]
    _audit("nutctl topology updated", f"by {_actor(request)}; sha256={content_hash}")
    return {"ok": True}


# --- GET /preview ------------------------------------------------------------
#: MONITOR <ups>@<host> <n> <user> <pass> <role> (render.py's client render,
#: both the generic pve-node account "nutnode" and the nas-nut-client account
#: "monuser" -- the user token IS the secret key's prefix in both cases).
_MONITOR_LINE_RE = re.compile(r"^(MONITOR\s+\S+\s+\S+\s+)(\S+)(\s+)(\S+)(\s+\S+\s*)$")
#: upsd.users section headers ("[monuser]" / "[nutnode]") and its 2-space-
#: indented "password = ..." body line (render.py's server render).
_UPSD_SECTION_RE = re.compile(r"^\[(.+?)\]\s*$")
_UPSD_PASSWORD_RE = re.compile(r"^(\s*password\s*=\s*)(\S*)(.*)$")


def _redact_upsmon_conf(text: str) -> str:
    """Mask field 4 (the password) of every MONITOR line, keyed by field 3
    (the account name -- "nutnode"/"monuser" -- so the placeholder always
    names the SAME secret key ``render.py`` would resolve for that account),
    regardless of what the live value actually is."""
    out = []
    for line in text.splitlines(keepends=True):
        newline = "\n" if line.endswith("\n") else ""
        m = _MONITOR_LINE_RE.match(line[: len(line) - len(newline)])
        if m:
            user = m.group(2)
            out.append(f"{m.group(1)}{user}{m.group(3)}@SECRET:{user}_pass@{m.group(5)}{newline}")
        else:
            out.append(line)
    return "".join(out)


def _redact_upsd_users(text: str) -> str:
    """Mask the value of every "password = ..." line, keyed by the account
    name of the ``[section]`` it falls under -- regardless of the live value."""
    section: Optional[str] = None
    out = []
    for line in text.splitlines(keepends=True):
        newline = "\n" if line.endswith("\n") else ""
        body = line[: len(line) - len(newline)]
        sm = _UPSD_SECTION_RE.match(body)
        if sm:
            section = sm.group(1)
            out.append(line)
            continue
        pm = _UPSD_PASSWORD_RE.match(body)
        if pm:
            key = f"{section}_pass" if section else "unknown"
            out.append(f"{pm.group(1)}@SECRET:{key}@{pm.group(3)}{newline}")
        else:
            out.append(line)
    return "".join(out)


def _structural_redact(path: str, text: Optional[str]) -> Optional[str]:
    """Mask secret-carrying values in ``text`` (fetched live from a host) by
    LINE PATTERN -- never by knowing the real secret value. This is what makes
    the redaction correct even when the live value has DIVERGED from the local
    secrets file (rotation, or a host still on install-client.sh's original
    password): see the module docstring and fix-round-1's C1.
    """
    if text is None:
        return None
    if path == "/etc/nut/upsmon.conf":
        return _redact_upsmon_conf(text)
    if path == "/etc/nut/upsd.users":
        return _redact_upsd_users(text)
    return text


def _mask_secrets(text: Optional[str], secrets: dict[str, str]) -> Optional[str]:
    """Replace every occurrence of a real, currently-configured secret *value*
    in ``text`` with its ``@SECRET:key@`` placeholder. Redundant defense in
    depth on top of ``_structural_redact`` (which is what actually guarantees
    no secret reaches the response) -- kept because it is cheap and catches a
    value that leaked somewhere ``_structural_redact``'s two known patterns
    don't cover.
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
        rendered_redacted = render_server(topo, None)
    else:
        host = topo.hosts[name]
        assert host.ssh is not None  # display-only hosts are filtered out by the caller
        ssh = host.ssh
        rendered_redacted = render_host(topo, name, None)

    live = await fetch_live(t, ssh, list(rendered_redacted.keys()))
    # Primary defense: structural, pattern-based redaction that needs no
    # knowledge of the real secret value (see _structural_redact / C1). Value-
    # based masking runs after as a second, redundant net.
    redacted_live = {p: _structural_redact(p, c) for p, c in live.items()}
    masked_live = {p: _mask_secrets(c, secrets) for p, c in redacted_live.items()}
    files = _diff_per_file(masked_live, rendered_redacted)

    return {"files": files, "drift": bool(files)}


@router.get("/preview")
async def get_preview():
    eng = get_engine()
    try:
        topo = _load_topology_or_409(eng)
    except _Conflict as exc:
        return JSONResponse(status_code=409, content={"errors": exc.errors})

    # {} when the secrets file is missing OR partial (see load_secrets) -- safe
    # either way, since _structural_redact does not depend on knowing the real
    # values at all; _mask_secrets just has nothing extra to mask with.
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


async def _deploy_server(t, topo: Topology, secrets: dict[str, str], on_battery: bool) -> DeployResult:
    ssh = topo.nut_server.ssh
    rendered = render_server(topo, secrets)
    live = await fetch_live(t, ssh, list(rendered.keys()))

    # Driver bounce is only worth the (serialized, per-UPS) disruption when
    # ups.conf actually changed. The reload happens whenever EITHER file
    # changed (fix-round-1, I9): upsd only learns about added/removed ups.conf
    # stanzas on start/reload, so a ups.conf-only change still needs it -- the
    # driver restarts run first, the (single, de-duplicated) reload after.
    ups_conf_changed = live.get("/etc/nut/ups.conf") != rendered.get("/etc/nut/ups.conf")
    users_changed = live.get("/etc/nut/upsd.users") != rendered.get("/etc/nut/upsd.users")

    reload_cmds: list[str] = []
    if ups_conf_changed:
        for name in sorted(topo.ups):
            reload_cmds += [
                f"upsdrvctl stop {name}",
                f"upsdrvctl start {name}",
                f"upsc {name}@localhost",
            ]
    if ups_conf_changed or users_changed:
        reload_cmds.append("systemctl reload nut-server")

    return await deploy_host(t, ssh, rendered, reload_cmds=reload_cmds, on_battery=on_battery)


async def _deploy_client(t, topo: Topology, secrets: dict[str, str], name: str, on_battery: bool) -> DeployResult:
    host = topo.hosts[name]
    assert host.ssh is not None
    rendered = render_host(topo, name, secrets)
    return await deploy_host(t, host.ssh, rendered, reload_cmds=["upsmon -c reload"], on_battery=on_battery)


async def _deploy_named(t, topo: Topology, secrets: dict[str, str], name: str, on_battery: bool) -> DeployResult:
    if name == SERVER_KEY:
        return await _deploy_server(t, topo, secrets, on_battery)
    return await _deploy_client(t, topo, secrets, name, on_battery)


def _redacted_render(topo: Topology, name: str) -> dict[str, str]:
    return render_server(topo, None) if name == SERVER_KEY else render_host(topo, name, None)


async def _deploy_route(names: Optional[list[str]]) -> dict[str, dict]:
    """Shared body for /deploy/{host} (``names`` = a single host) and
    /deploy-fleet (``names=None`` -> every managed host + the server).

    Order: validate the request shape first (topology load, unknown/display-
    only host -> 404/400) -- cheap, and independent of operational state --
    THEN the on-battery/telemetry interlock, THEN secrets. Hosts are deployed
    one at a time; the battery/telemetry predicate is RE-EVALUATED immediately
    before each host (fix-round-1, I6): a fleet deploy is hundreds of
    sequential SSH round trips, so a UPS dropping to battery mid-run must stop
    the REMAINING hosts, not just gate the first one. The live predicate value
    is threaded into ``deploy_host``'s own ``on_battery`` param (rather than
    just checked here) so ``deploy.py``'s ``DeployRefused`` guard -- previously
    dead, since both call sites hardcoded ``on_battery=False`` -- is the thing
    that actually stops a host once tripped.
    """
    eng = get_engine()
    cfg = eng.cfg

    topo = _load_topology_or_409(eng)
    if names is None:
        names = [SERVER_KEY] + [n for n, h in topo.hosts.items() if h.type != "display-only"]
    else:
        for name in names:
            _host_or_404(topo, name)

    refusal = _fleet_battery_refusal(eng)
    if refusal is not None:
        raise _Conflict409({"detail": refusal})

    secrets = load_secrets(cfg.nutctl_secrets_path)
    if not secrets:
        missing = _missing_secret_keys(cfg.nutctl_secrets_path)
        detail = "nutctl secrets not configured"
        if missing:
            detail += f" (missing: {', '.join(missing)})"
        detail += " -- refusing to deploy placeholder text as a real password"
        raise _Conflict409({"detail": detail, "missing_keys": missing})

    t = AsyncsshTransport(cfg.nutctl_key_path)
    out: dict[str, dict] = {}
    for name in names:
        on_battery = _fleet_battery_refusal(eng) is not None
        try:
            result = await _deploy_named(t, topo, secrets, name, on_battery)
        except DeployRefused as exc:
            out[name] = {"ok": False, "verified": False, "detail": f"refused: {exc}"}
            break  # the interlock tripped mid-run -- stop, don't touch the rest
        out[name] = {"ok": result.ok, "verified": result.verified, "detail": result.detail}
        if result.ok:
            _write_repo_snapshot(cfg, name, _redacted_render(topo, name))
    return out


def _deploy_summary(out: dict[str, dict]) -> str:
    return "; ".join(f"{name}: ok={v['ok']} verified={v['verified']}" for name, v in out.items())


@router.post("/deploy/{host}", dependencies=[Depends(require_ui_password_configured)])
async def deploy_one(host: str, request: Request):
    actor = _actor(request)
    try:
        out = await _deploy_route([host])
    except _Conflict as exc:
        _audit(f"nutctl deploy {host}", f"by {actor}: refused - {'; '.join(exc.errors)}")
        return JSONResponse(status_code=409, content={"errors": exc.errors})
    except _Conflict409 as exc:
        _audit(f"nutctl deploy {host}", f"by {actor}: refused - {exc.content.get('detail')}")
        return JSONResponse(status_code=409, content=exc.content)
    result = out[host]
    _audit(
        f"nutctl deploy {host}",
        f"by {actor}: ok={result['ok']} verified={result['verified']} - {result['detail']}",
    )
    return result


@router.post("/deploy-fleet", dependencies=[Depends(require_ui_password_configured)])
async def deploy_fleet(request: Request):
    actor = _actor(request)
    try:
        out = await _deploy_route(None)
    except _Conflict as exc:
        _audit("nutctl deploy-fleet", f"by {actor}: refused - {'; '.join(exc.errors)}")
        return JSONResponse(status_code=409, content={"errors": exc.errors})
    except _Conflict409 as exc:
        _audit("nutctl deploy-fleet", f"by {actor}: refused - {exc.content.get('detail')}")
        return JSONResponse(status_code=409, content=exc.content)
    _audit("nutctl deploy-fleet", f"by {actor}: {_deploy_summary(out)}")
    return out


# --- POST /revert/{host} -----------------------------------------------------
@router.post("/revert/{host}", dependencies=[Depends(require_ui_password_configured)])
async def revert_one(host: str, request: Request):
    actor = _actor(request)
    eng = get_engine()
    try:
        topo = _load_topology_or_409(eng)
    except _Conflict as exc:
        _audit(f"nutctl revert {host}", f"by {actor}: refused - {'; '.join(exc.errors)}")
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

    # Deliberately NOT gated by the battery/telemetry interlock: reverting a
    # bad push is exactly the kind of thing you'd want to do mid-outage (see
    # deploy.py's revert_host docstring).
    t = AsyncsshTransport(eng.cfg.nutctl_key_path)
    result = await revert_host(t, ssh, paths)
    _audit(
        f"nutctl revert {host}",
        f"by {actor}: ok={result.ok} verified={result.verified} - {result.detail}",
    )
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
