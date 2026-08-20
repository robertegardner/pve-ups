"""FastAPI application: REST status (public) + config wizard (authenticated).

Copyright 2026 Florian Finder
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import subprocess
import tarfile
import time
import zipfile
from contextlib import asynccontextmanager
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, File, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from itsdangerous import BadSignature, URLSafeTimedSerializer
from passlib.context import CryptContext
from pydantic import BaseModel

from . import __version__, config, db, notify
from .config import (
    UPS_SOURCE_MODELS,
    AppConfig,
    HostConfig,
    SnmpConfig,
    UpsBase,
    _to_serialisable,
    assign_ups_ids,
    load_config,
    save_config,
)
from .engine import Engine, selftest_slot
from . import proxmox, proxyauth, sources
from .nutctl import routes as nutctl_routes
from .nutctl.probe import probe_fleet as nutctl_probe_fleet
from .nutctl.topology import TopologyError as NutctlTopologyError
from .nutctl.topology import load_topology as nutctl_load_topology

log = logging.getLogger("pve-usv")

WEB_DIR = Path(__file__).parent / "web"
SECRET_PLACEHOLDER = "**********"  # pydantic SecretStr json mask; means "unchanged"
SESSION_COOKIE = "pve_usv_session"
SESSION_MAX_AGE = 8 * 3600

# Deployment mode: "lxc" (default, privileged agent handles NTP/timezone/updates) or
# "docker" (no agent present; those features are disabled and surfaced to the UI).
DEPLOYMENT = os.environ.get("PVE_USV_DEPLOYMENT", "lxc").strip().lower()
IS_DOCKER = DEPLOYMENT == "docker"

# State dir layout (shared with the privileged deploy agent, see deploy/pve-usv-agent.*).
STATE_DIR = db.DB_PATH.parent
AGENT_DIR = STATE_DIR / "agent"
AGENT_QUEUE = AGENT_DIR / "queue"
AGENT_RESULT = AGENT_DIR / "result.json"
AGENT_SEEN = AGENT_DIR / "result.seen"  # job_id of the last result already logged
AGENT_LAST_JOB = AGENT_DIR / "last_job"  # job_id of the most recent upload (for the UI)
AGENT_LOG = AGENT_DIR / "agent.log"
UPDATE_DIR = STATE_DIR / "updates"
AGENT_TIMER_UNIT = Path("/etc/systemd/system/pve-usv-agent.timer")

pwd_ctx = CryptContext(schemes=["argon2"], deprecated="auto")

# Single global engine instance, created on startup.
engine: Optional[Engine] = None


# --- session helpers --------------------------------------------------------
def _serializer(cfg: AppConfig) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(cfg.session_secret, salt="pve-usv-session")


def _is_authenticated(request: Request, cfg: AppConfig) -> bool:
    # A trusted reverse proxy (authentik forward-auth) that injected an
    # identity header counts as a full session (see app/proxyauth.py).
    if proxyauth.header_identity(request, cfg) is not None:
        return True
    # Bootstrap: before a password is set the wizard is open so it can be set.
    if not cfg.ui_password_hash:
        return True
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return False
    try:
        _serializer(cfg).loads(token, max_age=SESSION_MAX_AGE)
        return True
    except BadSignature:
        return False


def require_auth(request: Request):
    assert engine is not None
    if not _is_authenticated(request, engine.cfg):
        raise HTTPException(status_code=401, detail="Authentication required")


# --- privileged deploy agent (update + NTP) ---------------------------------
def _enqueue_agent(action: str, **fields) -> str:
    """Drop a job for the root agent into the queue dir (the app stays unprivileged).

    The temp file is written OUTSIDE the watched queue dir and then atomically moved in.
    Writing the .tmp inside queue/ would already make the dir non-empty, so the systemd
    ``pve-usv-agent.path`` unit (DirectoryNotEmpty) could fire on the .tmp — which has no
    ``*.json`` match — and then never re-fire for the real file, silently dropping the job.
    Returns the job id so callers can correlate the result.
    """
    AGENT_QUEUE.mkdir(parents=True, exist_ok=True)
    job_id = f"{time.time_ns()}-{action}"
    req = {"job_id": job_id, "action": action, "ts": datetime.now(timezone.utc).isoformat(), **fields}
    tmp = AGENT_DIR / f".{job_id}.json.tmp"  # sibling of queue/, same filesystem
    tmp.write_text(json.dumps(req), encoding="utf-8")
    os.replace(tmp, AGENT_QUEUE / f"{job_id}.json")
    return job_id


def _agent_drainer_active() -> Optional[bool]:
    """Is the queue-drainer (pve-usv-agent.timer) running? Best-effort, never raises.

    Detects the one-time bootstrap gap where a box was updated INTO the first version that
    ships the timer by an OLD agent that never installed it: then queued jobs are only picked
    up by the fragile inotify ``.path`` unit and can hang silently. The UI uses this to show a
    recovery hint instead of a perpetual "in queue" message.

    Returns True/False on Linux, or None when undeterminable (e.g. the Windows dev box).
    """
    try:
        # Read-only query; allowed under the service hardening (no extra privilege needed).
        out = subprocess.run(
            ["systemctl", "is-active", "pve-usv-agent.timer"],
            capture_output=True, text=True, timeout=2,
        )
        state = out.stdout.strip()
        if state in ("active", "inactive", "failed", "activating", "deactivating"):
            return state == "active"
    except Exception:
        pass
    # Fallback: the unit file is missing exactly in the bootstrap case (old agent never
    # installed it). Presence alone can't prove it's enabled, but absence is a clear signal.
    try:
        return AGENT_TIMER_UNIT.exists()
    except Exception:
        return None


def _read_package_version(path: Path) -> Optional[str]:
    """Best-effort: read ``__version__`` from app/__init__.py inside the uploaded archive."""
    try:
        data: Optional[str] = None
        if path.name.endswith(".zip"):
            with zipfile.ZipFile(path) as z:
                names = [n for n in z.namelist() if n.endswith("app/__init__.py")]
                if names:
                    data = z.read(min(names, key=len)).decode("utf-8", "replace")
        else:
            with tarfile.open(path) as t:
                members = [m for m in t.getmembers() if m.name.endswith("app/__init__.py")]
                if members:
                    fh = t.extractfile(min(members, key=lambda m: len(m.name)))
                    data = fh.read().decode("utf-8", "replace") if fh else None
        if data:
            m = re.search(r"""__version__\s*=\s*["']([^"']+)["']""", data)
            if m:
                return m.group(1)
    except Exception as exc:  # noqa: BLE001 - best effort only
        log.warning("Could not read package version from %s: %s", path, exc)
    return None


def _ingest_agent_result() -> Optional[dict]:
    """Read the agent's last result and log it to the event log exactly once.

    Idempotent across restarts via the ``result.seen`` marker (the agent restarts the app
    after an update, so this also runs on the next startup and surfaces the outcome).
    """
    if not AGENT_RESULT.exists():
        return None
    try:
        result = json.loads(AGENT_RESULT.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        log.warning("Could not read agent result: %s", exc)
        return None

    job_id = result.get("job_id")
    seen = AGENT_SEEN.read_text(encoding="utf-8").strip() if AGENT_SEEN.exists() else None
    if job_id and job_id != seen:
        ok = bool(result.get("ok"))
        vb, va = result.get("version_before"), result.get("version_after")
        change = f" ({vb} → {va})" if (vb or va) else ""
        db.log_event(
            "Update applied" if ok else "Update FAILED",
            f"{result.get('message', '')}{change}",
            db.INFO if ok else db.CRITICAL,
        )
        try:
            AGENT_SEEN.write_text(job_id, encoding="utf-8")
        except Exception as exc:  # noqa: BLE001
            log.warning("Could not write agent seen-marker: %s", exc)
    return result


# --- nutctl: observer-mode SSH fleet probe -----------------------------------
# app.engine.Engine._maybe_selftest returns immediately while cfg.observer_mode is
# True (the nutctl fork's default) -- the Proxmox credential test has nothing real
# to check against a synthesized host's placeholder API URL. This task runs in its
# place, on the SAME selftest_slot cadence, and probes the actual NUT fleet over
# SSH instead (ssh reachability + upsmon health + config drift, app.nutctl.probe).
_NUTCTL_PROBE_TICK_S = 60

_nutctl_last_probe_slot: Optional[datetime] = None
#: The SET of hosts that were failing at the end of the previous sweep; None
#: until the first sweep completes. Deliberately a set, not an all-green
#: boolean: a boolean latch only fires on the aggregate all-green -> not-green
#: edge, so a SECOND host going bad while a first one is still bad is silent
#: until the whole fleet recovers -- exactly the dead-upsmon blind spot this
#: probe exists to close. Notifications key off set MEMBERSHIP changes instead.
_nutctl_last_bad: Optional[set[str]] = None


def _probe_failures(result, secrets_loaded: bool) -> list[str]:
    """Human-readable list of which checks failed for one host. Empty == green.

    `config_match` is only consulted when secrets are loaded (see the caller):
    without them, every secret-bearing line reads as drift against the redacted
    render, which is not a fleet regression.
    """
    reasons: list[str] = []
    if not result.ssh_ok:
        reasons.append("ssh unreachable")
        return reasons  # the other two signals are None -- nothing else to say
    if not result.upsmon_active:
        reasons.append("service check failed")
    if secrets_loaded and result.config_match is False:
        reasons.append("config drift")
    return reasons


async def _maybe_run_nutctl_probe() -> None:
    """Run the SSH fleet probe once per self-test slot; store results for
    GET /api/nutctl/fleet; emit an event (+ notify) whenever a host JOINS the
    failing set, and a quiet db-only event when hosts leave it.
    """
    global _nutctl_last_probe_slot, _nutctl_last_bad
    assert engine is not None
    cfg = engine.cfg
    if not cfg.observer_mode:
        return  # non-observer deployments have no topology-driven fleet to probe

    topo_path = Path(cfg.nutctl_topology_path)
    if not topo_path.exists():
        return  # nothing written yet -- nothing to probe

    slot = selftest_slot(datetime.now(), cfg.selftest_hour, cfg.selftest_interval_min)
    if _nutctl_last_probe_slot is not None and slot <= _nutctl_last_probe_slot:
        return
    _nutctl_last_probe_slot = slot

    try:
        topo = nutctl_load_topology(topo_path)
    except NutctlTopologyError as exc:
        log.warning("nutctl: topology invalid, skipping fleet probe: %s", exc)
        return

    secrets = nutctl_routes.load_secrets(cfg.nutctl_secrets_path)
    # Resolved through the SAME seam every route (and every test) patches --
    # ``nutctl_routes.AsyncsshTransport`` -- rather than a separately imported
    # binding of the same class. A second, independent import here used to
    # bypass any test's monkeypatch of the routes-module attribute and make
    # real asyncssh connection attempts on every test that starts the app
    # (fix-round-1, I3).
    transport = nutctl_routes.AsyncsshTransport(
        cfg.nutctl_key_path, cfg.nutctl_known_hosts_path
    )
    try:
        results = await nutctl_probe_fleet(transport, topo, secrets)
    except Exception as exc:  # noqa: BLE001 - a probe crash must not kill the poll loop
        log.warning("nutctl: fleet probe failed: %s", exc)
        return

    nutctl_routes.set_last_probe(results, datetime.now(timezone.utc).isoformat())

    # Secrets missing means every secret-bearing line reads as "drifted" against
    # the redacted render (probe_fleet has no Optional-secrets mode) -- that is
    # not a real fleet regression, so config_match is excluded from the verdict
    # in that case. ssh_ok/upsmon_active alone still catch a genuinely dead host.
    secrets_loaded = bool(secrets)

    failures = {
        name: _probe_failures(r, secrets_loaded) for name, r in results.items()
    }
    bad = {name for name, reasons in failures.items() if reasons}

    prev_bad = _nutctl_last_bad
    # First sweep of the process: everything currently bad counts as newly bad,
    # so a fleet that comes up already broken still notifies once.
    newly_bad = sorted(bad if prev_bad is None else bad - prev_bad)
    recovered = sorted((prev_bad - bad) if prev_bad is not None else set())
    still_bad = sorted(bad - set(newly_bad))

    if newly_bad:
        # "failed" is a deliberate severity keyword (app/notify.py: _severity)
        # -- a host dropping out of the fleet is the one thing this probe is
        # for, and it must not go out at ntfy's default priority.
        subject = f"nutctl fleet probe: {len(newly_bad)} host(s) failed"
        lines = [f"{name}: {', '.join(failures[name])}" for name in newly_bad]
        body = "Newly failing:\n" + "\n".join(lines)
        if still_bad:
            body += "\nStill failing: " + ", ".join(still_bad)
        db.log_event(subject, body, db.WARNING)
        await notify.notify(engine.cfg.notifications, f"[PVE-UPS] {subject}", body, {})

    if recovered:
        body = "Recovered: " + ", ".join(recovered)
        body += "\nFleet is all-green again." if not bad else f"\nStill failing: {', '.join(sorted(bad))}"
        db.log_event("nutctl fleet probe: recovered", body, db.INFO)

    _nutctl_last_bad = bad


async def _nutctl_probe_loop() -> None:
    while True:
        try:
            await _maybe_run_nutctl_probe()
        except Exception:  # noqa: BLE001 - the loop itself must never die
            log.exception("nutctl fleet probe tick failed")
        await asyncio.sleep(_NUTCTL_PROBE_TICK_S)


# --- lifespan ---------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    global engine
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    # Read the path off the module attribute (not the function's own default arg,
    # which is bound once at import time) so tests can monkeypatch db.DB_PATH /
    # config.CONFIG_PATH and have it actually take effect here.
    db.init_db(db.DB_PATH)
    cfg = load_config(config.CONFIG_PATH)
    engine = Engine(cfg)
    engine.start()
    nutctl_routes.set_engine(engine)
    nutctl_routes.sync_topology_into_engine(engine)
    nutctl_task = asyncio.create_task(_nutctl_probe_loop(), name="pve-usv-nutctl-probe")
    log.info("PVE-UPS %s started", __version__)
    # If we just restarted because of an applied update, surface its outcome now.
    try:
        _ingest_agent_result()
    except Exception as exc:  # noqa: BLE001
        log.warning("Ingesting agent result at startup failed: %s", exc)
    try:
        yield
    finally:
        nutctl_task.cancel()
        try:
            await nutctl_task
        except asyncio.CancelledError:
            pass
        if engine:
            await engine.stop()


app = FastAPI(title="PVE-UPS", version=__version__, lifespan=lifespan)

# nutctl fleet control-plane routes: same require_auth as every other authenticated
# endpoint below, applied once here rather than per-route (see app/nutctl/routes.py's
# module docstring for the "no exceptions" rationale).
app.include_router(nutctl_routes.router, dependencies=[Depends(require_auth)])


# --- public (read-only) endpoints ------------------------------------------
@app.get("/api/status")
async def api_status():
    """Full snapshot plus the event log of the last 48 h, so an external monitor can
    react to warnings/errors from this single (public, secret-free) endpoint."""
    assert engine is not None
    snap = engine.snapshot()
    try:
        snap["events"] = db.events_since(hours=48)
        snap["events_summary"] = db.severity_counts_since(hours=48)
    except Exception as exc:  # noqa: BLE001 - status must stay available even if the log read fails
        log.warning("Reading events for /api/status failed: %s", exc)
        snap["events"] = []
        snap["events_summary"] = {db.INFO: 0, db.WARNING: 0, db.CRITICAL: 0}
    return snap


@app.get("/api/health")
async def api_health():
    assert engine is not None
    snap = engine.snapshot()
    ok = engine._task is not None and not engine._task.done()
    ups_list = snap["ups"]
    payload = {
        "status": "ok" if ok else "degraded",
        "version": __version__,
        "engine_state": snap["appliance"]["engine_state"],
        # True only when every configured UPS is reachable (all() of empty list is True).
        "ups_reachable": all(u["reachable"] for u in ups_list),
        "ups_reachable_count": sum(1 for u in ups_list if u["reachable"]),
        "ups_total": len(ups_list),
    }
    return JSONResponse(payload, status_code=200 if ok else 503)


# --- auth -------------------------------------------------------------------
class LoginBody(BaseModel):
    password: str


@app.post("/api/login")
async def api_login(body: LoginBody, response: Response):
    assert engine is not None
    cfg = engine.cfg
    if not cfg.ui_password_hash:
        raise HTTPException(status_code=400, detail="No password set — run the setup first.")
    if not pwd_ctx.verify(body.password, cfg.ui_password_hash):
        raise HTTPException(status_code=401, detail="Wrong password")
    token = _serializer(cfg).dumps("ok")
    response.set_cookie(
        SESSION_COOKIE, token, max_age=SESSION_MAX_AGE, httponly=True, samesite="lax"
    )
    return {"ok": True}


@app.post("/api/logout")
async def api_logout(response: Response):
    response.delete_cookie(SESSION_COOKIE)
    return {"ok": True}


@app.get("/api/session")
async def api_session(request: Request):
    assert engine is not None
    return {
        "authenticated": _is_authenticated(request, engine.cfg),
        "password_set": bool(engine.cfg.ui_password_hash),
        "configured": engine.cfg.configured,
        "deployment": DEPLOYMENT,
    }


class PasswordBody(BaseModel):
    new_password: str
    current_password: Optional[str] = None


@app.post("/api/password")
async def api_password(body: PasswordBody, request: Request):
    assert engine is not None
    cfg = engine.cfg
    # If a password already exists, require the current one.
    if cfg.ui_password_hash:
        if not body.current_password or not pwd_ctx.verify(
            body.current_password, cfg.ui_password_hash
        ):
            raise HTTPException(status_code=401, detail="Current password is wrong")
    if len(body.new_password) < 6:
        raise HTTPException(status_code=400, detail="Password too short (min. 6 characters)")
    cfg.ui_password_hash = pwd_ctx.hash(body.new_password)
    save_config(cfg)
    engine.update_config(cfg)
    return {"ok": True}


# --- config (authenticated) -------------------------------------------------
def _sanitized_config(cfg: AppConfig) -> dict:
    data = cfg.model_dump(mode="json")  # SecretStr -> "**********"
    data.pop("session_secret", None)
    data.pop("ui_password_hash", None)
    return data


def _reconcile_secret(incoming, existing: str) -> str:
    if incoming in ("", None, SECRET_PLACEHOLDER):
        return existing
    return incoming


def _ups_model(ups_entry: dict) -> type[UpsBase]:
    """Model class for a submitted UPS entry; unknown/absent type means the legacy SNMP one."""
    return UPS_SOURCE_MODELS.get(str(ups_entry.get("type") or "snmp"), SnmpConfig)


def _reconcile_ups_secrets(ups_entry: dict, old: Optional[UpsBase]) -> None:
    """Carry over unchanged (masked) per-UPS secrets, in place.

    Which fields those are comes from the source model itself, so a new source type only
    has to declare ``secret_fields()`` to be handled correctly here.
    """
    model = _ups_model(ups_entry)
    for fld, default in model.secret_fields().items():
        # Only reuse the stored secret when the entry still is the same source type —
        # switching a UPS from SNMP to NUT must not inherit anything.
        keep = old is not None and isinstance(old, model)
        old_secret = getattr(old, fld).get_secret_value() if keep else default
        ups_entry[fld] = _reconcile_secret(ups_entry.get(fld), old_secret)


def _merge_config(incoming: dict, existing: AppConfig) -> AppConfig:
    """Build a new config, carrying over unchanged (masked) secrets."""
    data = dict(incoming)

    # Per-UPS secrets, matched by stable UPS id.
    existing_ups = {u.id: u for u in existing.ups}
    for ups_entry in data.get("ups", []) or []:
        _reconcile_ups_secrets(ups_entry, existing_ups.get(ups_entry.get("id")))
    data.pop("snmp", None)  # legacy key never accepted from the form

    # Host token secrets matched by node name
    existing_hosts = {h.name: h for h in existing.hosts}
    for host in data.get("hosts", []):
        old = existing_hosts.get(host.get("name"))
        old_secret = old.token_secret.get_secret_value() if old else ""
        host["token_secret"] = _reconcile_secret(host.get("token_secret"), old_secret)

    # ntfy bearer token: a masked value round-tripping from the UI must not clobber it.
    notifications = data.get("notifications")
    if isinstance(notifications, dict):
        old_ntfy_token = existing.notifications.ntfy_token.get_secret_value()
        notifications["ntfy_token"] = _reconcile_secret(
            notifications.get("ntfy_token"), old_ntfy_token
        )

    # Measured-circuit-power block (config-file managed; the settings form does
    # not render it): carry the whole block over when the form omits it, and
    # never let a masked HA token round-trip clobber the stored one.
    circuit_power = data.get("circuit_power")
    if isinstance(circuit_power, dict):
        old_ha_token = existing.circuit_power.ha_token.get_secret_value()
        circuit_power["ha_token"] = _reconcile_secret(
            circuit_power.get("ha_token"), old_ha_token
        )
    else:
        data["circuit_power"] = existing.circuit_power.model_dump(mode="python")

    # Same deal for the PDU-outlet-power block (config-file managed, no
    # secret): a form save that omits it must not reset it to defaults.
    if not isinstance(data.get("pdu_power"), dict):
        data["pdu_power"] = existing.pdu_power.model_dump(mode="python")

    # Never overwrite auth/session material from the config form.
    data["ui_password_hash"] = existing.ui_password_hash
    data["session_secret"] = existing.session_secret

    cfg = AppConfig.model_validate(data)
    assign_ups_ids(cfg.ups)  # safety net: fill any still-empty UPS ids with stable slugs
    return cfg


@app.get("/api/config", dependencies=[Depends(require_auth)])
async def api_get_config():
    assert engine is not None
    return _sanitized_config(engine.cfg)


@app.post("/api/config", dependencies=[Depends(require_auth)])
async def api_set_config(incoming: dict):
    assert engine is not None
    old_ntp = engine.cfg.ntp_server
    old_tz = engine.cfg.timezone
    try:
        new_cfg = _merge_config(incoming, engine.cfg)
    except Exception as exc:  # noqa: BLE001 - validation error -> 400
        raise HTTPException(status_code=400, detail=f"Invalid configuration: {exc}")
    new_cfg.configured = True
    save_config(new_cfg)
    engine.update_config(new_cfg)
    db.log_event("Configuration saved", "", db.INFO)
    # Apply changed system settings (NTP / timezone) via the privileged agent (needs root).
    # No agent exists in Docker deployments; the values persist but nothing is enqueued.
    if not IS_DOCKER:
        if new_cfg.ntp_server and new_cfg.ntp_server != old_ntp:
            _enqueue_agent("set-ntp", server=new_cfg.ntp_server)
        if new_cfg.timezone and new_cfg.timezone != old_tz:
            _enqueue_agent("set-timezone", tz=new_cfg.timezone)
    return _sanitized_config(new_cfg)


# --- config export / import (full backup incl. plaintext secrets) -----------
def _exportable_config(cfg: AppConfig) -> dict:
    """Full config with revealed secrets, minus this instance's auth/session material."""
    data = _to_serialisable(cfg)
    data.pop("session_secret", None)
    data.pop("ui_password_hash", None)
    return data


@app.get("/api/config/export", dependencies=[Depends(require_auth)])
async def api_config_export():
    assert engine is not None
    data = _exportable_config(engine.cfg)
    first_ups = engine.cfg.ups[0].label if engine.cfg.ups else ""
    host = re.sub(r"[^A-Za-z0-9._-]+", "-", first_ups).strip("-") or "appliance"
    stamp = datetime.now().strftime("%Y%m%d")
    filename = f"pve-usv-config-{host}-{stamp}.json"
    db.log_event("Configuration exported", "Backup including secrets downloaded.", db.INFO)
    return JSONResponse(
        data,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/api/config/import", dependencies=[Depends(require_auth)])
async def api_config_import(incoming: dict):
    assert engine is not None
    data = dict(incoming)
    # Keep the running instance's own auth/session material (not part of the backup).
    data["ui_password_hash"] = engine.cfg.ui_password_hash
    data["session_secret"] = engine.cfg.session_secret
    try:
        new_cfg = AppConfig.model_validate(data)
    except Exception as exc:  # noqa: BLE001 - validation error -> 400
        raise HTTPException(status_code=400, detail=f"Invalid import file: {exc}")
    assign_ups_ids(new_cfg.ups)  # backups from <2.0 migrate to a single UPS; ensure ids
    new_cfg.configured = True
    save_config(new_cfg)
    engine.update_config(new_cfg)
    db.log_event("Configuration imported", "Settings taken over from file.", db.WARNING)
    # No agent exists in Docker deployments; the values persist but nothing is enqueued.
    if not IS_DOCKER:
        if new_cfg.ntp_server:
            _enqueue_agent("set-ntp", server=new_cfg.ntp_server)
        if new_cfg.timezone:
            _enqueue_agent("set-timezone", tz=new_cfg.timezone)
    return _sanitized_config(new_cfg)


# --- tests / actions (authenticated) ---------------------------------------
@app.post("/api/test/ups", dependencies=[Depends(require_auth)])
async def api_test_ups(incoming: dict):
    """One-shot poll of the submitted UPS settings (secrets reconciled by UPS id).

    Runs the production poll *and* a per-object probe: the poll proves the path the engine
    actually uses works (an SNMPv1 multi-object GET can fail even when every object is
    readable on its own), the probe says which object is to blame and which triggers the
    device cannot feed at all.
    """
    assert engine is not None
    incoming = dict(incoming)
    existing_ups = {u.id: u for u in engine.cfg.ups}
    _reconcile_ups_secrets(incoming, existing_ups.get(incoming.get("id")))
    try:
        cfg = _ups_model(incoming).model_validate(incoming)
    except Exception as exc:  # noqa: BLE001 - validation error -> 400
        raise HTTPException(status_code=400, detail=f"Invalid UPS settings: {exc}")
    state = await sources.poll(cfg)
    diag = await sources.probe(cfg)
    return {
        "reachable": state.reachable,
        "power_source": state.power_source,
        "battery_status": state.battery_status,
        "runtime_remaining_min": state.runtime_remaining_min,
        "battery_charge_pct": state.battery_charge_pct,
        "error": state.error,
        "manufacturer": state.manufacturer,
        "model": state.model,
        "probe": {
            "reachable": diag.reachable,
            "summary": diag.summary,
            "ok_count": diag.ok_count,
            "total": diag.total,
            "mib": diag.mib,
            "entries": [asdict(e) for e in diag.entries],
            "missing_triggers": diag.missing_triggers,
        },
    }


@app.post("/api/test/snmp", dependencies=[Depends(require_auth)])
async def api_test_snmp(incoming: dict):
    """Kept for compatibility with 3.1.x; /api/test/ups supersedes it."""
    return await api_test_ups(incoming)


@app.post("/api/test/host", dependencies=[Depends(require_auth)])
async def api_test_host(incoming: dict):
    assert engine is not None
    # Reconcile this single host's secret against the stored one (by name).
    existing_hosts = {h.name: h for h in engine.cfg.hosts}
    old = existing_hosts.get(incoming.get("name"))
    old_secret = old.token_secret.get_secret_value() if old else ""
    incoming = dict(incoming)
    incoming["token_secret"] = _reconcile_secret(incoming.get("token_secret"), old_secret)
    host = HostConfig.model_validate(incoming)
    result = await proxmox.test_connection(host)
    return {"ok": result.ok, "message": result.message, "has_power_mgmt": result.has_power_mgmt}


@app.post("/api/test/shutdown", dependencies=[Depends(require_auth)])
async def api_test_shutdown():
    """Log a dry-run shutdown without touching the live state machine (always safe)."""
    assert engine is not None
    msg = await engine.simulate_shutdown()
    return {"ok": True, "message": msg}


@app.post("/api/reset", dependencies=[Depends(require_auth)])
async def api_reset():
    assert engine is not None
    engine.reset()
    db.log_event("State reset", "", db.INFO)
    return {"ok": True}


@app.get("/api/events", dependencies=[Depends(require_auth)])
async def api_events(limit: int = 100):
    return db.recent_events(limit)


@app.delete("/api/events", dependencies=[Depends(require_auth)])
async def api_events_clear():
    removed = db.clear_events()
    db.log_event("Event log cleared", f"{removed} entries removed.", db.INFO)
    return {"ok": True, "removed": removed}


# --- updater (manual upload, applied by the privileged agent) ---------------
def _read_text(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8")
    except Exception:  # noqa: BLE001
        return None


@app.get("/api/update/status", dependencies=[Depends(require_auth)])
async def api_update_status():
    if IS_DOCKER:
        # No privileged agent exists in a Docker deployment; there is no queue/log to
        # report. The frontend shows "docker pull" guidance instead of this panel.
        return {
            "version": __version__,
            "deployment": "docker",
            "result": None,
            "last_job": None,
            "pending": [],
            "log_tail": None,
            "agent_drainer": None,
        }
    # Ingesting here makes the outcome show up in the event log even if the user never
    # left the settings page open during the restart.
    result = _ingest_agent_result()
    pending = sorted(p.name for p in AGENT_QUEUE.glob("*.json")) if AGENT_QUEUE.exists() else []
    last_job = (_read_text(AGENT_LAST_JOB) or "").strip() or None
    log_tail = None
    raw = _read_text(AGENT_LOG)
    if raw:
        log_tail = "\n".join(raw.splitlines()[-40:])
    return {
        "version": __version__,
        "deployment": "lxc",
        "result": result,
        "last_job": last_job,
        "pending": pending,
        "log_tail": log_tail,
        "agent_drainer": _agent_drainer_active(),
    }


@app.post("/api/update/upload", dependencies=[Depends(require_auth)])
async def api_update_upload(file: UploadFile = File(...)):
    if IS_DOCKER:
        raise HTTPException(
            status_code=501,
            detail="In-app updates are not supported in Docker deployments. "
            "Pull a new image tag and recreate the container.",
        )
    name = file.filename or ""
    if not name.endswith((".tar.gz", ".tgz", ".zip")):
        raise HTTPException(status_code=400, detail="Only .tar.gz/.tgz/.zip allowed")
    UPDATE_DIR.mkdir(parents=True, exist_ok=True)
    # Sanitise the name to a basename; the agent only looks in UPDATE_DIR.
    safe = Path(name).name
    target = UPDATE_DIR / safe
    size = 0
    with target.open("wb") as fh:
        while chunk := await file.read(1 << 20):
            size += len(chunk)
            fh.write(chunk)

    pkg_version = _read_package_version(target)
    same_version = bool(pkg_version) and pkg_version == __version__
    job_id = _enqueue_agent("update", package=str(target))
    try:
        AGENT_LAST_JOB.write_text(job_id, encoding="utf-8")
    except Exception as exc:  # noqa: BLE001
        log.warning("Could not record last update job: %s", exc)
    db.log_event(
        "Update uploaded",
        f"Package {safe} ({size // 1024} KiB), package version {pkg_version or 'unknown'}; "
        f"running {__version__}. Applied by the system agent (job {job_id}).",
        db.WARNING,
    )
    return {
        "ok": True,
        "job_id": job_id,
        "package": safe,
        "package_version": pkg_version,
        "running_version": __version__,
        "same_version": same_version,
    }


# --- static UI --------------------------------------------------------------
@app.get("/")
async def index():
    return FileResponse(WEB_DIR / "index.html")


app.mount("/", StaticFiles(directory=WEB_DIR), name="web")


def run() -> None:
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=8080, log_level="info")


if __name__ == "__main__":
    run()
