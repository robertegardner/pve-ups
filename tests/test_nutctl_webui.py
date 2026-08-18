"""Tests for the nutctl web UI static assets (app/web/nutctl.html + nutctl.js).

These pages are served by the same `StaticFiles(directory=WEB_DIR)` mount as
index.html/app.js -- publicly, with no `require_auth` dependency (see
app/main.py's `app.mount("/", StaticFiles(directory=WEB_DIR), ...)` at the very
end of the route table, and the fact that none of index.html/app.js/manual.html
carry an auth check either). The auth boundary for nutctl lives entirely in the
API layer (`app.include_router(nutctl_routes.router,
dependencies=[Depends(require_auth)])`, exercised by tests/test_nutctl_routes.py)
-- the page itself just renders "please log in" client-side when /api/session
says unauthenticated. These tests confirm that split: the static assets are
public like every other page in the app, and the JS ships no fleet secrets or
hardcoded homelab identifiers (this is a public repo -- placeholder text only).

Run with: pytest tests/test_nutctl_webui.py
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from passlib.context import CryptContext

from app import config as config_mod
from app import db as db_mod
from app import engine as engine_mod
from app import main as main_mod
from app.config import AppConfig

WEB_DIR = Path(__file__).parent.parent / "app" / "web"
_pwd_ctx = CryptContext(schemes=["argon2"], deprecated="auto")
PASSWORD = "testpass123"

# Real homelab identifiers that must never leak into a public-repo static asset
# (see CLAUDE.md's "public repo: synthetic placeholder text only" instruction).
_FORBIDDEN_SUBSTRINGS = ["192.168.", "rtx", "thebeast", "wol", "cyber-"]


@pytest.fixture
def paths(tmp_path, monkeypatch):
    """Same seam-monkeypatching pattern as tests/test_nutctl_routes.py's `paths`
    fixture, trimmed to what booting the app + logging in needs -- no nutctl
    topology/secrets files, since these tests never touch /api/nutctl/*."""
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
    return {"tmp_path": tmp_path}


def _write_cfg(**overrides) -> AppConfig:
    kwargs = dict(
        configured=True,
        ui_password_hash=_pwd_ctx.hash(PASSWORD),
        observer_mode=True,
    )
    kwargs.update(overrides)
    cfg = AppConfig(**kwargs)
    config_mod.save_config(cfg, config_mod.CONFIG_PATH)
    return cfg


@pytest.fixture
def client(paths):
    _write_cfg()
    with TestClient(main_mod.app) as c:
        yield c


# --- the page is public, like every other static asset -----------------------

def test_nutctl_html_served_without_login(client):
    """No session cookie at all -- must still be 200 (static pages carry no
    require_auth dependency; the page itself handles "not logged in" client-side
    via /api/session, matching index.html's own pattern)."""
    resp = client.get("/nutctl.html")
    assert resp.status_code == 200
    assert "NUT Fleet" in resp.text  # <title> marker


def test_nutctl_html_served_with_login_too(client):
    """Same page, now with a real session -- still 200, same content (a static
    file has nothing that varies by auth state; the login gate only matters at
    the API layer, exercised separately in test_nutctl_routes.py)."""
    login = client.post("/api/login", json={"password": PASSWORD})
    assert login.status_code == 200, login.text

    resp = client.get("/nutctl.html")
    assert resp.status_code == 200
    assert "NUT Fleet" in resp.text


def test_nutctl_html_public_but_api_stays_gated(client):
    """The split this whole test module is checking: the page loads for anyone,
    but the data behind it does not. If this ever regressed to the API being
    open too, that would be a real auth bypass -- not covered by this task's
    file scope (routes.py), but worth a canary here since the page is exactly
    what makes that boundary meaningful to a user."""
    page = client.get("/nutctl.html")
    api = client.get("/api/nutctl/fleet")
    assert page.status_code == 200
    assert api.status_code == 401


def test_nutctl_html_references_nutctl_js(client):
    resp = client.get("/nutctl.html")
    assert resp.status_code == 200
    assert re.search(r'<script\s+src="/nutctl\.js"', resp.text), (
        "nutctl.html must load nutctl.js for the page to do anything"
    )


def test_nutctl_js_served(client):
    resp = client.get("/nutctl.js")
    assert resp.status_code == 200
    assert "function boot" in resp.text  # sanity: this is really the app script


# --- public-repo hygiene: no real homelab identifiers in the shipped JS ------

@pytest.mark.parametrize("needle", _FORBIDDEN_SUBSTRINGS)
def test_nutctl_js_has_no_hardcoded_homelab_identifiers(client, needle):
    resp = client.get("/nutctl.js")
    assert resp.status_code == 200
    assert needle.lower() not in resp.text.lower(), (
        f"nutctl.js must not hardcode real homelab identifiers ('{needle}' found) -- "
        "this is a public repo, everything host-specific comes from the API at runtime"
    )


def test_nutctl_js_has_no_hardcoded_ip_literal(client):
    """Broader net than the '192.168.' substring check above: no dotted-quad IPv4
    literal anywhere in the shipped JS at all (the page only ever talks to
    relative /api/nutctl/* paths -- every real address comes from the API)."""
    resp = client.get("/nutctl.js")
    assert resp.status_code == 200
    assert not re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", resp.text)
