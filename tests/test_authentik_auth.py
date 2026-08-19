"""Trusted-reverse-proxy (authentik forward-auth) identity for the app itself.

A reverse proxy that has already authenticated the user (authentik
forward-auth) injects ``X-Authentik-Username``. The app honors that header as
a full session ONLY when the direct TCP peer is in
``AppConfig.trusted_auth_upstreams`` (fail closed: default empty list means
the header is always ignored). Direct access keeps the ordinary UI-password
cookie flow. The header identity also becomes the audit-log actor.

TestClient's synthetic peer address is the literal string "testclient", which
is what the trusted/untrusted fixtures key on.

Run with: pytest tests/test_authentik_auth.py
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from app import main as main_mod
from app.nutctl import routes as nutctl_routes
from app.proxyauth import AUTH_HEADER

# Reuse the route tests' full fixture stack (paths, cfg writer, transport fake).
from tests.test_nutctl_routes import (  # noqa: F401  (pytest fixtures)
    VALID_TOPO_TEXT,
    _fake_transport_factory,
    _write_cfg,
    paths,
)

HDR = {AUTH_HEADER: "rgardner"}


def _client(paths, monkeypatch, **cfg_overrides) -> TestClient:
    _write_cfg(paths, **cfg_overrides)
    monkeypatch.setattr(nutctl_routes, "AsyncsshTransport", _fake_transport_factory())
    return TestClient(main_mod.app)


def test_header_from_trusted_upstream_authenticates(paths, monkeypatch):
    with _client(paths, monkeypatch, trusted_auth_upstreams=["testclient"]) as c:
        resp = c.get("/api/nutctl/topology", headers=HDR)
        assert resp.status_code == 200


def test_header_from_untrusted_upstream_is_ignored(paths, monkeypatch):
    with _client(paths, monkeypatch, trusted_auth_upstreams=["10.9.9.9"]) as c:
        resp = c.get("/api/nutctl/topology", headers=HDR)
        assert resp.status_code == 401


def test_default_config_ignores_header_entirely(paths, monkeypatch):
    # Fail closed: empty trusted_auth_upstreams (the default) never trusts it.
    with _client(paths, monkeypatch) as c:
        resp = c.get("/api/nutctl/topology", headers=HDR)
        assert resp.status_code == 401


def test_trusted_upstream_without_header_still_needs_cookie(paths, monkeypatch):
    with _client(paths, monkeypatch, trusted_auth_upstreams=["testclient"]) as c:
        resp = c.get("/api/nutctl/topology")
        assert resp.status_code == 401


def test_empty_header_value_does_not_authenticate(paths, monkeypatch):
    with _client(paths, monkeypatch, trusted_auth_upstreams=["testclient"]) as c:
        resp = c.get("/api/nutctl/topology", headers={AUTH_HEADER: "  "})
        assert resp.status_code == 401


def test_header_auth_satisfies_write_guard_even_in_bootstrap(paths, monkeypatch):
    """A proxy-authenticated user is real auth: the I4 no-password 403 must
    not fire for them. deploy on a topology host reaches the no-UPS-telemetry
    interlock (409) -- past both auth layers -- instead of 401/403."""
    with _client(
        paths, monkeypatch, ui_password_hash="", trusted_auth_upstreams=["testclient"]
    ) as c:
        resp = c.post("/api/nutctl/deploy/node1", headers=HDR)
        assert resp.status_code == 409
        assert "telemetry" in resp.json()["detail"].lower()


def test_bootstrap_writes_still_403_without_header(paths, monkeypatch):
    with _client(
        paths, monkeypatch, ui_password_hash="", trusted_auth_upstreams=["testclient"]
    ) as c:
        resp = c.post("/api/nutctl/deploy/node1")
        assert resp.status_code == 403


def test_actor_uses_header_identity_in_audit(paths, monkeypatch):
    from app import db as db_mod

    with _client(paths, monkeypatch, trusted_auth_upstreams=["testclient"]) as c:
        resp = c.put(
            "/api/nutctl/topology", json={"yaml": VALID_TOPO_TEXT}, headers=HDR
        )
        assert resp.status_code == 200
        events = [e for e in db_mod.recent_events(50) if "topology" in e["event"]]
        assert events and "rgardner" in events[0]["detail"]
