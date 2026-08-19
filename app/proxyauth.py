"""Trusted-reverse-proxy identity (authentik forward-auth).

A reverse proxy that has already authenticated the user injects
``X-Authentik-Username`` on the proxied request. That header is attacker
-controlled on any direct connection, so it is honored ONLY when the direct
TCP peer address is explicitly allowlisted in
``AppConfig.trusted_auth_upstreams`` — fail closed: the default empty list
means the header is never trusted. The proxy must be the one setting the
header (authentik's outpost overwrites any inbound value).

Lives in its own module because both app.main (session check) and
app.nutctl.routes (write guard, audit actor) need it, and main imports
routes — a shared helper avoids the import cycle.
"""
from __future__ import annotations

from typing import Optional

from fastapi import Request

AUTH_HEADER = "X-Authentik-Username"


def header_identity(request: Request, cfg) -> Optional[str]:
    """The proxy-authenticated username, or None when the header can't be trusted."""
    trusted = getattr(cfg, "trusted_auth_upstreams", None) or []
    if not trusted or request.client is None:
        return None
    if request.client.host not in trusted:
        return None
    value = request.headers.get(AUTH_HEADER)
    if value is None:
        return None
    value = value.strip()
    return value or None
