"""Optional notifications: generic webhook + ntfy.

Notifications are best-effort: a failure to notify must never affect the shutdown
logic, so every send is wrapped and only logged on error.

Copyright 2026 Florian Finder
"""

from __future__ import annotations

import logging

import httpx

from .config import Notifications

log = logging.getLogger("pve-usv.notify")

_NTFY_USER_AGENT = "pve-usv-nutctl/1.0"

# notify() keeps upstream's (cfg, subject, body, payload) signature -- there is no
# explicit severity parameter -- so ntfy priority/title-prefix are inferred from
# keywords in `subject`. FAILED/CRITICAL/OBSERVER are real-failure language used by
# call sites (e.g. "shutdown FAILED", the observer-mode guard) and rank above the
# comms-degraded language unreachable/outage/"on battery", which still outranks
# routine subjects.
_CRITICAL_KEYWORDS = ("failed", "critical", "observer")
_WARNING_KEYWORDS = ("unreachable", "outage", "on battery")


def _severity(subject: str) -> tuple[str, str]:
    """Return (title_prefix, ntfy_priority) derived from keywords in `subject`."""
    lowered = subject.lower()
    if any(keyword in lowered for keyword in _CRITICAL_KEYWORDS):
        return "[CRIT] ", "urgent"
    if any(keyword in lowered for keyword in _WARNING_KEYWORDS):
        return "[WARN] ", "high"
    return "", "default"


def _ascii_title(subject: str) -> str:
    """Severity-prefixed title, with every non-latin-1 character (e.g. emoji) stripped.

    ntfy/httpx headers are latin-1-only; a raw emoji in `subject` would otherwise
    raise UnicodeEncodeError deep inside httpx when the request is sent.
    """
    prefix, _ = _severity(subject)
    raw = prefix + subject
    return raw.encode("latin-1", errors="ignore").decode("latin-1")


async def _notify_ntfy(notifications: Notifications, subject: str, body: str) -> None:
    if not (notifications.ntfy_url and notifications.ntfy_topic):
        return
    try:
        _, priority = _severity(subject)
        headers = {
            "Title": _ascii_title(subject),
            "User-Agent": _NTFY_USER_AGENT,
            "Priority": priority,
        }
        if notifications.ntfy_token:
            headers["Authorization"] = f"Bearer {notifications.ntfy_token}"
        url = f"{notifications.ntfy_url.rstrip('/')}/{notifications.ntfy_topic}"
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(url, content=body.encode("utf-8"), headers=headers)
    except Exception as exc:  # noqa: BLE001
        log.warning("ntfy notification failed: %s", exc)


async def notify(notifications: Notifications, subject: str, body: str, payload: dict) -> None:
    """Fire the configured notification targets, swallowing all errors."""
    hook = notifications.webhook
    if hook.enabled and hook.url:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(
                    hook.url,
                    json={"subject": subject, "body": body, "status": payload},
                )
        except Exception as exc:  # noqa: BLE001
            log.warning("Webhook notification failed: %s", exc)

    await _notify_ntfy(notifications, subject, body)
