"""Unit tests for the ntfy notification target in app/notify.py.

Upstream's webhook notifier is unit-tested in test_basic.py (config round-trip only,
no network mocking); this file adds the ntfy path plus an httpx.MockTransport-based
harness so the actual outbound request (URL, headers, body) is asserted directly
instead of just "did it raise".

Run with:  pytest tests/test_nutctl_notify.py
These tests need no UPS hardware and no network.
"""

from __future__ import annotations

import httpx
import pytest

from app import notify
from app.config import Notifications


class _Recorder:
    """Captures every request an app.notify.notify() call sends, via a MockTransport."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(200)


@pytest.fixture
def recorder(monkeypatch):
    rec = _Recorder()
    transport = httpx.MockTransport(rec.handler)
    real_async_client = httpx.AsyncClient

    class _MockingAsyncClient(real_async_client):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    # notify.py does `import httpx` then `httpx.AsyncClient(...)`; patching the
    # AsyncClient attribute on the (shared) httpx module intercepts that call without
    # touching notify.py itself. monkeypatch reverts this after the test.
    monkeypatch.setattr(httpx, "AsyncClient", _MockingAsyncClient)
    return rec


def _cfg(**kwargs) -> Notifications:
    return Notifications(**kwargs)


@pytest.mark.asyncio
async def test_ntfy_posts_to_url_slash_topic_join(recorder):
    cfg = _cfg(ntfy_url="https://ntfy.example.test/", ntfy_topic="pve-ups")

    await notify.notify(cfg, "subject", "body", {})

    assert len(recorder.requests) == 1
    assert str(recorder.requests[0].url) == "https://ntfy.example.test/pve-ups"


@pytest.mark.asyncio
async def test_ntfy_posts_body_as_the_payload(recorder):
    cfg = _cfg(ntfy_url="https://ntfy.example.test", ntfy_topic="pve-ups")

    await notify.notify(cfg, "subject", "the message body", {})

    assert recorder.requests[0].content == b"the message body"


@pytest.mark.asyncio
async def test_ntfy_sets_explicit_user_agent(recorder):
    cfg = _cfg(ntfy_url="https://ntfy.example.test", ntfy_topic="pve-ups")

    await notify.notify(cfg, "subject", "body", {})

    assert recorder.requests[0].headers["user-agent"] == "pve-usv-nutctl/1.0"


@pytest.mark.asyncio
async def test_ntfy_no_authorization_header_when_token_empty(recorder):
    cfg = _cfg(ntfy_url="https://ntfy.example.test", ntfy_topic="pve-ups", ntfy_token="")

    await notify.notify(cfg, "subject", "body", {})

    assert "authorization" not in recorder.requests[0].headers


@pytest.mark.asyncio
async def test_ntfy_authorization_header_present_when_token_set(recorder):
    cfg = _cfg(
        ntfy_url="https://ntfy.example.test",
        ntfy_topic="pve-ups",
        ntfy_token="tok-123",
    )

    await notify.notify(cfg, "subject", "body", {})

    assert recorder.requests[0].headers["authorization"] == "Bearer tok-123"


@pytest.mark.asyncio
async def test_ntfy_skipped_entirely_when_url_empty(recorder):
    cfg = _cfg(ntfy_url="", ntfy_topic="pve-ups")

    await notify.notify(cfg, "subject", "body", {})

    assert recorder.requests == []


@pytest.mark.asyncio
async def test_ntfy_skipped_entirely_when_topic_empty(recorder):
    cfg = _cfg(ntfy_url="https://ntfy.example.test", ntfy_topic="")

    await notify.notify(cfg, "subject", "body", {})

    assert recorder.requests == []


@pytest.mark.asyncio
async def test_ntfy_title_is_pure_ascii_and_emoji_does_not_raise(recorder):
    cfg = _cfg(ntfy_url="https://ntfy.example.test", ntfy_topic="pve-ups")
    subject = "Host x: shutdown FAILED \U0001f534"  # trailing red-circle emoji

    # Must not raise UnicodeEncodeError: ntfy/httpx headers are latin-1 only.
    await notify.notify(cfg, subject, "body", {})

    title = recorder.requests[0].headers["title"]
    title.encode("ascii")  # raises if any non-ASCII byte slipped through
    assert "\U0001f534" not in title
    assert "FAILED" in title


@pytest.mark.asyncio
async def test_ntfy_priority_urgent_and_crit_prefix_on_failed_keyword(recorder):
    cfg = _cfg(ntfy_url="https://ntfy.example.test", ntfy_topic="pve-ups")

    await notify.notify(cfg, "Host x: shutdown FAILED", "body", {})

    headers = recorder.requests[0].headers
    assert headers["priority"] == "urgent"
    assert headers["title"] == "[CRIT] Host x: shutdown FAILED"


@pytest.mark.asyncio
async def test_ntfy_priority_urgent_on_critical_keyword(recorder):
    cfg = _cfg(ntfy_url="https://ntfy.example.test", ntfy_topic="pve-ups")

    await notify.notify(cfg, "CRITICAL: comms lost", "body", {})

    assert recorder.requests[0].headers["priority"] == "urgent"


@pytest.mark.asyncio
async def test_ntfy_priority_urgent_on_observer_keyword(recorder):
    cfg = _cfg(ntfy_url="https://ntfy.example.test", ntfy_topic="pve-ups")

    await notify.notify(cfg, "OBSERVER mode guard tripped", "body", {})

    assert recorder.requests[0].headers["priority"] == "urgent"


@pytest.mark.asyncio
async def test_ntfy_priority_high_and_warn_prefix_on_unreachable_keyword(recorder):
    cfg = _cfg(ntfy_url="https://ntfy.example.test", ntfy_topic="pve-ups")

    await notify.notify(cfg, "Host x is unreachable", "body", {})

    headers = recorder.requests[0].headers
    assert headers["priority"] == "high"
    assert headers["title"] == "[WARN] Host x is unreachable"


@pytest.mark.asyncio
async def test_ntfy_priority_high_on_outage_keyword(recorder):
    cfg = _cfg(ntfy_url="https://ntfy.example.test", ntfy_topic="pve-ups")

    await notify.notify(cfg, "power outage detected", "body", {})

    assert recorder.requests[0].headers["priority"] == "high"


@pytest.mark.asyncio
async def test_ntfy_priority_high_on_battery_keyword(recorder):
    cfg = _cfg(ntfy_url="https://ntfy.example.test", ntfy_topic="pve-ups")

    await notify.notify(cfg, "UPS a is now on battery", "body", {})

    assert recorder.requests[0].headers["priority"] == "high"


@pytest.mark.asyncio
async def test_ntfy_priority_default_and_no_prefix_for_routine_subject(recorder):
    cfg = _cfg(ntfy_url="https://ntfy.example.test", ntfy_topic="pve-ups")

    await notify.notify(cfg, "Selftest completed", "body", {})

    headers = recorder.requests[0].headers
    assert headers["priority"] == "default"
    assert headers["title"] == "Selftest completed"


@pytest.mark.asyncio
async def test_ntfy_failure_is_logged_not_raised(monkeypatch, caplog):
    cfg = _cfg(ntfy_url="https://ntfy.example.test", ntfy_topic="pve-ups")

    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    transport = httpx.MockTransport(boom)
    real_async_client = httpx.AsyncClient

    class _FailingAsyncClient(real_async_client):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _FailingAsyncClient)

    with caplog.at_level("WARNING"):
        await notify.notify(cfg, "subject", "body", {})  # must not raise

    assert any("ntfy" in rec.message.lower() for rec in caplog.records)
