"""Measured circuit power from Home Assistant (Emporia Vue panel monitor).

Display-only companion to the per-UPS output-watts estimate: a poller reads
whole-circuit watts (one HA sensor per physical feed circuit letter) and the
dashboard shows them on the circuit rails. Strictly fail-soft — HA being
unreachable never raises out of the poller and never influences any engine
decision; the last good value is kept and flagged stale once it ages out.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Awaitable, Callable, Optional

from pydantic import BaseModel, Field, SecretStr

log = logging.getLogger("pve-usv.circuits")

# A reading older than this many poll intervals renders as stale (UI dims it).
_STALE_INTERVALS = 4


def parse_ha_watts(payload: dict) -> Optional[float]:
    """State of an HA sensor entity -> watts, or None for unavailable/garbage."""
    try:
        return float(payload["state"])
    except (KeyError, TypeError, ValueError):
        return None


class CircuitPowerConfig(BaseModel):
    ha_url: str = ""  # e.g. http://homeassistant.iot:8123 (no trailing slash)
    # HA long-lived access token. SecretStr like every other credential, so
    # /api/config masks it; _merge_config() in main.py carries it across saves.
    ha_token: SecretStr = SecretStr("")
    # Physical circuit letter -> HA entity id, e.g.
    # {"A": "sensor.server_outlet_power_minute_average"}
    entities: dict[str, str] = Field(default_factory=dict)
    poll_interval_s: int = 30

    @property
    def enabled(self) -> bool:
        return bool(self.ha_url and self.ha_token.get_secret_value() and self.entities)


class CircuitPowerPoller:
    """Polls HA for each configured circuit sensor; keeps last good watts.

    `fetch` is injectable for tests: async entity_id -> decoded /api/states
    JSON dict. The default fetcher uses httpx against cfg.ha_url.
    """

    def __init__(
        self,
        cfg: CircuitPowerConfig,
        fetch: Optional[Callable[[str], Awaitable[dict]]] = None,
    ):
        self.cfg = cfg
        self._fetch = fetch or self._http_fetch
        self._watts: dict[str, Optional[float]] = {}
        self._ok_at: dict[str, Optional[datetime]] = {}
        self._last_poll_at: Optional[datetime] = None

    async def _http_fetch(self, entity: str) -> dict:
        import httpx

        url = f"{self.cfg.ha_url.rstrip('/')}/api/states/{entity}"
        headers = {"Authorization": f"Bearer {self.cfg.ha_token.get_secret_value()}"}
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(url, headers=headers)
            r.raise_for_status()
            return r.json()

    async def maybe_poll(self, now: datetime) -> None:
        """poll() at most once per poll_interval_s; safe to call every loop."""
        if (
            self._last_poll_at is not None
            and (now - self._last_poll_at).total_seconds() < self.cfg.poll_interval_s
        ):
            return
        await self.poll(now)

    async def poll(self, now: datetime) -> None:
        self._last_poll_at = now
        for circuit, entity in self.cfg.entities.items():
            try:
                watts = parse_ha_watts(await self._fetch(entity))
            except Exception as exc:  # noqa: BLE001 - fail-soft by contract
                log.debug("circuit %s (%s): HA fetch failed: %s", circuit, entity, exc)
                continue  # keep last good value; staleness handles display
            if watts is not None:
                self._watts[circuit] = watts
                self._ok_at[circuit] = now

    def snapshot(self, now: datetime) -> dict:
        """Per-circuit {watts, stale} for the dashboard; {} when disabled."""
        if not self.cfg.enabled:
            return {}
        stale_after = _STALE_INTERVALS * self.cfg.poll_interval_s
        out: dict[str, dict] = {}
        for circuit in self.cfg.entities:
            ok_at = self._ok_at.get(circuit)
            age = (now - ok_at).total_seconds() if ok_at else None
            out[circuit] = {
                "watts": self._watts.get(circuit),
                "stale": age is None or age > stale_after,
            }
        return out
