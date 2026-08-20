"""Per-outlet PDU watts from Prometheus (unpoller's UniFi SmartPower metrics).

Display-only companion to the power-feed diagram: the nutctl topology can map
each UPS to the PDU outlets it feeds (``UpsSpec.pdu_loads``), and this poller
reads the live per-outlet watts so the dashboard's "PDU loads" toggle can show
the UniFi gear (UDM, switches, modems, ...) hanging off each UPS with real
draw numbers. One instant query fetches every outlet series at once.

Strictly fail-soft, same contract as app.circuits: Prometheus being
unreachable never raises out of the poller and never influences any engine
decision; the last good reading is kept and flagged stale once it ages out.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Awaitable, Callable, Optional

from pydantic import BaseModel

log = logging.getLogger("pve-usv.outlets")

# A reading older than this many poll intervals renders as stale (UI dims it).
_STALE_INTERVALS = 4

#: (device name, outlet index) -> (live outlet name, watts)
OutletReadings = dict[tuple[str, int], tuple[str, float]]


def parse_prom_outlets(payload: dict) -> OutletReadings:
    """Prometheus instant-query JSON -> readings; skips malformed series.

    unpoller labels each series with the PDU's ``name``, the string
    ``outlet_index`` and the UI-editable ``outlet_name`` (renames in the
    UniFi controller flow through automatically).
    """
    out: OutletReadings = {}
    if payload.get("status") != "success":
        return out
    for series in payload.get("data", {}).get("result", []):
        metric = series.get("metric", {})
        device = metric.get("name")
        if not device:
            continue
        try:
            index = int(metric["outlet_index"])
            watts = float(series["value"][1])
        except (KeyError, IndexError, TypeError, ValueError):
            continue
        out[(device, index)] = (metric.get("outlet_name") or f"Outlet {index}", watts)
    return out


class PduPowerConfig(BaseModel):
    # e.g. http://192.168.6.51:9090 (no trailing slash). LAN Prometheus with
    # unpoller scraped; no credential involved, hence no SecretStr here.
    prometheus_url: str = ""
    metric: str = "unpoller_device_outlet_outlet_power"
    poll_interval_s: int = 30

    @property
    def enabled(self) -> bool:
        return bool(self.prometheus_url)


class PduOutletPoller:
    """Polls Prometheus for all outlet watts; keeps the last good readings.

    ``fetch`` is injectable for tests: async () -> decoded /api/v1/query JSON
    dict. The default fetcher uses httpx against cfg.prometheus_url.
    """

    def __init__(
        self,
        cfg: PduPowerConfig,
        fetch: Optional[Callable[[], Awaitable[dict]]] = None,
    ):
        self.cfg = cfg
        self._fetch = fetch or self._http_fetch
        self._readings: OutletReadings = {}
        self._ok_at: Optional[datetime] = None
        self._last_poll_at: Optional[datetime] = None

    async def _http_fetch(self) -> dict:
        import httpx

        url = f"{self.cfg.prometheus_url.rstrip('/')}/api/v1/query"
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(url, params={"query": self.cfg.metric})
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
        try:
            readings = parse_prom_outlets(await self._fetch())
        except Exception as exc:  # noqa: BLE001 - fail-soft by contract
            log.debug("PDU outlet poll failed: %s", exc)
            return  # keep last good readings; staleness handles display
        if readings:
            self._readings = readings
            self._ok_at = now

    def snapshot(self, now: datetime, mapping: dict[str, list[dict]]) -> dict:
        """{ups_id: [{name, watts, stale}, ...]} for the dashboard.

        ``mapping`` comes from the nutctl topology (ups id -> list of
        {device, outlet, label} dicts, insertion order preserved). {} when the
        poller is disabled or nothing is mapped, so the UI simply hides the
        toggle.
        """
        if not self.cfg.enabled or not mapping:
            return {}
        age = (now - self._ok_at).total_seconds() if self._ok_at else None
        stale = age is None or age > _STALE_INTERVALS * self.cfg.poll_interval_s
        out: dict[str, list[dict]] = {}
        for ups_id, refs in mapping.items():
            rows = []
            for ref in refs:
                reading = self._readings.get((ref["device"], int(ref["outlet"])))
                name = ref.get("label") or (
                    reading[0] if reading else f"{ref['device']} outlet {ref['outlet']}"
                )
                rows.append(
                    {
                        "name": name,
                        "watts": reading[1] if reading else None,
                        "stale": stale or reading is None,
                    }
                )
            out[ups_id] = rows
        return out
