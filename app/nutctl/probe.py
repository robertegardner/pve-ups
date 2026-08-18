"""nutctl probe: SSH fleet probe -- reachability, upsmon health, config drift.

Repurposes upstream's credential self-test in spirit: instead of a single
"do these keys authenticate" check, this walks the whole fleet -- every
non-display host plus the NUT server itself -- and reports three independent
signals per host:

- ``ssh_ok``: a trivial ``true`` round trip succeeded.
- ``upsmon_active``: the host's service check exited 0. By default that is
  ``systemctl is-active nut-monitor`` (``nut-server`` for the NUT server); a
  host can override it with ``service_check`` in the topology, which is what
  keeps non-systemd appliances (a NAS running a vendor NUT plugin, where
  ``systemctl`` does not exist at all) from reading as permanently dead.
  ``None`` when ssh failed.
- ``config_match``: every live file this host is supposed to carry matches,
  byte for byte, the *secret-substituted* render for that host -- never the
  redacted placeholder render, which would never match a real host and would
  make every healthy host look drifted. Hashing/comparison happens server
  side; no secret material is ever shipped to (or read back from) the wire
  beyond what deploy.py already writes there. ``None`` when ssh failed.

Results are keyed by hostname as it appears in ``topo.hosts``, plus one
extra entry for the NUT server itself under the literal key ``"server"``
(:data:`SERVER_KEY`) -- never a real hostname, so it can't collide with a
topology entry. ``display-only`` hosts carry no NUT client at all and are
never probed (they simply don't appear in the result dict).

Probing is concurrent (``asyncio.gather``); a single host that's dead,
misconfigured, or whose transport raises never breaks the sweep -- one
:class:`ProbeResult` is contained per host, everything else still reports
normally.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass

from app.nutctl.deploy import Transport, fetch_live
from app.nutctl.render import render_host, render_server
from app.nutctl.topology import SshSpec, Topology

#: Sentinel key for the NUT server's own probe result. Never a real hostname
#: (topology host names come from the topology file's `hosts:` map), so this
#: can't collide with a fleet host that happens to be named "server".
SERVER_KEY = "server"

_CLIENT_SERVICE = "nut-monitor"
_SERVER_SERVICE = "nut-server"

#: Default per-role liveness commands. rc 0 == healthy. A host whose topology
#: entry sets ``service_check`` replaces the client default entirely.
_CLIENT_CHECK = f"systemctl is-active {_CLIENT_SERVICE}"
_SERVER_CHECK = f"systemctl is-active {_SERVER_SERVICE}"


@dataclass
class ProbeResult:
    ssh_ok: bool
    #: None when ssh failed (nothing to check upsmon health against).
    upsmon_active: bool | None
    #: None when ssh failed (nothing to fetch live config from).
    config_match: bool | None
    detail: str


async def _probe_one(
    t: Transport, ssh: SshSpec, rendered: dict[str, str], service_check: str
) -> ProbeResult:
    """Probe a single host/server: reachability, then (only if reachable)
    service health + config drift against `rendered`.

    `service_check` is a full shell command; only its rc is consulted (0 ==
    healthy). `systemctl is-active` already exits nonzero for every non-active
    state, and an override like `pgrep -x upsmon` has no status word to print
    at all -- so rc is the one signal that means the same thing for both.
    """
    rc, _out, err = await t.run(ssh, "true")
    if rc != 0:
        detail = f"ssh unreachable: {err.strip() or f'rc={rc}'}"
        return ProbeResult(ssh_ok=False, upsmon_active=None, config_match=None, detail=detail)

    rc, _out, _err = await t.run(ssh, service_check)
    upsmon_active = rc == 0

    live = await fetch_live(t, ssh, list(rendered.keys()))
    mismatches = sorted(path for path, content in rendered.items() if live.get(path) != content)
    config_match = not mismatches

    detail = f"`{service_check}` {'ok' if upsmon_active else f'FAILED (rc={rc})'}"
    detail += f"; config drift: {', '.join(mismatches)}" if mismatches else "; config matches"

    return ProbeResult(ssh_ok=True, upsmon_active=upsmon_active, config_match=config_match, detail=detail)


async def _probe_named(
    t: Transport, topo: Topology, secrets: dict[str, str], name: str
) -> tuple[str, ProbeResult]:
    """Wrap `_probe_one` so any unexpected exception (a transport crash,
    not a plain SSH failure -- `_probe_one` already turns that into
    `ssh_ok=False`) is contained per host rather than propagating out of
    `probe_fleet` and aborting the whole sweep.
    """
    try:
        if name == SERVER_KEY:
            rendered = render_server(topo, secrets)
            result = await _probe_one(t, topo.nut_server.ssh, rendered, _SERVER_CHECK)
        else:
            host = topo.hosts[name]
            if host.ssh is None:  # pragma: no cover - display-only never reaches here
                raise ValueError(f"host {name} has no ssh spec")
            rendered = render_host(topo, name, secrets)
            result = await _probe_one(
                t, host.ssh, rendered, host.service_check or _CLIENT_CHECK
            )
    except Exception as exc:
        result = ProbeResult(ssh_ok=False, upsmon_active=None, config_match=None,
                              detail=f"probe error: {exc}")
    return name, result


async def probe_fleet(t: Transport, topo: Topology, secrets: dict[str, str]) -> dict[str, ProbeResult]:
    """Probe every non-display host plus the NUT server, concurrently.

    Returns a dict keyed by host name (as in `topo.hosts`) plus
    :data:`SERVER_KEY` for the NUT server. `display-only` hosts are omitted
    entirely -- they run no NUT client, so there's nothing to probe.
    """
    names = [SERVER_KEY] + [
        name for name, h in topo.hosts.items() if h.type != "display-only"
    ]
    pairs = await asyncio.gather(*(_probe_named(t, topo, secrets, name) for name in names))
    return dict(pairs)
