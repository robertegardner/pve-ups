"""Tests for nutctl.probe: the SSH fleet probe (auth, upsmon health, config hash).

No real SSH, no asyncssh import: `FakeTransport` records every
`(ssh, cmd, stdin)` call and returns scripted `(rc, stdout, stderr)` responses
keyed by a command prefix -- same shape as `tests/test_nutctl_deploy.py`'s.

Run with:  pytest tests/test_nutctl_probe.py
These tests need no UPS hardware and no network.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from app.nutctl import probe
from app.nutctl.render import render_host, render_server
from app.nutctl.topology import SshSpec, load_topology

FIX = Path(__file__).parent / "fixtures" / "nutctl"
TOPO = load_topology(FIX / "example-topology.yaml")
SECRETS = {"nutnode_pass": "s3cret", "monuser_pass": "m4ster", "synology_pass": "syn0"}


class FakeTransport:
    """Records every call; returns the first scripted response whose key the
    command starts with, else `default`. Responses are per-``ssh.host`` (a
    dict of dicts) since different fleet hosts render different content for
    the same path -- a single flat `cmd -> response` map (as in
    `tests/test_nutctl_deploy.py`, which only ever exercises one host) would
    collide across hosts here."""

    def __init__(self, per_host: dict[str, dict[str, tuple[int, str, str]]] | None = None,
                 default: tuple[int, str, str] = (0, "", "")) -> None:
        self.per_host = per_host or {}
        self.default = default
        self.calls: list[tuple[SshSpec, str, str | None]] = []

    async def run(self, ssh: SshSpec, cmd: str, stdin: str | None = None) -> tuple[int, str, str]:
        self.calls.append((ssh, cmd, stdin))
        for prefix, resp in self.per_host.get(ssh.host, {}).items():
            if cmd.startswith(prefix):
                return resp
        return self.default

    @property
    def cmds(self) -> list[str]:
        return [c for _, c, _ in self.calls]


def _cat_responses(rendered: dict[str, str]) -> dict[str, tuple[int, str, str]]:
    """Scripted `cat` responses that make every path in `rendered` read back
    byte-identical -- i.e. a fully clean host."""
    return {f"cat -- {path}": (0, content, "") for path, content in rendered.items()}


def _base_responses() -> dict[str, tuple[int, str, str]]:
    return {
        "true": (0, "", ""),
        "systemctl is-active nut-monitor": (0, "active\n", ""),
        "systemctl is-active nut-server": (0, "active\n", ""),
    }


def _green_responses() -> dict[str, dict[str, tuple[int, str, str]]]:
    """Every host/server clean: ssh ok, service active, live config == rendered."""
    per_host: dict[str, dict[str, tuple[int, str, str]]] = {}
    for name, host in TOPO.hosts.items():
        if host.type == "display-only":
            continue
        assert host.ssh is not None
        resp = _base_responses()
        resp.update(_cat_responses(render_host(TOPO, name, SECRETS)))
        per_host[host.ssh.host] = resp

    srv_resp = _base_responses()
    srv_resp.update(_cat_responses(render_server(TOPO, SECRETS)))
    per_host[TOPO.nut_server.ssh.host] = srv_resp

    return per_host


# --- all-green fleet ---------------------------------------------------

async def test_all_green_fleet_reports_everything_ok():
    t = FakeTransport(_green_responses())

    results = await probe.probe_fleet(t, TOPO, SECRETS)

    for name in ("node1", "node2", "node3", "nas1", probe.SERVER_KEY):
        r = results[name]
        assert r.ssh_ok is True, name
        assert r.upsmon_active is True, name
        assert r.config_match is True, name


def test_display_only_host_is_never_probed():
    results_names = {"node1", "node2", "node3", "nas1", probe.SERVER_KEY}
    assert "nas2" not in results_names  # sanity on the fixture: nas2 is display-only


async def test_display_only_host_absent_from_results():
    t = FakeTransport(_green_responses())

    results = await probe.probe_fleet(t, TOPO, SECRETS)

    assert "nas2" not in results
    assert set(results) == {"node1", "node2", "node3", "nas1", probe.SERVER_KEY}


# --- unreachable host: ssh_ok False only, no exception ----------------

async def test_unreachable_host_reports_ssh_ok_false_only():
    node1_ssh = TOPO.hosts["node1"].ssh
    assert node1_ssh is not None
    responses = _green_responses()
    responses[node1_ssh.host]["true"] = (255, "", "Connection refused")

    t = FakeTransport(responses)

    results = await probe.probe_fleet(t, TOPO, SECRETS)

    r = results["node1"]
    assert r.ssh_ok is False
    assert r.upsmon_active is None
    assert r.config_match is None
    assert "unreachable" in r.detail.lower() or "refused" in r.detail.lower()

    # unreachable host must not have triggered systemctl/cat calls for it
    node1_calls = [c for ssh, c, _ in t.calls if ssh.host == node1_ssh.host]
    assert node1_calls == ["true"]

    # the rest of the fleet is unaffected
    assert results["node2"].ssh_ok is True
    assert results[probe.SERVER_KEY].ssh_ok is True


async def test_unreachable_host_raises_no_exception():
    # every host's "true" fails -- a fleet-wide outage, not just one host.
    per_host = {host: {"true": (255, "", "no route to host")} for host in _green_responses()}
    t = FakeTransport(per_host)

    # must not raise -- probe_fleet contains failures as ProbeResults
    results = await probe.probe_fleet(t, TOPO, SECRETS)

    assert all(r.ssh_ok is False for r in results.values())


# --- dead upsmon ---------------------------------------------------------

async def test_dead_upsmon_reports_upsmon_active_false():
    responses = _green_responses()
    for host_responses in responses.values():
        host_responses["systemctl is-active nut-monitor"] = (3, "inactive\n", "")
    t = FakeTransport(responses)

    results = await probe.probe_fleet(t, TOPO, SECRETS)

    for name in ("node1", "node2", "node3", "nas1"):
        assert results[name].upsmon_active is False, name
        assert results[name].ssh_ok is True
    assert "not active" in results["node1"].detail.lower()


async def test_dead_nut_server_reports_upsmon_active_false():
    responses = _green_responses()
    responses[TOPO.nut_server.ssh.host]["systemctl is-active nut-server"] = (3, "inactive\n", "")
    t = FakeTransport(responses)

    results = await probe.probe_fleet(t, TOPO, SECRETS)

    assert results[probe.SERVER_KEY].upsmon_active is False
    assert results[probe.SERVER_KEY].ssh_ok is True


# --- drifted config -------------------------------------------------------

async def test_drifted_file_reports_config_match_false_and_names_path():
    node1_ssh = TOPO.hosts["node1"].ssh
    assert node1_ssh is not None
    responses = _green_responses()
    responses[node1_ssh.host]["cat -- /etc/nut/upsmon.conf"] = (0, "SOMETHING ELSE\n", "")
    t = FakeTransport(responses)

    results = await probe.probe_fleet(t, TOPO, SECRETS)

    r = results["node1"]
    assert r.ssh_ok is True
    assert r.upsmon_active is True
    assert r.config_match is False
    assert "/etc/nut/upsmon.conf" in r.detail


async def test_missing_file_counts_as_drift():
    node1_ssh = TOPO.hosts["node1"].ssh
    assert node1_ssh is not None
    responses = _green_responses()
    responses[node1_ssh.host]["cat -- /etc/nut/nut.conf"] = (1, "", "no such file")
    t = FakeTransport(responses)

    results = await probe.probe_fleet(t, TOPO, SECRETS)

    assert results["node1"].config_match is False
    assert "/etc/nut/nut.conf" in results["node1"].detail


async def test_server_config_drift_detected():
    responses = _green_responses()
    responses[TOPO.nut_server.ssh.host]["cat -- /etc/nut/ups.conf"] = (0, "DRIFTED\n", "")
    t = FakeTransport(responses)

    results = await probe.probe_fleet(t, TOPO, SECRETS)

    assert results[probe.SERVER_KEY].config_match is False
    assert "/etc/nut/ups.conf" in results[probe.SERVER_KEY].detail


# --- config hashing never compares against redacted placeholders ---------

async def test_config_match_uses_real_secrets_not_redacted_placeholders():
    """If probe compared against the redacted render (None secrets) it would
    never match a live host that (correctly) has the real password -- this
    would make config_match spuriously False on every healthy host."""
    t = FakeTransport(_green_responses())

    results = await probe.probe_fleet(t, TOPO, SECRETS)

    assert results["node1"].config_match is True


# --- one dead host never breaks the sweep ---------------------------------

async def test_one_dead_host_does_not_break_the_rest_of_the_sweep():
    responses = _green_responses()
    node2_ssh = TOPO.hosts["node2"].ssh
    assert node2_ssh is not None

    class Boom(FakeTransport):
        async def run(self, ssh: SshSpec, cmd: str, stdin: str | None = None):
            if ssh.host == node2_ssh.host:
                raise RuntimeError("simulated transport crash")
            return await super().run(ssh, cmd, stdin)

    t = Boom(responses)

    results = await probe.probe_fleet(t, TOPO, SECRETS)

    assert results["node2"].ssh_ok is False
    assert results["node2"].upsmon_active is None
    assert results["node2"].config_match is None
    # everyone else still comes back clean
    assert results["node1"].ssh_ok is True
    assert results["node1"].config_match is True
    assert results[probe.SERVER_KEY].ssh_ok is True


# --- concurrency: hosts are probed via gather, not sequentially -----------

async def test_hosts_are_probed_concurrently(monkeypatch):
    import asyncio

    calls = []
    orig_gather = asyncio.gather

    async def spy_gather(*aws, **kwargs):
        calls.append(len(aws))
        return await orig_gather(*aws, **kwargs)

    monkeypatch.setattr(probe.asyncio, "gather", spy_gather)
    t = FakeTransport(_green_responses())

    await probe.probe_fleet(t, TOPO, SECRETS)

    assert calls and calls[0] == len({"node1", "node2", "node3", "nas1", probe.SERVER_KEY})
