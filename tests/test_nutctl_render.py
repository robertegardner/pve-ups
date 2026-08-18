"""Tests for nutctl.render: byte-exact client config rendering."""
from pathlib import Path

import pytest

from app.nutctl.topology import load_topology
from app.nutctl.render import render_host, render_server

FIX = Path(__file__).parent / "fixtures" / "nutctl"
TOPO = load_topology(FIX / "example-topology.yaml")
SECRETS = {"nutnode_pass": "s3cret"}
SECRETS_SRV = {"nutnode_pass": "s3cret", "monuser_pass": "m4ster", "synology_pass": "syn0"}


def test_node1_full_render_matches_fixtures():
    files = render_host(TOPO, "node1", SECRETS)
    for path, content in files.items():
        fname = "sudoers" if "sudoers" in path else Path(path).name
        assert content == (FIX / "rendered" / "node1" / fname).read_text(), path


def test_monitor_lines_and_minsupplies():
    files = render_host(TOPO, "node2", SECRETS)
    mon = files["/etc/nut/upsmon.conf"]
    assert "MONITOR alpha@192.0.2.10 1 nutnode s3cret slave" in mon
    assert "MONITOR beta@192.0.2.10 1 nutnode s3cret slave" in mon
    assert "MINSUPPLIES 1" in mon


def test_redacted_render_has_no_secret():
    files = render_host(TOPO, "node1", None)
    assert "s3cret" not in files["/etc/nut/upsmon.conf"]
    assert "@SECRET:nutnode_pass@" in files["/etc/nut/upsmon.conf"]


def test_t2_only_host_has_no_timers():
    files = render_host(TOPO, "node3", SECRETS)
    assert "START-TIMER" not in files["/etc/nut/upssched.conf"]


def test_display_only_rejected():
    with pytest.raises(KeyError):
        render_host(TOPO, "nas2", SECRETS)


def test_server_ups_conf_stanzas():
    files = render_server(TOPO, SECRETS_SRV)
    conf = files["/etc/nut/ups.conf"]
    assert "[alpha]" in conf and "[beta]" in conf
    assert 'driver = usbhid-ups' in conf
    assert 'serial = "AAA1"' in conf
    assert "onlinedischarge" in conf
    assert "override.battery.runtime.low = 420" in conf   # alpha
    assert "override.battery.runtime.low = 600" in conf   # beta


def test_server_no_override_when_null():
    topo2 = TOPO.model_copy(deep=True)
    topo2.ups["alpha"].runtime_low_s = None
    conf = render_server(topo2, SECRETS_SRV)["/etc/nut/ups.conf"]
    assert conf.count("override.battery.runtime.low") == 1


def test_upsd_users_redaction():
    files = render_server(TOPO, None)
    users = files["/etc/nut/upsd.users"]
    assert "@SECRET:nutnode_pass@" in users and "upsmon slave" in users
