"""Tests for nutctl.render: byte-exact client config rendering."""
from pathlib import Path

import pytest

from app.nutctl.topology import load_topology
from app.nutctl.render import render_host

FIX = Path(__file__).parent / "fixtures" / "nutctl"
TOPO = load_topology(FIX / "example-topology.yaml")
SECRETS = {"nutnode_pass": "s3cret"}


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
