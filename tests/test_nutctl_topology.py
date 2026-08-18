"""Tests for nutctl.topology: the fleet-topology schema + cross-field invariants."""
import copy
from pathlib import Path

import pytest

from app.nutctl.topology import TierSpec, Topology, TopologyError, load_topology

FIX = Path(__file__).parent / "fixtures" / "nutctl"


def test_load_example():
    topo = load_topology(FIX / "example-topology.yaml")
    assert set(topo.ups) == {"alpha", "beta"}
    assert topo.hosts["node2"].policy == "all"
    assert topo.hosts["node1"].tiers[0].action == "qm-shutdown"
    assert topo.hosts["nas2"].type == "display-only"


def test_unknown_feed_rejected():
    topo = load_topology(FIX / "example-topology.yaml")
    topo.hosts["node1"].feeds = ["nonexistent"]
    assert any("nonexistent" in e for e in topo.validate_invariants())


def test_non_display_host_must_terminate_in_shutdown():
    topo = load_topology(FIX / "example-topology.yaml")
    topo.hosts["node1"].tiers = [t for t in topo.hosts["node1"].tiers if t.action != "node-shutdown"]
    assert any("terminate" in e for e in topo.validate_invariants())


def test_quorum_invariant_clean_fixture_passes():
    topo = load_topology(FIX / "example-topology.yaml")
    assert topo.validate_invariants() == []


def test_quorum_invariant_flags_violation_on_mutated_copy():
    topo = load_topology(FIX / "example-topology.yaml")
    mutated = copy.deepcopy(topo)
    # node3's T2/lowbatt terminating tier is replaced by an onbatt/T1 shutdown tier,
    # so it now sheds at T1 like node1 -- only node2 (1 vote) + qdevice (1 vote) = 2
    # survive past T1, which is below quorum (need >= 3 of 5).
    mutated.hosts["node3"].tiers = [
        TierSpec(tier="T1", trigger="onbatt", after_s=240, action="node-shutdown")
    ]
    errs = mutated.validate_invariants()
    assert any("quorum" in e.lower() for e in errs)


def test_load_rejects_invariant_violation(tmp_path):
    bad = (FIX / "example-topology.yaml").read_text().replace(
        "trigger: lowbatt, action: node-shutdown", "trigger: onbatt, after_s: 240, action: node-shutdown"
    )
    p = tmp_path / "bad.yaml"
    p.write_text(bad)
    with pytest.raises(TopologyError):
        load_topology(p)  # everything sheds at T1 -> quorum violated
