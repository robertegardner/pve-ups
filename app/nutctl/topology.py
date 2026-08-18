"""nutctl topology: the single editable model everything else renders from.

A topology file describes a NUT fleet end to end: the UPS units (as NUT knows
them), the hosts that feed off them, and the shutdown tiers each host runs as
its UPS(es) go onbatt/lowbatt. ``load_topology`` parses + validates a YAML
file into a :class:`Topology` and raises :class:`TopologyError` on any schema
or invariant failure -- callers should never have to separately check
``validate_invariants()`` after a successful load.
"""
from __future__ import annotations

from pathlib import Path
from typing import Literal, Optional

import yaml
from pydantic import BaseModel, Field, ValidationError


class TopologyError(Exception):
    """Raised when a topology file fails schema validation or an invariant check."""


class SshSpec(BaseModel):
    host: str
    user: str = "root"
    sudo: bool = False


class DriverSpec(BaseModel):
    port: str = "auto"
    vendorid: Optional[str] = None
    serial: Optional[str] = None
    flags: list[str] = Field(default_factory=list)


class UpsSpec(BaseModel):
    runtime_low_s: Optional[int] = None
    nominal_w: Optional[int] = None
    driver: DriverSpec = Field(default_factory=DriverSpec)


class TierSpec(BaseModel):
    tier: Literal["T0", "T1", "T2"]
    trigger: Literal["onbatt", "lowbatt"]
    after_s: Optional[int] = None  # required when trigger == onbatt
    action: Literal["qm-shutdown", "node-shutdown", "shutdown"]
    vmid: Optional[int] = None  # required when action == qm-shutdown
    timeout_s: int = 120


class HostSpec(BaseModel):
    type: Literal["pve-node", "nas-nut-client", "display-only"]
    feeds: list[str]
    policy: Literal["all", "any"] = "all"
    votes: int = 0
    ssh: Optional[SshSpec] = None  # required unless display-only
    tiers: list[TierSpec] = Field(default_factory=list)
    on_online: list[str] = Field(default_factory=list)
    note: str = ""


class QuorumSpec(BaseModel):
    total_votes: int
    qdevice_votes: int = 0


class NutServer(BaseModel):
    host: str
    ssh: SshSpec


class Topology(BaseModel):
    nut_server: NutServer
    quorum: QuorumSpec
    ups: dict[str, UpsSpec]
    hosts: dict[str, HostSpec]

    def validate_invariants(self) -> list[str]:
        """Cross-field checks the pydantic schema alone can't express.

        Returns a list of human-readable error strings; empty means clean.
        """
        errs: list[str] = []
        for name, h in self.hosts.items():
            for f in h.feeds:
                if f not in self.ups:
                    errs.append(f"host {name}: unknown feed '{f}'")
            if h.type == "display-only":
                continue
            if h.ssh is None:
                errs.append(f"host {name}: ssh spec required")
            term = [t for t in h.tiers if t.action in ("node-shutdown", "shutdown")]
            if not term:
                errs.append(f"host {name}: tiers must terminate in a shutdown action")
            for t in h.tiers:
                if t.trigger == "onbatt" and t.after_s is None:
                    errs.append(f"host {name}: onbatt tier needs after_s")
                if t.action == "qm-shutdown" and t.vmid is None:
                    errs.append(f"host {name}: qm-shutdown tier needs vmid")
        # Quorum: a pve-node whose terminating shutdown tier fires on "onbatt"
        # (T0/T1) is shed early in an outage; only nodes that hold out to
        # "lowbatt" (T2) are still around to vote once the shedding is done.
        # If those survivors (plus any qdevice) can't hold a majority of the
        # cluster's total votes, a long outage silently fences the cluster.
        surviving = sum(
            h.votes
            for h in self.hosts.values()
            if h.type == "pve-node"
            and any(t.trigger == "lowbatt" and t.action == "node-shutdown" for t in h.tiers)
        ) + self.quorum.qdevice_votes
        needed = self.quorum.total_votes // 2 + 1
        if surviving < needed:
            errs.append(
                f"quorum: only {surviving} of {self.quorum.total_votes} votes survive past T1 "
                f"(need >= {needed})"
            )
        return errs


def load_topology(path: Path) -> Topology:
    """Parse + validate a topology YAML file, raising TopologyError on any failure."""
    try:
        topo = Topology.model_validate(yaml.safe_load(path.read_text()))
    except (ValidationError, yaml.YAMLError) as exc:
        raise TopologyError(str(exc)) from exc
    errs = topo.validate_invariants()
    if errs:
        raise TopologyError("; ".join(errs))
    return topo
