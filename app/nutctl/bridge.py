"""nutctl bridge: turn a Topology into the upstream engine's host list.

This is the seam between the topology model (app.nutctl.topology, the single
editable source of truth for the fleet) and the fork's engine/config
(app.engine.Engine / app.config.HostConfig): rather than hand-maintaining the
same fleet twice (once in the topology YAML, once in the web-UI host editor),
``synthesize_hosts`` derives the upstream host list straight from the
topology so the dashboard/feed map is always in sync with what each host's
own upsmon actually does.

Display-only hosts (vendor GUI clients with no ssh/tiers, e.g. a NAS's
built-in UPS client) are included too, not filtered out: this appliance runs
in observer mode by default (see ``AppConfig.observer_mode`` and the guard in
``Engine._fire_host``), which makes every synthesized host inert as far as
actually shutting anything down goes -- so there is no reason to hide a real
part of the fleet from the dashboard just because we can't (and shouldn't)
act on it ourselves.
"""
from __future__ import annotations

from app.config import HostConfig
from app.nutctl.topology import Topology

# Inert placeholder for hosts that have no Proxmox API of their own to call (a NAS,
# a display-only vendor client) and, in observer mode, for every host regardless --
# _fire_host never reaches proxmox.shutdown_node() for a synthesized host. Non-empty
# and obviously fake so that a future non-observer code path fails loudly against it
# rather than silently against "".
PLACEHOLDER_API_URL = "https://observer.invalid:8006"


def synthesize_hosts(topo: Topology, ups_id_by_nut_name: dict[str, str]) -> list[HostConfig]:
    """Build one upstream ``HostConfig`` per topology host, display-only included.

    ``ups_id_by_nut_name`` maps a topology UPS key (as it appears in
    ``HostSpec.feeds``) to the id used by the upstream ``AppConfig.ups`` list, so the
    synthesized ``ups_ids``/``ups_policy`` line up with the fork's trigger/policy
    machinery. Order mirrors the topology file's host order (dict insertion order),
    starting at 0, so ``AppConfig.ordered_hosts()`` sorts deterministically the same
    way twice in a row.
    """
    hosts: list[HostConfig] = []
    for order, (name, spec) in enumerate(topo.hosts.items()):
        hosts.append(
            HostConfig(
                name=name,
                api_url=PLACEHOLDER_API_URL,
                token_id="",
                token_secret="",
                ups_ids=[ups_id_by_nut_name[feed] for feed in spec.feeds],
                ups_policy=spec.policy,
                this_host=False,
                order=order,
            )
        )
    return hosts
