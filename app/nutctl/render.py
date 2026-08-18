"""nutctl render: pure functions turning a Topology + host name into the exact
NUT client config files `install-client.sh` used to hand-roll per node.

Byte-for-byte parity with the legacy shell script is the whole point here --
these files get pushed verbatim to `/etc/nut/*` and `/etc/sudoers.d/*` on real
hosts, so whitespace and line order are load-bearing, not cosmetic.
"""
from __future__ import annotations

from app.nutctl.topology import HostSpec, Topology, UpsSpec

#: Timer name for an "onbatt" tier, keyed by its shutdown action. Anything
#: other than qm-shutdown (node-shutdown, shutdown) sheds the whole host, so
#: it shares the node-shed timer.
_TIMER_NAME = {"qm-shutdown": "gpu-shed"}
_DEFAULT_TIMER_NAME = "node-shed"

_SUDOERS_LINE = (
    "nut ALL=(root) NOPASSWD: /usr/sbin/qm shutdown [0-9]* --timeout 120, "
    "/usr/sbin/qm start [0-9]*, /sbin/shutdown -h now\n"
)

#: Verbatim contents of nut/client/upssched-cmd.sh (public: no secrets/IPs).
UPSSCHED_CMD_SH = '''#!/bin/bash
# NUT upssched CMDSCRIPT — tier-0 (GPU VM shed) / tier-1 (node shed) / power-back.
# Runs as user 'nut'; privileged actions go through the sudoers drop-in
# (/etc/sudoers.d/nut-upssched, written by install-client.sh).
# Test-hook envs (FLAG_FILE/ENV_FILE) default to the real paths in production.
ENV_FILE="${ENV_FILE:-/etc/nut/upssched.env}"
FLAG_FILE="${FLAG_FILE:-/var/lib/nut/gpu-shed.flag}"
TIER0_VMID=""
[ -r "$ENV_FILE" ] && . "$ENV_FILE"
case "$1" in
  gpu-shed)
    if [ -n "$TIER0_VMID" ]; then
      logger -t upssched "T0: on battery 90s — stopping GPU VM $TIER0_VMID"
      sudo /usr/sbin/qm shutdown "$TIER0_VMID" --timeout 120 && touch "$FLAG_FILE"
    fi ;;
  node-shed)
    logger -t upssched "T1: on battery 240s — shutting down node"
    sudo /sbin/shutdown -h now ;;
  power-back)
    if [ -n "$TIER0_VMID" ] && [ -f "$FLAG_FILE" ]; then
      logger -t upssched "power restored — restarting GPU VM $TIER0_VMID"
      sudo /usr/sbin/qm start "$TIER0_VMID" && rm -f "$FLAG_FILE"
    fi ;;
  *) logger -t upssched "unknown event: $*" ;;
esac
'''


def _resolve_secret(secrets: dict[str, str] | None) -> str:
    return secrets["nutnode_pass"] if secrets else "@SECRET:nutnode_pass@"


def _resolve(secrets: dict[str, str] | None, key: str) -> str:
    return secrets[key] if secrets else f"@SECRET:{key}@"


def _render_upsmon_conf(host: HostSpec, nut_host: str, sec: str) -> str:
    mon_lines = "".join(
        f"MONITOR {feed}@{nut_host} 1 nutnode {sec} slave\n" for feed in host.feeds
    )
    return (
        mon_lines
        + "MINSUPPLIES 1\n"
        + 'SHUTDOWNCMD "/sbin/shutdown -h +0"\n'
        + "NOTIFYCMD /usr/sbin/upssched\n"
        + "POLLFREQ 5\n"
        + "POLLFREQALERT 5\n"
        + "HOSTSYNC 15\n"
        + "NOTIFYFLAG ONBATT SYSLOG+EXEC\n"
        + "NOTIFYFLAG ONLINE SYSLOG+EXEC\n"
        + "NOTIFYFLAG LOWBATT SYSLOG\n"
        + "NOTIFYFLAG FSD SYSLOG\n"
        + "NOTIFYFLAG SHUTDOWN SYSLOG\n"
        + "NOTIFYFLAG COMMBAD SYSLOG\n"
        + "NOTIFYFLAG COMMOK SYSLOG\n"
        + "NOTIFYFLAG NOCOMM SYSLOG\n"
    )


def _render_upssched_conf(host: HostSpec) -> str:
    sched_at = ""
    for tier in host.tiers:
        if tier.trigger != "onbatt":
            continue
        name = _TIMER_NAME.get(tier.action, _DEFAULT_TIMER_NAME)
        sched_at += f"AT ONBATT * START-TIMER {name} {tier.after_s}\n"
        sched_at += f"AT ONLINE * CANCEL-TIMER {name}\n"
    if "qm-start-if-we-stopped" in host.on_online:
        sched_at += "AT ONLINE * EXECUTE power-back\n"
    return (
        "CMDSCRIPT /etc/nut/upssched-cmd.sh\n"
        "PIPEFN /run/nut/upssched.pipe\n"
        "LOCKFN /run/nut/upssched.lock\n"
        + sched_at
    )


def _render_upssched_env(host: HostSpec) -> str:
    vmid = ""
    for tier in host.tiers:
        if tier.action == "qm-shutdown" and tier.vmid is not None:
            vmid = str(tier.vmid)
            break
    return f'TIER0_VMID="{vmid}"\n'


def _render_ups_stanza(name: str, ups: UpsSpec) -> str:
    """Render one `ups.conf` stanza, matching the live Debian/NUT convention
    (see nut/topology/fixtures/wol/ups.conf in homelab-monitor): the header
    is bare, every body line is indented 8 spaces, and `driver`/`port`/
    `vendorid`/`desc`/`productid`/`serial` are all double-quoted. Field order
    is driver -> port -> vendorid -> desc -> productid -> serial -> flags ->
    override.battery.runtime.low; desc/productid are omitted when unset.
    """
    d = ups.driver
    body = ['driver = "usbhid-ups"', f'port = "{d.port}"']
    if d.vendorid is not None:
        body.append(f'vendorid = "{d.vendorid}"')
    if d.desc is not None:
        body.append(f'desc = "{d.desc}"')
    if d.productid is not None:
        body.append(f'productid = "{d.productid}"')
    if d.serial is not None:
        body.append(f'serial = "{d.serial}"')
    body.extend(d.flags)
    if ups.runtime_low_s is not None:
        body.append(f"override.battery.runtime.low = {ups.runtime_low_s}")
    lines = [f"[{name}]"] + [f"        {line}" for line in body]
    return "\n".join(lines) + "\n"


def _render_ups_conf(topo: Topology) -> str:
    return "\n".join(
        _render_ups_stanza(name, topo.ups[name]) for name in sorted(topo.ups)
    )


def _render_upsd_users(secrets: dict[str, str] | None) -> str:
    return (
        "[monuser]\n"
        f"  password = {_resolve(secrets, 'monuser_pass')}\n"
        "  upsmon master\n"
        "\n"
        "[nutnode]\n"
        f"  password = {_resolve(secrets, 'nutnode_pass')}\n"
        "  upsmon slave\n"
    )


def render_server(topo: Topology, secrets: dict[str, str] | None) -> dict[str, str]:
    """Render wol's server-side NUT files: `ups.conf` driver stanzas + `upsd.users`.

    UPS stanzas are emitted sorted by NUT name for deterministic output.
    `upsd.users` carries exactly two 2-space-indented accounts, matching the
    live capture: `monuser` (upsmon master, the wol host itself) and
    `nutnode` (upsmon slave, shared by every NUT client host). There is no
    separate Synology account -- discstation's DSM NUT client authenticates
    as `monuser` directly (see nut/nas/README.md); the design spec's
    `synology-monuser` account never existed on the live fleet.
    """
    return {
        "/etc/nut/ups.conf": _render_ups_conf(topo),
        "/etc/nut/upsd.users": _render_upsd_users(secrets),
    }


#: Fixed footer nut-dw (the Unraid NAS plugin terramaster runs) appends to
#: every GUI-managed file it owns: the plugin regenerates specific line
#: numbers and leaves the rest as placeholder blanks, always closing with
#: this comment naming which lines it overwrites. Verbatim from the live
#: capture (nut/topology/fixtures/terramaster/{upsmon.conf,nut.conf} in
#: homelab-monitor) -- not something nutctl invents, just reproduces.
_NAS_RESERVED_FOOTER = (
    "# If not in manual mode, the following lines are reserved and overwritten by GUI:\n"
)


def _render_nas_upsmon_conf(host: HostSpec, nut_host: str, sec: str) -> str:
    mon_lines = "".join(
        f"MONITOR {feed}@{nut_host} 1 monuser {sec} slave\n" for feed in host.feeds
    )
    return (
        mon_lines
        + 'SHUTDOWNCMD "/sbin/poweroff"\n'
        + 'POWERDOWNFLAG "/etc/nut/no_killpower"\n'
        + 'NOTIFYCMD "/usr/sbin/nut-notify"\n'
        + "NOTIFYFLAG ONBATT SYSLOG+EXEC\n"
        + "NOTIFYFLAG ONLINE SYSLOG+EXEC\n"
        + "NOTIFYFLAG REPLBATT SYSLOG+EXEC\n"
        + "\n" * 11
        + _NAS_RESERVED_FOOTER
        + "# L1:MONITOR/L3:POWERDOWNFLAG/L8:DEBUG_MIN\n"
    )


def _render_nas_nut_conf() -> str:
    return (
        "MODE = slave\n"
        + "\n" * 17
        + _NAS_RESERVED_FOOTER
        + "# L1:MODE\n"
    )


def render_host(topo: Topology, name: str, secrets: dict[str, str] | None) -> dict[str, str]:
    """Render the full set of `/etc/nut/*` + sudoers files for one host.

    Raises KeyError for hosts that don't get a NUT client at all
    (``type: display-only``), matching dict-style "no such renderable key"
    semantics rather than inventing a bespoke exception.

    ``type: nas-nut-client`` hosts (e.g. terramaster's Unraid nut-dw plugin)
    are GUI-managed appliances, not scriptable Debian `nut-client` installs
    -- they get a completely different two-file render (`nut.conf` +
    `upsmon.conf` only, no upssched/sudoers, monitoring account `monuser`
    not `nutnode`) matching the live plugin's own generated layout exactly.
    See task-10-report.md gap #4 (homelab-monitor) for the byte evidence.
    """
    host = topo.hosts[name]
    if host.type == "display-only":
        raise KeyError(name)

    nut_host = topo.nut_server.host

    if host.type == "nas-nut-client":
        sec = _resolve(secrets, "monuser_pass")
        return {
            "/etc/nut/upsmon.conf": _render_nas_upsmon_conf(host, nut_host, sec),
            "/etc/nut/nut.conf": _render_nas_nut_conf(),
        }

    sec = _resolve_secret(secrets)

    return {
        "/etc/nut/upsmon.conf": _render_upsmon_conf(host, nut_host, sec),
        "/etc/nut/upssched.conf": _render_upssched_conf(host),
        "/etc/nut/upssched-cmd.sh": UPSSCHED_CMD_SH,
        "/etc/nut/upssched.env": _render_upssched_env(host),
        "/etc/nut/nut.conf": "MODE=netclient\n",
        "/etc/sudoers.d/nut-upssched": _SUDOERS_LINE,
    }
