"""nutctl deploy: the SSH deployment engine -- drift diff, push, verify, revert.

``Transport`` is the seam between the orchestration logic below (pure w.r.t. the
network -- it only ever calls ``Transport.run``) and the wire. ``AsyncsshTransport``
is the production implementation; tests drive ``deploy_host``/``revert_host``/
``fetch_live`` against a hand-rolled fake that never touches a socket.

Command construction lives entirely on this side of the seam: every command this
module builds is plain (no "sudo" anywhere in it). Privilege escalation is
``Transport.run``'s job alone, keyed off ``ssh.sudo`` -- that keeps deploy_host's
behavior against a fake transport identical to its behavior against a real host,
and means a new Transport (a different auth scheme, a dry-run recorder, ...) only
has to get sudo-wrapping right once.
"""
from __future__ import annotations

import difflib
import shlex
import time
from dataclasses import dataclass
from typing import Protocol

from app.nutctl.topology import SshSpec

#: Stashes kept per path; older ones are pruned after each successful stash.
_KEEP_STASHES = 3

#: Service nutctl expects the host's NUT client stack to be running as.
_SERVICE = "nut-monitor"


class DeployRefused(Exception):
    """Raised when a deploy is refused outright (e.g. the fleet is on battery)."""


@dataclass
class DeployResult:
    ok: bool
    verified: bool
    detail: str


class Transport(Protocol):
    async def run(
        self, ssh: SshSpec, cmd: str, stdin: str | None = None
    ) -> tuple[int, str, str]:
        """Run `cmd` on `ssh.host`, feeding `stdin` if given. Returns (rc, stdout, stderr)."""
        ...


class AsyncsshTransport:
    """Production Transport: one asyncssh connection per call, key-based auth.

    Privilege escalation happens here, not in deploy.py:

    - A plain (no-stdin) command run with ``ssh.sudo`` is wrapped
      ``sudo -n -- sh -c '<cmd>'`` (single-quote-escaped) so a host that would
      otherwise prompt for a password fails fast instead of hanging.
    - A stdin-carrying write -- deploy.py always shapes those as
      ``tee <path> >/dev/null`` -- gets a bare ``sudo -n `` prefix instead of
      the ``sh -c`` wrapping, since routing raw config bytes through an extra
      shell layer risks mangling them; ``sudo -n tee ...`` runs tee directly
      under sudo and still reads stdin normally.

    Both are exposed as pure staticmethods (``build_command``/
    ``build_write_command``) precisely so the wrapping logic is unit-testable
    without a real SSH connection.
    """

    def __init__(self, key_path: str) -> None:
        self._key_path = key_path

    @staticmethod
    def build_command(cmd: str, sudo: bool) -> str:
        """The command actually sent over the wire for a non-stdin call."""
        if not sudo:
            return cmd
        escaped = cmd.replace("'", "'\\''")
        return f"sudo -n -- sh -c '{escaped}'"

    @staticmethod
    def build_write_command(cmd: str, sudo: bool) -> str:
        """The command actually sent over the wire for a stdin-carrying write."""
        return f"sudo -n {cmd}" if sudo else cmd

    @staticmethod
    def normalize_rc(exit_status: int | None) -> int:
        """Map an asyncssh `exit_status` to our rc convention.

        asyncssh reports `exit_status=None` when the remote process was killed
        by a signal rather than exiting normally (it reports the signal name
        separately). `int(None or 0)` would misread that as rc=0 (success) --
        instead treat it as a hard failure, using 255, the shell convention for
        "process died abnormally."
        """
        if exit_status is None:
            return 255
        return int(exit_status)

    async def run(self, ssh: SshSpec, cmd: str, stdin: str | None = None) -> tuple[int, str, str]:
        import asyncssh  # local import: keeps asyncssh out of the test import graph

        remote_cmd = (
            self.build_write_command(cmd, ssh.sudo)
            if stdin is not None
            else self.build_command(cmd, ssh.sudo)
        )
        async with asyncssh.connect(
            ssh.host, username=ssh.user, client_keys=[self._key_path], known_hosts=None
        ) as conn:
            result = await conn.run(remote_cmd, input=stdin, check=False)
            return (
                self.normalize_rc(result.exit_status),
                str(result.stdout or ""),
                str(result.stderr or ""),
            )


def _q(path: str) -> str:
    return shlex.quote(path)


def _stash_ts(stash_name: str) -> int:
    suffix = stash_name.rsplit(".", 1)[-1]
    return int(suffix) if suffix.isdigit() else 0


async def fetch_live(t: Transport, ssh: SshSpec, paths: list[str]) -> dict[str, str | None]:
    """Read each of `paths` off the host. A nonzero `cat` rc reads as "absent" (None)."""
    live: dict[str, str | None] = {}
    for path in paths:
        rc, out, _err = await t.run(ssh, f"cat -- {_q(path)}")
        live[path] = out if rc == 0 else None
    return live


def diff_files(live: dict[str, str | None], rendered: dict[str, str]) -> str:
    """Pure unified diff of live vs rendered content, one block per differing path.

    A path missing on one side diffs against `/dev/null` on that side (the
    `diff -u` convention for "this file doesn't exist yet/anymore"). Paths with
    identical content produce no block. Iterates in sorted path order so the
    report is deterministic regardless of dict insertion order.
    """
    blocks: list[str] = []
    for path in sorted(set(live) | set(rendered)):
        old = live.get(path)
        new = rendered.get(path)
        old_lines = old.splitlines(keepends=True) if old is not None else []
        new_lines = new.splitlines(keepends=True) if new is not None else []
        old_name = path if old is not None else "/dev/null"
        new_name = path if new is not None else "/dev/null"
        diff = list(
            difflib.unified_diff(
                old_lines, new_lines, fromfile=old_name, tofile=new_name, lineterm=""
            )
        )
        if diff:
            blocks.append("\n".join(diff))
    return "\n".join(blocks)


def _mode_for(path: str) -> tuple[str, str | None]:
    """(chmod-arg, chown-arg-or-None) for a deployed path, per the fleet's install
    script conventions -- executable scripts run 0755, the upssched sudoers
    drop-in runs 0440, and everything else NUT keeps under `/etc/nut/` runs
    0640 root:nut. That last rule is deliberately NOT scoped to `*.conf`: it
    also has to cover `upsd.users` (server-side, holds the monuser/nutnode/
    synology-monuser passwords in plaintext) and any future non-`.conf` file
    dropped in `/etc/nut/` -- narrowing it to `.conf` would silently leave a
    secrets-bearing file world-readable at tee's default create mode.
    """
    if path.endswith(".sh"):
        return "755", None
    if path.startswith("/etc/sudoers.d/"):
        return "440", None
    if path.startswith("/etc/nut/"):
        return "640", "root:nut"
    return "", None


async def _stash_and_prune(t: Transport, ssh: SshSpec, path: str) -> tuple[bool, str]:
    """Stash `path`'s current content (if any) before it gets overwritten, then
    prune that path's stashes down to the newest `_KEEP_STASHES`.
    """
    rc, _out, _err = await t.run(ssh, f"test -f {_q(path)}")
    if rc != 0:
        return True, f"{path}: no live file, nothing to stash"

    stash_path = f"{path}.pre-nutctl.{int(time.time())}"
    rc, _out, err = await t.run(ssh, f"cp -a -- {_q(path)} {_q(stash_path)}")
    if rc != 0:
        return False, f"{path}: stash failed: {err.strip()}"

    rc, out, _err = await t.run(ssh, f"ls -1 -- {_q(path)}.pre-nutctl.*")
    stashes = [line for line in out.splitlines() if line.strip()]
    stashes.sort(key=_stash_ts, reverse=True)
    stale = stashes[_KEEP_STASHES:]
    if stale:
        await t.run(ssh, "rm -f -- " + " ".join(_q(s) for s in stale))

    return True, f"{path}: stashed to {stash_path}"


async def _write_file(t: Transport, ssh: SshSpec, path: str, content: str) -> tuple[bool, str]:
    """Write `content` to a temp path via `tee`, then atomically `mv` it into place
    and set the mode/ownership `_mode_for` calls for.
    """
    tmp_path = f"{path}.nutctl-tmp"
    rc, _out, err = await t.run(ssh, f"tee -- {_q(tmp_path)} >/dev/null", stdin=content)
    if rc != 0:
        return False, f"{path}: write failed: {err.strip()}"

    rc, _out, err = await t.run(ssh, f"mv -f -- {_q(tmp_path)} {_q(path)}")
    if rc != 0:
        return False, f"{path}: move-into-place failed: {err.strip()}"

    mode, owner = _mode_for(path)
    if mode:
        rc, _out, err = await t.run(ssh, f"chmod {mode} -- {_q(path)}")
        if rc != 0:
            return False, f"{path}: chmod {mode} failed: {err.strip()}"
    if owner:
        rc, _out, err = await t.run(ssh, f"chown {owner} -- {_q(path)}")
        if rc != 0:
            return False, f"{path}: chown {owner} failed: {err.strip()}"

    return True, f"{path}: written + placed"


async def _verify(t: Transport, ssh: SshSpec, rendered: dict[str, str]) -> tuple[bool, str]:
    rc, out, _err = await t.run(ssh, f"systemctl is-active {_SERVICE}")
    active = rc == 0 and out.strip() == "active"

    live = await fetch_live(t, ssh, list(rendered.keys()))
    mismatches = [path for path, content in rendered.items() if live.get(path) != content]

    detail = f"{_SERVICE} {'active' if active else 'NOT active'}"
    if mismatches:
        detail += f"; content mismatch: {', '.join(mismatches)}"
    return active and not mismatches, detail


async def deploy_host(
    t: Transport,
    ssh: SshSpec,
    rendered: dict[str, str],
    *,
    reload_cmds: list[str],
    on_battery: bool,
) -> DeployResult:
    """Push `rendered` files to `ssh.host`, stash-then-atomic-move each one, run
    `reload_cmds`, and verify.

    Refuses outright -- before any transport call at all -- if `on_battery`:
    riding out a power event is not the moment to be rewriting the very config
    that governs how (and whether) this host sheds load or shuts down. A write
    failure on one file aborts the remaining files for this host (no partial
    fleet of half-applied configs) and forces `ok=False`; `reload_cmds` only run
    once every file placed cleanly.
    """
    if on_battery:
        raise DeployRefused("refusing to deploy: fleet is on battery")

    details: list[str] = []
    ok = True
    written: dict[str, str] = {}
    for path, content in rendered.items():
        stash_ok, stash_detail = await _stash_and_prune(t, ssh, path)
        details.append(stash_detail)
        if not stash_ok:
            ok = False
            break

        write_ok, write_detail = await _write_file(t, ssh, path, content)
        details.append(write_detail)
        if not write_ok:
            ok = False
            break
        written[path] = content

    if ok:
        for cmd in reload_cmds:
            rc, _out, err = await t.run(ssh, cmd)
            details.append(f"reload `{cmd}`: rc={rc}")
            if rc != 0:
                ok = False
                if err.strip():
                    details.append(f"  stderr: {err.strip()}")

    # Only re-check files that actually got written -- a path that never made
    # it past _write_file was never touched, and shouldn't get an extra
    # network round trip (or a spurious "content mismatch") in the verify step.
    verified, verify_detail = await _verify(t, ssh, written)
    details.append(verify_detail)

    return DeployResult(ok=ok, verified=verified, detail="; ".join(details))


async def revert_host(t: Transport, ssh: SshSpec, paths: list[str]) -> DeployResult:
    """Restore the newest `<path>.pre-nutctl.*` stash for each of `paths`.

    A path with no stash at all fails the whole revert (`ok=False`) -- there is
    nothing correct to restore it to -- but the loop still processes every
    other path rather than bailing early, so one missing stash doesn't strand
    the rest of the host on its (presumably bad) just-deployed config.
    """
    details: list[str] = []
    ok = True
    for path in paths:
        rc, out, _err = await t.run(ssh, f"ls -1 -- {_q(path)}.pre-nutctl.*")
        stashes = [line for line in out.splitlines() if line.strip()]
        if not stashes:
            details.append(f"{path}: no stash to revert to")
            ok = False
            continue

        newest = max(stashes, key=_stash_ts)
        rc, _out, err = await t.run(ssh, f"cp -a -- {_q(newest)} {_q(path)}")
        if rc != 0:
            details.append(f"{path}: revert copy failed: {err.strip()}")
            ok = False
            continue

        details.append(f"{path}: reverted from {newest}")

    verified, verify_detail = await _verify(t, ssh, {})
    details.append(verify_detail)

    return DeployResult(ok=ok, verified=verified, detail="; ".join(details))
