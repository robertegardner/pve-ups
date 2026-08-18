"""Unit tests for app/nutctl/deploy.py -- the SSH deployment engine.

No real SSH, no asyncssh import: `FakeTransport` records every
`(ssh, cmd, stdin)` call and returns scripted `(rc, stdout, stderr)` responses
keyed by a command prefix. `AsyncsshTransport` itself is exercised only through
its two pure staticmethods (`build_command`/`build_write_command`), which is
where its sudo-wrapping logic actually lives -- there's no need to open a real
SSH connection to test that logic.

Run with:  pytest tests/test_nutctl_deploy.py
These tests need no UPS hardware and no network.
"""
from __future__ import annotations

import pytest

from app.nutctl import deploy
from app.nutctl.topology import SshSpec

FIXED_TS = 1700000000


@pytest.fixture(autouse=True)
def _fixed_time(monkeypatch):
    """Deploy stamps stash filenames with the current unix time; pin it so
    stash paths in these tests are predictable strings, not moving targets."""
    monkeypatch.setattr(deploy.time, "time", lambda: FIXED_TS)


def _ssh(sudo: bool = False) -> SshSpec:
    return SshSpec(host="h1.example.test", sudo=sudo)


class FakeTransport:
    """Records every call; returns the first scripted response whose key the
    command starts with, else `default`."""

    def __init__(self, responses: dict[str, tuple[int, str, str]] | None = None,
                 default: tuple[int, str, str] = (0, "", "")) -> None:
        self.responses = responses or {}
        self.default = default
        self.calls: list[tuple[SshSpec, str, str | None]] = []

    async def run(self, ssh: SshSpec, cmd: str, stdin: str | None = None) -> tuple[int, str, str]:
        self.calls.append((ssh, cmd, stdin))
        for prefix, resp in self.responses.items():
            if cmd.startswith(prefix):
                return resp
        return self.default

    @property
    def cmds(self) -> list[str]:
        return [c for _, c, _ in self.calls]


# --- on-battery interlock ---------------------------------------------------

async def test_on_battery_refuses_before_any_transport_call():
    t = FakeTransport()

    with pytest.raises(deploy.DeployRefused):
        await deploy.deploy_host(
            t, _ssh(), {"/etc/nut/nut.conf": "MODE=netclient\n"},
            reload_cmds=["upsmon -c reload"], on_battery=True,
        )

    assert t.calls == []


async def test_revert_is_not_gated_by_on_battery():
    # revert_host takes no on_battery param at all -- reverting a bad push is
    # exactly the kind of thing you'd want to do mid-outage.
    path = "/etc/nut/nut.conf"
    stash = f"{path}.pre-nutctl.{FIXED_TS}"
    t = FakeTransport({
        f"ls -1 -- {path}.pre-nutctl.*": (0, f"{stash}\n", ""),
        f"cp -a -- {stash} {path}": (0, "", ""),
        "systemctl is-active": (0, "active\n", ""),
    })

    result = await deploy.revert_host(t, _ssh(), [path])

    assert result.ok is True


# --- stash-before-write ordering --------------------------------------------

async def test_stash_before_write_ordering_and_stash_name():
    path = "/etc/nut/nut.conf"
    stash = f"{path}.pre-nutctl.{FIXED_TS}"
    t = FakeTransport({
        f"test -f {path}": (0, "", ""),               # live file exists
        f"ls -1 -- {path}.pre-nutctl.*": (0, f"{stash}\n", ""),
        "systemctl is-active": (0, "active\n", ""),
        f"cat -- {path}": (0, "MODE=netclient\n", ""),
    })

    result = await deploy.deploy_host(
        t, _ssh(), {path: "MODE=netclient\n"}, reload_cmds=[], on_battery=False,
    )

    cmds = t.cmds
    test_idx = cmds.index(f"test -f {path}")
    stash_idx = cmds.index(f"cp -a -- {path} {stash}")
    tee_idx = next(i for i, c in enumerate(cmds) if c.startswith("tee -- "))
    mv_idx = next(i for i, c in enumerate(cmds) if c.startswith("mv -f -- "))
    assert test_idx < stash_idx < tee_idx < mv_idx
    assert result.ok is True and result.verified is True


async def test_no_live_file_skips_stash():
    path = "/etc/nut/nut.conf"
    t = FakeTransport({
        f"test -f {path}": (1, "", ""),  # absent
        "systemctl is-active": (0, "active\n", ""),
    })

    await deploy.deploy_host(t, _ssh(), {path: "x\n"}, reload_cmds=[], on_battery=False)

    assert not any(c.startswith("cp -a") for c in t.cmds)


async def test_prune_keeps_only_newest_three_stashes():
    path = "/etc/nut/nut.conf"
    older = [f"{path}.pre-nutctl.{FIXED_TS - n}" for n in (4, 3, 2, 1)]
    stash = f"{path}.pre-nutctl.{FIXED_TS}"
    all_stashes = older + [stash]
    t = FakeTransport({
        f"test -f {path}": (0, "", ""),
        f"ls -1 -- {path}.pre-nutctl.*": (0, "\n".join(all_stashes) + "\n", ""),
        "systemctl is-active": (0, "active\n", ""),
    })

    await deploy.deploy_host(t, _ssh(), {path: "x\n"}, reload_cmds=[], on_battery=False)

    rm_cmds = [c for c in t.cmds if c.startswith("rm -f -- ")]
    assert len(rm_cmds) == 1
    # newest 3 kept = stash (ts), ts-1, ts-2; pruned = ts-3, ts-4
    assert f"{path}.pre-nutctl.{FIXED_TS - 3}" in rm_cmds[0]
    assert f"{path}.pre-nutctl.{FIXED_TS - 4}" in rm_cmds[0]
    for kept in (stash, f"{path}.pre-nutctl.{FIXED_TS - 1}", f"{path}.pre-nutctl.{FIXED_TS - 2}"):
        assert kept not in rm_cmds[0]


# --- write success path: mode/ownership -------------------------------------

async def test_deploy_sets_modes_per_fleet_convention():
    files = {
        "/etc/nut/upssched-cmd.sh": "#!/bin/bash\n",
        "/etc/nut/upsmon.conf": "MINSUPPLIES 1\n",
        "/etc/sudoers.d/nut-upssched": "nut ALL=...\n",
        "/etc/nut/upsd.users": "[monuser]\n",
    }
    t = FakeTransport({
        "test -f": (1, "", ""),
        "systemctl is-active": (0, "active\n", ""),
    })

    result = await deploy.deploy_host(t, _ssh(), files, reload_cmds=[], on_battery=False)

    cmds = t.cmds
    assert "chmod 755 -- /etc/nut/upssched-cmd.sh" in cmds
    assert "chmod 640 -- /etc/nut/upsmon.conf" in cmds
    assert "chown root:nut -- /etc/nut/upsmon.conf" in cmds
    assert "chmod 440 -- /etc/sudoers.d/nut-upssched" in cmds
    # upsd.users has no .conf suffix but still lives under /etc/nut/ and holds
    # real passwords -- it must get the same 640 root:nut as the .conf files.
    assert "chmod 640 -- /etc/nut/upsd.users" in cmds
    assert "chown root:nut -- /etc/nut/upsd.users" in cmds
    assert result.ok is True


# --- write failure aborts the rest of the host ------------------------------

async def test_write_failure_aborts_remaining_files_for_that_host():
    path1 = "/etc/nut/nut.conf"
    path2 = "/etc/nut/upsmon.conf"
    t = FakeTransport({
        "test -f": (1, "", ""),
        "tee -- ": (1, "", "permission denied"),  # every write fails
        "systemctl is-active": (0, "active\n", ""),
    })

    result = await deploy.deploy_host(
        t, _ssh(), {path1: "a\n", path2: "b\n"}, reload_cmds=[], on_battery=False,
    )

    assert result.ok is False
    assert not any(path2 in c for c in t.cmds)  # second file's path never touched


async def test_reload_cmd_failure_marks_not_ok():
    path = "/etc/nut/nut.conf"
    t = FakeTransport({
        "test -f": (1, "", ""),
        "systemctl is-active": (0, "active\n", ""),
        "upsmon -c reload": (1, "", "no such service"),
    })

    result = await deploy.deploy_host(
        t, _ssh(), {path: "x\n"}, reload_cmds=["upsmon -c reload"], on_battery=False,
    )

    assert result.ok is False


# --- verify -------------------------------------------------------------

async def test_verify_failure_leaves_ok_true_but_verified_false():
    path = "/etc/nut/nut.conf"
    t = FakeTransport({
        "test -f": (1, "", ""),
        "systemctl is-active": (3, "inactive\n", ""),
    })

    result = await deploy.deploy_host(t, _ssh(), {path: "x\n"}, reload_cmds=[], on_battery=False)

    assert result.ok is True
    assert result.verified is False


async def test_verify_hash_mismatch_leaves_ok_true_but_verified_false():
    path = "/etc/nut/nut.conf"
    t = FakeTransport({
        "test -f": (1, "", ""),
        "systemctl is-active": (0, "active\n", ""),
        f"cat -- {path}": (0, "SOMETHING ELSE\n", ""),  # re-fetch disagrees
    })

    result = await deploy.deploy_host(t, _ssh(), {path: "x\n"}, reload_cmds=[], on_battery=False)

    assert result.ok is True
    assert result.verified is False


async def test_verify_success_when_active_and_content_matches():
    path = "/etc/nut/nut.conf"
    t = FakeTransport({
        "test -f": (1, "", ""),
        "systemctl is-active": (0, "active\n", ""),
        f"cat -- {path}": (0, "x\n", ""),
    })

    result = await deploy.deploy_host(t, _ssh(), {path: "x\n"}, reload_cmds=[], on_battery=False)

    assert result.ok is True
    assert result.verified is True


# --- revert ------------------------------------------------------------

async def test_revert_picks_newest_stash():
    path = "/etc/nut/nut.conf"
    stashes = [f"{path}.pre-nutctl.{ts}" for ts in (100, 300, 200)]
    t = FakeTransport({
        f"ls -1 -- {path}.pre-nutctl.*": (0, "\n".join(stashes) + "\n", ""),
        "systemctl is-active": (0, "active\n", ""),
    })

    result = await deploy.revert_host(t, _ssh(), [path])

    assert f"cp -a -- {path}.pre-nutctl.300 {path}" in t.cmds
    assert result.ok is True


async def test_revert_with_no_stash_is_not_ok():
    path = "/etc/nut/nut.conf"
    t = FakeTransport({
        f"ls -1 -- {path}.pre-nutctl.*": (0, "", ""),  # no matches
        "systemctl is-active": (0, "active\n", ""),
    })

    result = await deploy.revert_host(t, _ssh(), [path])

    assert result.ok is False
    assert not any(c.startswith("cp -a") for c in t.cmds)


async def test_revert_continues_past_a_path_with_no_stash():
    missing = "/etc/nut/missing.conf"
    present = "/etc/nut/nut.conf"
    present_stash = f"{present}.pre-nutctl.{FIXED_TS}"
    t = FakeTransport({
        f"ls -1 -- {missing}.pre-nutctl.*": (0, "", ""),
        f"ls -1 -- {present}.pre-nutctl.*": (0, f"{present_stash}\n", ""),
        f"cp -a -- {present_stash} {present}": (0, "", ""),
        "systemctl is-active": (0, "active\n", ""),
    })

    result = await deploy.revert_host(t, _ssh(), [missing, present])

    assert result.ok is False  # missing had no stash
    assert f"cp -a -- {present_stash} {present}" in t.cmds  # but present still reverted


# --- fetch_live ----------------------------------------------------------

async def test_fetch_live_maps_absent_files_to_none():
    t = FakeTransport({"cat -- /etc/nut/gone.conf": (1, "", "no such file")})

    live = await deploy.fetch_live(t, _ssh(), ["/etc/nut/gone.conf", "/etc/nut/there.conf"])

    assert live["/etc/nut/gone.conf"] is None
    assert live["/etc/nut/there.conf"] == ""  # default response: rc 0, empty stdout


async def test_fetch_live_returns_content_for_present_files():
    t = FakeTransport({"cat -- /etc/nut/nut.conf": (0, "MODE=netclient\n", "")})

    live = await deploy.fetch_live(t, _ssh(), ["/etc/nut/nut.conf"])

    assert live["/etc/nut/nut.conf"] == "MODE=netclient\n"


# --- diff_files (pure) -----------------------------------------------------

def test_diff_files_is_pure_and_labels_absent_live_as_dev_null():
    live = {"/etc/nut/nut.conf": None}
    rendered = {"/etc/nut/nut.conf": "MODE=netclient\n"}

    out = deploy.diff_files(live, rendered)

    assert "/dev/null" in out
    assert "+MODE=netclient" in out
    # calling again with the same inputs gives byte-identical output (pure)
    assert deploy.diff_files(live, rendered) == out


def test_diff_files_labels_absent_rendered_as_dev_null():
    live = {"/etc/nut/nut.conf": "MODE=netclient\n"}
    rendered: dict[str, str] = {}

    out = deploy.diff_files(live, rendered)

    assert "-MODE=netclient" in out
    assert out.count("/dev/null") == 1


def test_diff_files_identical_content_yields_no_block():
    live = {"/etc/nut/nut.conf": "MODE=netclient\n"}
    rendered = {"/etc/nut/nut.conf": "MODE=netclient\n"}

    assert deploy.diff_files(live, rendered) == ""


def test_diff_files_shows_line_change():
    live = {"/etc/nut/nut.conf": "MODE=netserver\n"}
    rendered = {"/etc/nut/nut.conf": "MODE=netclient\n"}

    out = deploy.diff_files(live, rendered)

    assert "-MODE=netserver" in out
    assert "+MODE=netclient" in out


# --- AsyncsshTransport command-building (pure staticmethods) ---------------

def test_build_command_passthrough_without_sudo():
    assert deploy.AsyncsshTransport.build_command("cat -- /etc/nut/nut.conf", sudo=False) == (
        "cat -- /etc/nut/nut.conf"
    )


def test_build_command_wraps_sudo_dash_n_sh_c():
    out = deploy.AsyncsshTransport.build_command("cat -- /etc/nut/nut.conf", sudo=True)

    assert out == "sudo -n -- sh -c 'cat -- /etc/nut/nut.conf'"


def test_build_command_escapes_single_quotes_in_wrapped_cmd():
    out = deploy.AsyncsshTransport.build_command("echo 'hi'", sudo=True)

    assert out == "sudo -n -- sh -c 'echo '\\''hi'\\'''"


def test_build_write_command_passthrough_without_sudo():
    assert deploy.AsyncsshTransport.build_write_command(
        "tee -- /etc/nut/nut.conf.nutctl-tmp >/dev/null", sudo=False
    ) == "tee -- /etc/nut/nut.conf.nutctl-tmp >/dev/null"


def test_build_write_command_uses_bare_sudo_dash_n_prefix_for_tee():
    out = deploy.AsyncsshTransport.build_write_command(
        "tee -- /etc/nut/nut.conf.nutctl-tmp >/dev/null", sudo=True
    )

    assert out == "sudo -n tee -- /etc/nut/nut.conf.nutctl-tmp >/dev/null"
    assert "sh -c" not in out  # not routed through an extra shell layer


def test_normalize_rc_passes_through_normal_exit_codes():
    assert deploy.AsyncsshTransport.normalize_rc(0) == 0
    assert deploy.AsyncsshTransport.normalize_rc(1) == 1
    assert deploy.AsyncsshTransport.normalize_rc(127) == 127


def test_normalize_rc_treats_none_exit_status_as_failure_not_success():
    # asyncssh reports exit_status=None when the remote process was killed by a
    # signal -- int(None or 0) would misread that as rc=0 (success); it must
    # come back as a nonzero failure code instead.
    rc = deploy.AsyncsshTransport.normalize_rc(None)

    assert rc != 0
    assert rc == 255
