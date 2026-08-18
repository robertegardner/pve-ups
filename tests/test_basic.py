"""Unit tests for config persistence and the engine trigger logic.

Run with:  pytest
These tests need no UPS hardware and no network.
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.config import (
    AppConfig,
    HostConfig,
    NutConfig,
    SnmpConfig,
    SnmpMib,
    SnmpVersion,
    Thresholds,
    UpsThresholdOverride,
    load_config,
    save_config,
)
from app.engine import ON_BATTERY, ONLINE, SHUTDOWN_PENDING, SHUTTING_DOWN, Engine
from app.ups import UpsState


@pytest.fixture(autouse=True)
def _isolated_engine_state(tmp_path, monkeypatch):
    """Point the engine's battery-timer state file at a per-test path, so tests never
    read/write a real (or another test's) engine-state.json."""
    from app import engine as engine_mod
    monkeypatch.setattr(engine_mod, "STATE_PATH", tmp_path / "engine-state.json")


# --- config round-trip ------------------------------------------------------
def test_config_roundtrip_keeps_secrets(tmp_path):
    path = tmp_path / "config.yaml"
    cfg = AppConfig(
        ups=[SnmpConfig(id="ups1", name="USV A", host="10.0.0.9",
                        version=SnmpVersion.v2c, community="topsecret")],
        hosts=[HostConfig(name="pve01", api_url="https://10.0.0.10:8006",
                          token_id="ups@pve!shutdown", token_secret="uuid-secret",
                          this_host=True, ups_ids=["ups1"])],
    )
    save_config(cfg, path)
    loaded = load_config(path)

    assert loaded.ups[0].host == "10.0.0.9"
    assert loaded.ups[0].community.get_secret_value() == "topsecret"
    assert loaded.ups[0].version == SnmpVersion.v2c
    assert loaded.hosts[0].token_secret.get_secret_value() == "uuid-secret"
    assert loaded.hosts[0].ups_ids == ["ups1"]
    # File must be owner-only.
    import os, stat
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if os.name != "nt":
        assert mode == 0o600


def test_config_roundtrip_multi_ups_and_overrides(tmp_path):
    path = tmp_path / "config.yaml"
    cfg = AppConfig(
        ups=[
            SnmpConfig(id="a", name="A", host="10.0.0.1", community="ca"),
            SnmpConfig(id="b", name="B", host="10.0.0.2", community="cb",
                       overrides=UpsThresholdOverride(runtime_below_minutes=2)),
        ],
        hosts=[HostConfig(name="pve01", api_url="x", ups_ids=["a", "b"], ups_policy="all")],
    )
    save_config(cfg, path)
    loaded = load_config(path)
    assert [u.id for u in loaded.ups] == ["a", "b"]
    assert loaded.ups[0].community.get_secret_value() == "ca"
    assert loaded.ups[1].community.get_secret_value() == "cb"
    assert loaded.ups[1].overrides.runtime_below_minutes == 2
    # effective thresholds: per-UPS override applied, global value inherited otherwise
    assert loaded.effective_thresholds(loaded.ups[1]).runtime_below_minutes == 2
    assert loaded.effective_thresholds(loaded.ups[0]).runtime_below_minutes == \
        loaded.thresholds.runtime_below_minutes


def test_config_migrates_single_snmp_to_ups_list():
    # An old (pre-2.0) config dict with a single `snmp` block migrates to `ups: [...]`.
    old = {
        "snmp": {"host": "10.0.0.9", "community": "sec", "version": "v2c"},
        "hosts": [{"name": "pve01", "api_url": "https://x:8006"}],
    }
    cfg = AppConfig.model_validate(old)
    assert len(cfg.ups) == 1
    assert cfg.ups[0].id == "ups1"
    assert cfg.ups[0].host == "10.0.0.9"
    assert cfg.ups[0].community.get_secret_value() == "sec"
    # the host now depends on the migrated UPS
    assert cfg.hosts[0].ups_ids == ["ups1"]


def test_config_defaults_untyped_ups_entries_to_snmp(tmp_path):
    """Pre-3.2 configs have no ``type``; the discriminated union would reject them."""
    import yaml

    path = tmp_path / "config.yaml"
    old = {
        "ups": [{"id": "a", "name": "A", "host": "10.0.0.1", "community": "sec"}],
        "hosts": [{"name": "pve01", "api_url": "https://x:8006", "ups_ids": ["a"]}],
    }
    path.write_text(yaml.safe_dump(old), encoding="utf-8")
    cfg = load_config(path)
    assert isinstance(cfg.ups[0], SnmpConfig)
    assert cfg.ups[0].type == "snmp"
    assert cfg.ups[0].community.get_secret_value() == "sec"
    # ... and the type is written back explicitly on the next save.
    save_config(cfg, path)
    assert yaml.safe_load(path.read_text(encoding="utf-8"))["ups"][0]["type"] == "snmp"


def test_config_defaults_the_mib_of_pre_3_3_entries_to_auto(tmp_path):
    """A config written before MIB profiles must pick up "auto", so an existing APC UPS
    starts using its vendor MIB after an update without anyone touching the wizard."""
    import yaml

    path = tmp_path / "config.yaml"
    old = {"ups": [{"id": "a", "type": "snmp", "host": "10.0.0.1"}]}
    path.write_text(yaml.safe_dump(old), encoding="utf-8")

    cfg = load_config(path)
    assert cfg.ups[0].mib == SnmpMib.auto

    save_config(cfg, path)
    assert yaml.safe_load(path.read_text(encoding="utf-8"))["ups"][0]["mib"] == "auto"


def test_config_roundtrip_keeps_an_explicit_mib(tmp_path):
    path = tmp_path / "config.yaml"
    cfg = AppConfig(ups=[SnmpConfig(id="a", host="10.0.0.1", mib=SnmpMib.apc)])
    save_config(cfg, path)

    assert load_config(path).ups[0].mib == SnmpMib.apc


def test_config_roundtrip_mixes_snmp_and_nut_sources(tmp_path):
    path = tmp_path / "config.yaml"
    cfg = AppConfig(
        ups=[
            SnmpConfig(id="a", name="Card", host="10.0.0.1", community="ca"),
            NutConfig(id="b", name="USB", host="10.0.0.2", ups_name="ups",
                      username="monitor", password="np",
                      overrides=UpsThresholdOverride(charge_below_percent=25)),
        ],
        hosts=[HostConfig(name="pve01", api_url="x", ups_ids=["a", "b"], ups_policy="any")],
    )
    save_config(cfg, path)
    loaded = load_config(path)

    assert [type(u).__name__ for u in loaded.ups] == ["SnmpConfig", "NutConfig"]
    assert loaded.ups[0].community.get_secret_value() == "ca"
    assert loaded.ups[1].password.get_secret_value() == "np"
    assert loaded.ups[1].port == 3493
    assert loaded.ups[1].configured is True
    # Per-UPS overrides work the same regardless of the source type.
    assert loaded.effective_thresholds(loaded.ups[1]).charge_below_percent == 25


def test_nut_source_is_unconfigured_without_a_ups_name():
    assert NutConfig(host="10.0.0.2").configured is False
    assert NutConfig(ups_name="ups").configured is False
    assert NutConfig(host="10.0.0.2", ups_name="ups").configured is True
    # Label falls back to something recognisable in events when no name is set.
    assert NutConfig(host="10.0.0.2", ups_name="ups").label == "ups@10.0.0.2"


def test_config_ignores_legacy_smtp_key(tmp_path):
    # Pre-3.0 configs carry a `notifications.smtp` block; it must load without error
    # and disappear from the file on the next save (e-mail was removed in 3.0.0).
    import yaml
    path = tmp_path / "config.yaml"
    old = {
        "notifications": {
            "smtp": {"enabled": True, "server": "mail.example", "recipients": ["a@b"]},
            "webhook": {"enabled": True, "url": "https://hook.example/x"},
        },
    }
    path.write_text(yaml.safe_dump(old), encoding="utf-8")
    cfg = load_config(path)
    assert cfg.notifications.webhook.enabled is True
    assert cfg.notifications.webhook.url == "https://hook.example/x"
    save_config(cfg, path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert "smtp" not in raw["notifications"]
    assert raw["notifications"]["webhook"]["url"] == "https://hook.example/x"


def test_default_config_missing_file_returns_defaults(tmp_path):
    cfg = load_config(tmp_path / "does-not-exist.yaml")
    assert cfg.configured is False
    assert cfg.dry_run is True  # safe default


def test_merge_config_reconciles_ups_secrets_by_id():
    from app import main
    existing = AppConfig(ups=[SnmpConfig(id="a", host="10.0.0.1", community="keep")])
    incoming = {
        "ups": [{"id": "a", "host": "10.0.0.1", "community": main.SECRET_PLACEHOLDER}],
        "hosts": [],
    }
    merged = main._merge_config(incoming, existing)
    assert merged.ups[0].community.get_secret_value() == "keep"  # placeholder kept old secret


def test_merge_config_reconciles_nut_password_and_ignores_the_other_type():
    """Each source type declares its own secrets; switching type must not inherit any."""
    from app import main

    existing = AppConfig(
        ups=[
            NutConfig(id="n", host="10.0.0.2", ups_name="ups", password="keepme"),
            SnmpConfig(id="s", host="10.0.0.1", community="oldcomm"),
        ]
    )
    incoming = {
        "ups": [
            {"id": "n", "type": "nut", "host": "10.0.0.2", "ups_name": "ups",
             "password": main.SECRET_PLACEHOLDER},
            # Same id, but now a NUT source: the stored SNMP community is irrelevant and
            # the empty password must fall back to the default, not to anything stored.
            {"id": "s", "type": "nut", "host": "10.0.0.3", "ups_name": "ups", "password": ""},
        ],
        "hosts": [],
    }
    merged = main._merge_config(incoming, existing)
    assert merged.ups[0].password.get_secret_value() == "keepme"
    assert merged.ups[1].password.get_secret_value() == ""


# --- ordered_hosts: own host last ------------------------------------------
def test_ordered_hosts_puts_this_host_last():
    cfg = AppConfig(hosts=[
        HostConfig(name="self", api_url="x", this_host=True, order=0),
        HostConfig(name="a", api_url="x", order=5),
        HostConfig(name="b", api_url="x", order=1),
    ])
    order = [h.name for h in cfg.ordered_hosts()]
    assert order == ["b", "a", "self"]


# --- per-UPS trigger logic --------------------------------------------------
def _ups_engine(th: Thresholds) -> Engine:
    """Engine with a single UPS 'u' (no hosts) for testing the per-UPS trigger decision."""
    return Engine(AppConfig(ups=[SnmpConfig(id="u", host="10.0.0.9")], thresholds=th))


def _reason(eng: Engine, uid: str = "u"):
    return eng._ups_trigger_reason(eng.cfg.ups_by_id(uid), eng.ups_rt[uid])


def test_trigger_on_low_runtime():
    eng = _ups_engine(Thresholds(on_battery_seconds=None, runtime_below_minutes=5,
                                 charge_below_percent=None, on_battery_low=False))
    eng.ups_rt["u"].state = UpsState(reachable=True, power_source="battery", runtime_remaining_min=3)
    assert _reason(eng) is not None


def test_trigger_on_low_charge():
    eng = _ups_engine(Thresholds(on_battery_seconds=None, runtime_below_minutes=None,
                                 charge_below_percent=30, on_battery_low=False))
    eng.ups_rt["u"].state = UpsState(reachable=True, power_source="battery", battery_charge_pct=20)
    assert _reason(eng) is not None


def test_trigger_on_battery_low_flag():
    eng = _ups_engine(Thresholds(on_battery_seconds=None, runtime_below_minutes=None,
                                 charge_below_percent=None, on_battery_low=True))
    eng.ups_rt["u"].state = UpsState(reachable=True, power_source="battery", battery_status="low")
    assert _reason(eng) is not None


def test_trigger_on_battery_seconds_uses_own_timer():
    eng = _ups_engine(Thresholds(on_battery_seconds=120, runtime_below_minutes=None,
                                 charge_below_percent=None, on_battery_low=False))
    eng.ups_rt["u"].state = UpsState(reachable=True, power_source="battery")  # no UPS counter
    eng.ups_rt["u"].on_battery_since = datetime.now(timezone.utc) - timedelta(seconds=130)
    assert _reason(eng) is not None


def test_no_trigger_when_healthy():
    eng = _ups_engine(Thresholds())
    eng.ups_rt["u"].state = UpsState(reachable=True, power_source="mains",
                                     runtime_remaining_min=60, battery_charge_pct=100)
    assert _reason(eng) is None


@pytest.mark.asyncio
async def test_nut_source_runs_through_the_same_trigger_logic():
    """The engine must not care how a UPS is read — same thresholds, same latching."""
    th = Thresholds(on_battery_seconds=None, runtime_below_minutes=None,
                    charge_below_percent=25, on_battery_low=False)
    cfg = AppConfig(ups=[NutConfig(id="u", name="USB UPS", host="127.0.0.1", ups_name="ups")],
                    thresholds=th)
    eng = Engine(cfg)

    eng.ups_rt["u"].state = UpsState(reachable=True, power_source="battery",
                                     battery_charge_pct=20)
    await eng._evaluate()
    assert eng.ups_rt["u"].triggered
    assert "charge 20%" in eng.ups_rt["u"].trigger_reason

    # Snapshot tells the UI which source this is, and mains return clears the trigger.
    assert eng.snapshot()["ups"][0]["type"] == "nut"
    eng.ups_rt["u"].state = UpsState(reachable=True, power_source="mains",
                                     battery_charge_pct=90)
    await eng._evaluate()
    assert not eng.ups_rt["u"].triggered


@pytest.mark.asyncio
async def test_unreachable_nut_source_alarms_but_never_shuts_down():
    """Fail safe is a property of the engine, so it holds for every source type."""
    cfg = AppConfig(
        ups=[NutConfig(id="u", name="USB UPS", host="127.0.0.1", ups_name="ups")],
        hosts=[HostConfig(name="pve01", api_url="https://x:8006", ups_ids=["u"])],
        thresholds=Thresholds(unreachable_alarm_after_polls=1),
        dry_run=False,
    )
    eng = Engine(cfg)
    eng.ups_rt["u"].state = UpsState(reachable=False, error="upsd has stale data")
    await eng._evaluate()
    assert eng.ups_rt["u"].alarm_active
    assert not eng.ups_rt["u"].triggered
    assert not eng.shutdown_triggered


# --- multi-UPS host policy (AND/OR) -----------------------------------------
def _multi_engine(policy: str, *, dry_run=True, ups_ids=("a", "b")) -> Engine:
    th = Thresholds(on_battery_seconds=None, runtime_below_minutes=5,
                    charge_below_percent=None, on_battery_low=False)
    cfg = AppConfig(
        dry_run=dry_run,
        ups=[SnmpConfig(id="a", name="A", host="10.0.0.1"),
             SnmpConfig(id="b", name="B", host="10.0.0.2")],
        hosts=[HostConfig(name="pve01", api_url="x", ups_ids=list(ups_ids), ups_policy=policy)],
        thresholds=th,
    )
    return Engine(cfg)


def _on_battery_low_runtime(eng, uid):
    eng.ups_rt[uid].state = UpsState(reachable=True, power_source="battery", runtime_remaining_min=3)


def _on_mains(eng, uid):
    eng.ups_rt[uid].state = UpsState(reachable=True, power_source="mains", runtime_remaining_min=60)


@pytest.mark.asyncio
async def test_and_policy_waits_for_all_feeds():
    # Redundant host: only one of two UPS critical -> NO shutdown.
    eng = _multi_engine("all")
    _on_battery_low_runtime(eng, "a")
    _on_mains(eng, "b")
    await eng._evaluate()
    assert eng.host_fired.get("pve01") in (None, False)
    assert eng.shutdown_triggered is False
    # now the second UPS also goes critical -> shutdown fires
    _on_battery_low_runtime(eng, "b")
    await eng._evaluate()
    assert eng.host_fired.get("pve01") is True
    assert eng.shutdown_triggered is True


@pytest.mark.asyncio
async def test_or_policy_fires_on_first_feed():
    eng = _multi_engine("any")
    _on_battery_low_runtime(eng, "a")
    _on_mains(eng, "b")
    await eng._evaluate()
    assert eng.host_fired.get("pve01") is True
    assert eng.shutdown_triggered is True


@pytest.mark.asyncio
async def test_single_ups_host_behaves_like_before():
    # Regression: a host fed by exactly one UPS shuts down when that UPS triggers.
    eng = _multi_engine("all", ups_ids=("a",))
    _on_battery_low_runtime(eng, "a")
    _on_mains(eng, "b")
    await eng._evaluate()
    assert eng.host_fired.get("pve01") is True


@pytest.mark.asyncio
async def test_and_policy_abort_when_feed_recovers():
    # A dry-run latched host is released when a required feed returns to mains.
    eng = _multi_engine("all")
    _on_battery_low_runtime(eng, "a")
    _on_battery_low_runtime(eng, "b")
    await eng._evaluate()
    assert eng.host_fired.get("pve01") is True
    _on_mains(eng, "a")  # one feed recovers
    await eng._evaluate()
    assert eng.host_fired.get("pve01") is False  # latch released (abort)
    assert eng.shutdown_triggered is False


@pytest.mark.asyncio
async def test_eligible_hosts_shut_down_this_host_last(monkeypatch):
    from app import proxmox
    order: list[str] = []

    async def fake_shutdown(host, timeout=60):
        order.append(host.name)
        return True, "ok"

    monkeypatch.setattr(proxmox, "shutdown_node", fake_shutdown)
    th = Thresholds(on_battery_seconds=None, runtime_below_minutes=5,
                    charge_below_percent=None, on_battery_low=False)
    cfg = AppConfig(
        dry_run=False,
        # nutctl fork defaults to observer_mode=True (no real shutdown, ever); this test
        # exercises the real Proxmox-call path, which only exists for a deployment
        # without per-host upsmon, so it must opt out explicitly.
        observer_mode=False,
        ups=[SnmpConfig(id="a", host="10.0.0.1")],
        hosts=[
            HostConfig(name="self", api_url="x", this_host=True, ups_ids=["a"]),
            HostConfig(name="other", api_url="x", order=1, ups_ids=["a"]),
        ],
        thresholds=th,
    )
    eng = Engine(cfg)
    eng.ups_rt["a"].state = UpsState(reachable=True, power_source="battery", runtime_remaining_min=3)
    await eng._evaluate()
    assert order == ["other", "self"]  # appliance host last


@pytest.mark.asyncio
async def test_per_ups_override_changes_only_that_ups():
    th = Thresholds(on_battery_seconds=None, runtime_below_minutes=5,
                    charge_below_percent=None, on_battery_low=False)
    cfg = AppConfig(
        dry_run=True,
        ups=[SnmpConfig(id="a", host="10.0.0.1",
                        overrides=UpsThresholdOverride(runtime_below_minutes=2)),
             SnmpConfig(id="b", host="10.0.0.2")],
        hosts=[HostConfig(name="ha", api_url="x", ups_ids=["a"]),
               HostConfig(name="hb", api_url="x", ups_ids=["b"])],
        thresholds=th,
    )
    eng = Engine(cfg)
    # runtime 3 min: below global (5) but above the per-UPS override (2) for UPS a
    eng.ups_rt["a"].state = UpsState(reachable=True, power_source="battery", runtime_remaining_min=3)
    eng.ups_rt["b"].state = UpsState(reachable=True, power_source="battery", runtime_remaining_min=3)
    await eng._evaluate()
    assert eng.host_fired.get("ha") in (None, False)  # a's stricter threshold not met
    assert eng.host_fired.get("hb") is True            # b uses global 5 -> met


# --- snapshot ---------------------------------------------------------------
def test_snapshot_ups_is_list_with_feeds():
    eng = _multi_engine("all")
    snap = eng.snapshot()
    assert isinstance(snap["ups"], list)
    assert {u["id"] for u in snap["ups"]} == {"a", "b"}
    host = snap["hosts"][0]
    assert host["ups_policy"] == "all"
    assert {f["id"] for f in host["feeds"]} == {"a", "b"}
    assert host["eligible"] is False


# --- new in v1.2.0 ----------------------------------------------------------
def test_config_roundtrip_new_fields(tmp_path):
    path = tmp_path / "c.yaml"
    cfg = AppConfig(ntp_server="pool.ntp.org", timezone="Europe/Berlin",
                    selftest_enabled=False, selftest_hour=3,
                    thresholds=Thresholds(comm_loss_shutdown_after_min=15))
    save_config(cfg, path)
    loaded = load_config(path)
    assert loaded.ntp_server == "pool.ntp.org"
    assert loaded.timezone == "Europe/Berlin"
    assert loaded.selftest_enabled is False
    assert loaded.selftest_hour == 3
    assert loaded.thresholds.comm_loss_shutdown_after_min == 15


@pytest.mark.asyncio
async def test_no_shutdown_on_mains_even_with_low_charge():
    # Item 9: a low charge while on mains (UPS recharging) must never shut down.
    eng = _ups_engine(Thresholds(charge_below_percent=30, on_battery_seconds=None,
                                 runtime_below_minutes=None, on_battery_low=False))
    eng.ups_rt["u"].state = UpsState(reachable=True, power_source="mains", battery_charge_pct=10)
    await eng._evaluate()
    assert eng.shutdown_triggered is False
    assert eng.state == ONLINE


@pytest.mark.asyncio
async def test_unreachable_raises_alarm_not_shutdown():
    eng = _ups_engine(Thresholds(unreachable_alarm_after_polls=1))
    eng.ups_rt["u"].state = UpsState(reachable=False, error="timeout")
    await eng._evaluate()
    assert eng.alarm_active is True
    assert eng.state != SHUTTING_DOWN
    assert eng.shutdown_triggered is False


@pytest.mark.asyncio
async def test_dry_run_latches_and_does_not_shutdown():
    th = Thresholds(on_battery_seconds=1, runtime_below_minutes=None,
                    charge_below_percent=None, on_battery_low=False)
    cfg = AppConfig(dry_run=True, ups=[SnmpConfig(id="u", host="10.0.0.9")],
                    hosts=[HostConfig(name="pve01", api_url="x", ups_ids=["u"])],
                    thresholds=th)
    eng = Engine(cfg)
    eng.ups_rt["u"].state = UpsState(reachable=True, power_source="battery", seconds_on_battery=10)
    await eng._evaluate()  # enters ON_BATTERY + fires dry-run
    assert eng.shutdown_triggered is True
    assert eng.host_fired.get("pve01") is True
    assert eng.state == SHUTDOWN_PENDING
    # No real host shutdown recorded because nothing was actually shut down.
    assert eng.host_states == {}


@pytest.mark.asyncio
async def test_comm_loss_does_not_shutdown_by_default():
    eng = _ups_engine(Thresholds(unreachable_alarm_after_polls=1,
                                 comm_loss_shutdown_after_min=None, poll_interval_normal_s=30))
    eng.ups_rt["u"].state = UpsState(reachable=False, error="timeout")
    for _ in range(10):
        await eng._evaluate()
    assert eng.shutdown_triggered is False


@pytest.mark.asyncio
async def test_comm_loss_shutdown_when_configured():
    th = Thresholds(unreachable_alarm_after_polls=1, comm_loss_shutdown_after_min=1,
                    poll_interval_normal_s=30)
    cfg = AppConfig(dry_run=True, ups=[SnmpConfig(id="u", host="10.0.0.9")],
                    hosts=[HostConfig(name="pve01", api_url="x", ups_ids=["u"])], thresholds=th)
    eng = Engine(cfg)
    eng.ups_rt["u"].state = UpsState(reachable=False, error="timeout")
    await eng._evaluate()  # arms the wall-clock timer; ~0 s elapsed
    assert eng.shutdown_triggered is False
    # Wall clock, not poll count: backdate the loss beyond the 1-min threshold.
    eng.ups_rt["u"].unreachable_since -= timedelta(seconds=70)
    await eng._evaluate()
    assert eng.shutdown_triggered is True
    assert eng.ups_rt["u"].comm_loss_fired is True


# --- comms loss WHILE ON BATTERY: do not abort the running countdown --------
def _comm_loss_battery_engine(**th_kw) -> Engine:
    th = Thresholds(on_battery_seconds=120, runtime_below_minutes=None,
                    charge_below_percent=None, on_battery_low=False,
                    unreachable_alarm_after_polls=1, **th_kw)
    # dry_run so the (real) shutdown path needs no Proxmox; a host depends on the UPS so a
    # shutdown can actually fire.
    cfg = AppConfig(dry_run=True, ups=[SnmpConfig(id="u", host="10.0.0.9")],
                    hosts=[HostConfig(name="pve01", api_url="x", ups_ids=["u"])], thresholds=th)
    eng = Engine(cfg)
    eng.ups_rt["u"].state = UpsState(reachable=False, error="timeout")  # comms dropped
    return eng


@pytest.mark.asyncio
async def test_comm_loss_on_battery_continues_countdown_and_fires():
    eng = _comm_loss_battery_engine()
    eng.ups_rt["u"].on_battery_since = datetime.now(timezone.utc) - timedelta(seconds=130)
    await eng._evaluate()
    assert eng.shutdown_triggered is True


@pytest.mark.asyncio
async def test_comm_loss_on_battery_waits_until_countdown_elapses():
    eng = _comm_loss_battery_engine()
    eng.ups_rt["u"].on_battery_since = datetime.now(timezone.utc) - timedelta(seconds=30)
    await eng._evaluate()
    assert eng.shutdown_triggered is False  # not due yet
    assert eng.alarm_active is True


@pytest.mark.asyncio
async def test_comm_loss_on_battery_alarm_does_not_claim_no_shutdown():
    eng = _comm_loss_battery_engine()
    eng.ups_rt["u"].on_battery_since = datetime.now(timezone.utc) - timedelta(seconds=30)
    events: list[tuple[str, str]] = []

    async def rec(subject, body, severity):
        events.append((subject, body))

    eng._emit = rec  # type: ignore[assignment]
    await eng._evaluate()
    assert eng.shutdown_triggered is False
    assert any("countdown continues" in s for s, _ in events)
    assert all("NO shutdown" not in b for _, b in events)


@pytest.mark.asyncio
async def test_pure_comm_loss_alarm_still_says_no_shutdown():
    eng = _ups_engine(Thresholds(unreachable_alarm_after_polls=1))
    events: list[tuple[str, str]] = []

    async def rec(subject, body, severity):
        events.append((subject, body))

    eng._emit = rec  # type: ignore[assignment]
    eng.ups_rt["u"].state = UpsState(reachable=False, error="timeout")
    await eng._evaluate()
    assert any("NO shutdown" in b for _, b in events)
    assert eng._aggregate_comm_loss_s() is None  # opt-in not armed


@pytest.mark.asyncio
async def test_comm_loss_optin_alarm_announces_pending_shutdown():
    eng = _ups_engine(Thresholds(unreachable_alarm_after_polls=1,
                                 comm_loss_shutdown_after_min=5, poll_interval_normal_s=30))
    events: list[tuple[str, str]] = []

    async def rec(subject, body, severity):
        events.append((subject, body))

    eng._emit = rec  # type: ignore[assignment]
    eng.ups_rt["u"].state = UpsState(reachable=False, error="timeout")
    await eng._evaluate()  # first poll: alarm only, threshold (5 min) not yet reached
    assert eng.shutdown_triggered is False
    assert any("prolonged loss" in s for s, _ in events)
    assert all("NO shutdown" not in b for _, b in events)
    assert eng._aggregate_comm_loss_s() is not None


@pytest.mark.asyncio
async def test_comm_loss_on_battery_respects_option_off():
    eng = _comm_loss_battery_engine(keep_shutdown_on_comm_loss=False)
    eng.ups_rt["u"].on_battery_since = datetime.now(timezone.utc) - timedelta(seconds=130)
    await eng._evaluate()
    assert eng.shutdown_triggered is False  # opted out -> stays fail-safe


# --- an already fired trigger is never downgraded ----------------------------
@pytest.mark.asyncio
async def test_immediate_trigger_fires_during_running_countdown():
    # A running on_battery_seconds countdown must not delay battery low & Co.
    th = Thresholds(on_battery_seconds=600, runtime_below_minutes=None,
                    charge_below_percent=30, on_battery_low=True)
    cfg = AppConfig(dry_run=True, ups=[SnmpConfig(id="u", host="10.0.0.9")],
                    hosts=[HostConfig(name="pve01", api_url="x", ups_ids=["u"])], thresholds=th)
    eng = Engine(cfg)
    eng.ups_rt["u"].state = UpsState(reachable=True, power_source="battery",
                                     battery_charge_pct=80)
    await eng._evaluate()
    assert eng.shutdown_triggered is False  # countdown running, nothing critical yet
    eng.ups_rt["u"].state = UpsState(reachable=True, power_source="battery",
                                     battery_status="low", battery_charge_pct=80)
    await eng._evaluate()
    assert eng.shutdown_triggered is True
    assert "reports" in (eng.ups_rt["u"].trigger_reason or "")  # battery-low reason, not timer


@pytest.mark.asyncio
async def test_countdown_hidden_once_ups_triggered():
    # Once a UPS has triggered (battery low & Co.), the time-based countdown is moot and
    # must vanish from the status (UPS card, banner) — it previously kept ticking and
    # suggested the shutdown would wait for it.
    th = Thresholds(on_battery_seconds=600, runtime_below_minutes=None,
                    charge_below_percent=None, on_battery_low=True)
    cfg = AppConfig(dry_run=True, ups=[SnmpConfig(id="u", host="10.0.0.9")],
                    hosts=[HostConfig(name="pve01", api_url="x", ups_ids=["u"])], thresholds=th)
    eng = Engine(cfg)
    eng.ups_rt["u"].state = UpsState(reachable=True, power_source="battery",
                                     battery_charge_pct=80)
    await eng._evaluate()
    snap = eng.snapshot()  # countdown running, nothing critical yet
    assert snap["ups"][0]["countdown_remaining_s"] is not None
    assert snap["shutdown"]["countdown_remaining_s"] is not None

    eng.ups_rt["u"].state = UpsState(reachable=True, power_source="battery",
                                     battery_status="depleted", battery_charge_pct=80)
    await eng._evaluate()
    snap = eng.snapshot()
    assert eng.ups_rt["u"].triggered is True
    assert snap["ups"][0]["countdown_remaining_s"] is None
    assert snap["shutdown"]["countdown_remaining_s"] is None


def _latched_trigger_engine() -> Engine:
    """Charge threshold only, no time countdown, blind countdown opted out — the harshest
    setup: before the latch, a comms loss dropped the fired trigger entirely."""
    th = Thresholds(on_battery_seconds=None, runtime_below_minutes=None,
                    charge_below_percent=30, on_battery_low=False,
                    unreachable_alarm_after_polls=1, keep_shutdown_on_comm_loss=False)
    return Engine(AppConfig(ups=[SnmpConfig(id="u", host="10.0.0.9")], thresholds=th))


@pytest.mark.asyncio
async def test_fired_trigger_stays_latched_on_comm_loss():
    eng = _latched_trigger_engine()
    eng.ups_rt["u"].state = UpsState(reachable=True, power_source="battery",
                                     battery_charge_pct=20)
    await eng._evaluate()
    reason = eng.ups_rt["u"].trigger_reason
    assert eng.ups_rt["u"].triggered is True and reason

    eng.ups_rt["u"].state = UpsState(reachable=False, error="timeout")
    await eng._evaluate()
    assert eng.ups_rt["u"].triggered is True  # blind = never downgrade
    assert eng.ups_rt["u"].trigger_reason == reason


@pytest.mark.asyncio
async def test_latched_trigger_clears_on_mains_return():
    eng = _latched_trigger_engine()
    eng.ups_rt["u"].state = UpsState(reachable=True, power_source="battery",
                                     battery_charge_pct=20)
    await eng._evaluate()
    eng.ups_rt["u"].state = UpsState(reachable=False, error="timeout")
    await eng._evaluate()
    assert eng.ups_rt["u"].triggered is True

    eng.ups_rt["u"].state = UpsState(reachable=True, power_source="mains",
                                     battery_charge_pct=20)
    await eng._evaluate()
    assert eng.ups_rt["u"].triggered is False  # confirmed mains return releases the latch


@pytest.mark.asyncio
async def test_latched_trigger_persists_across_restart():
    th = Thresholds(on_battery_seconds=None, runtime_below_minutes=None,
                    charge_below_percent=30, on_battery_low=False,
                    unreachable_alarm_after_polls=1)
    cfg = AppConfig(dry_run=True, ups=[SnmpConfig(id="u", host="10.0.0.9")],
                    hosts=[HostConfig(name="pve01", api_url="x", ups_ids=["u"])], thresholds=th)
    eng1 = Engine(cfg)
    eng1.ups_rt["u"].state = UpsState(reachable=True, power_source="battery",
                                      battery_charge_pct=20)
    await eng1._evaluate()
    reason = eng1.ups_rt["u"].trigger_reason
    assert reason

    # "Restart": the latch is re-armed together with the battery timer.
    eng2 = Engine(cfg)
    assert eng2.ups_rt["u"].triggered is True
    assert eng2.ups_rt["u"].trigger_reason == reason


def test_config_roundtrip_keep_shutdown_on_comm_loss(tmp_path):
    assert Thresholds().keep_shutdown_on_comm_loss is True  # default on
    path = tmp_path / "c.yaml"
    save_config(AppConfig(thresholds=Thresholds(keep_shutdown_on_comm_loss=False)), path)
    assert load_config(path).thresholds.keep_shutdown_on_comm_loss is False


@pytest.mark.asyncio
async def test_network_transitions_are_logged():
    eng = _ups_engine(Thresholds(unreachable_alarm_after_polls=99))
    events: list[str] = []

    async def rec(subject, body, severity):
        events.append(subject)

    eng._emit = rec  # type: ignore[assignment]
    eng.ups_rt["u"].state = UpsState(reachable=True, power_source="mains")
    await eng._evaluate()  # first poll: no transition (last is None)
    eng.ups_rt["u"].state = UpsState(reachable=False, error="timeout")
    await eng._evaluate()  # -> lost
    eng.ups_rt["u"].state = UpsState(reachable=True, power_source="mains")
    await eng._evaluate()  # -> restored
    assert any("connection lost" in s for s in events)
    assert any("connection restored" in s for s in events)


# --- SNMP engine lifecycle (v1.8.3): no file-descriptor leak ----------------
def test_close_engine_handles_both_apis_and_never_raises():
    from app import ups

    # pysnmp 7.x style: engine.close_dispatcher()
    class Seven:
        def __init__(self):
            self.closed = False

        def close_dispatcher(self):
            self.closed = True

    seven = Seven()
    ups._close_engine(seven)
    assert seven.closed is True

    # pysnmp 6.x style: engine.transportDispatcher.closeDispatcher()
    class Dispatcher:
        def __init__(self):
            self.closed = False

        def closeDispatcher(self):
            self.closed = True

    class Six:
        def __init__(self):
            self.transportDispatcher = Dispatcher()

    six = Six()
    ups._close_engine(six)
    assert six.transportDispatcher.closed is True

    # None and a raising closer must both be swallowed (the poller may never crash).
    class Boom:
        def close_dispatcher(self):
            raise RuntimeError("nope")

    ups._close_engine(None)
    ups._close_engine(Boom())  # must not raise


@pytest.mark.asyncio
async def test_poll_closes_engine_even_when_unreachable(monkeypatch):
    """Every poll must release its SnmpEngine — especially on the common timeout path,
    which would otherwise leak a UDP socket per poll and exhaust the fd limit."""
    from app import ups
    from app.config import SnmpConfig

    closed: list = []
    monkeypatch.setattr(ups, "_close_engine", lambda eng: closed.append(eng))

    # Point at a port with no SNMP responder so the poll fails fast (reachable=False).
    cfg = SnmpConfig(host="127.0.0.1", port=1, timeout_s=0.1, retries=0)
    state = await ups.poll(cfg)

    assert state.reachable is False  # nothing answered
    assert len(closed) == 1  # the engine was handed to the closer exactly once
    assert closed[0] is not None


def test_clear_events(tmp_path):
    from app import db
    path = tmp_path / "events.db"
    db.init_db(path)
    db.log_event("a", "x", db.INFO, path)
    db.log_event("b", "y", db.WARNING, path)
    assert len(db.recent_events(path=path)) == 2
    assert db.clear_events(path) == 2
    assert db.recent_events(path=path) == []


def test_events_since_filters_window_and_counts(tmp_path):
    from app import db
    path = tmp_path / "events.db"
    db.init_db(path)
    db.log_event("recent", "", db.WARNING, path)
    # Inject an event older than 48 h directly (log_event always uses 'now').
    old_ts = (datetime.now(timezone.utc) - timedelta(hours=72)).isoformat()
    with db._connect(path) as conn:
        conn.execute(
            "INSERT INTO events (ts, severity, event, detail) VALUES (?, ?, ?, ?)",
            (old_ts, db.CRITICAL, "old", ""),
        )
        conn.commit()

    names = [e["event"] for e in db.events_since(48, path=path)]
    assert "recent" in names and "old" not in names

    counts = db.severity_counts_since(48, path=path)
    assert counts[db.WARNING] == 1
    assert counts[db.CRITICAL] == 0  # the 72 h-old critical is outside the window


# --- updater reliability (v1.5.0) -------------------------------------------
def test_enqueue_agent_writes_final_file_atomically(tmp_path, monkeypatch):
    import json
    from app import main

    agent_dir = tmp_path / "agent"
    queue = agent_dir / "queue"
    monkeypatch.setattr(main, "AGENT_DIR", agent_dir)
    monkeypatch.setattr(main, "AGENT_QUEUE", queue)

    job_id = main._enqueue_agent("update", package="/x/p.tgz")

    files = list(queue.iterdir())
    # Exactly the final job file; no leftover .tmp inside the watched queue dir.
    assert [f.name for f in files] == [f"{job_id}.json"]
    data = json.loads(files[0].read_text(encoding="utf-8"))
    assert data["job_id"] == job_id
    assert data["action"] == "update"
    assert data["package"] == "/x/p.tgz"


def test_agent_drainer_active_never_raises(monkeypatch):
    from app import main

    # systemctl absent / non-Linux dev box: must degrade gracefully, never raise.
    def boom(*a, **k):
        raise FileNotFoundError("systemctl")

    monkeypatch.setattr(main.subprocess, "run", boom)
    # Force the unit-file fallback to a known answer.
    monkeypatch.setattr(main, "AGENT_TIMER_UNIT", main.Path("/no/such/timer"))
    assert main._agent_drainer_active() is False  # missing unit file -> not active


def test_read_package_version_from_tar_and_zip(tmp_path):
    import io
    import tarfile
    import zipfile

    from app import main

    init = b'__version__ = "9.9.9"\n'

    tgz = tmp_path / "pkg.tar.gz"
    with tarfile.open(tgz, "w:gz") as t:  # with a prefix dir, like git archive produces
        info = tarfile.TarInfo("pve-usv/app/__init__.py")
        info.size = len(init)
        t.addfile(info, io.BytesIO(init))
    assert main._read_package_version(tgz) == "9.9.9"

    z = tmp_path / "pkg.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("app/__init__.py", init.decode())
    assert main._read_package_version(z) == "9.9.9"


# --- Docker deployment mode (v3.1.0) -----------------------------------------
async def test_update_upload_disabled_in_docker_mode(monkeypatch):
    """There is no privileged agent in a Docker image; the upload endpoint must refuse
    loudly (501) instead of silently enqueueing a job nothing will ever drain."""
    from app import main

    monkeypatch.setattr(main, "IS_DOCKER", True)
    with pytest.raises(main.HTTPException) as exc:
        await main.api_update_upload(file=None)
    assert exc.value.status_code == 501


async def test_update_status_reports_docker_mode_without_agent_state(monkeypatch):
    from app import main

    monkeypatch.setattr(main, "IS_DOCKER", True)
    result = await main.api_update_status()
    assert result["deployment"] == "docker"
    assert result["pending"] == []
    assert result["agent_drainer"] is None


# --- SNMP v1 -----------------------------------------------------------------
def test_snmp_v1_roundtrip_and_message_processing_model(tmp_path):
    from app.ups import _auth_data

    path = tmp_path / "c.yaml"
    save_config(AppConfig(ups=[SnmpConfig(id="u", host="10.0.0.9",
                                          version=SnmpVersion.v1)]), path)
    loaded = load_config(path)
    assert loaded.ups[0].version == SnmpVersion.v1

    # v1 must go on the wire as model 0, v2c as model 1. pysnmp 6.x exposes the
    # attribute as `mpModel`, 7.x as `message_processing_model`.
    def mp(auth):
        for attr in ("mpModel", "message_processing_model"):
            v = getattr(auth, attr, None)
            if v is not None:
                return v
        raise AssertionError("no message processing model attribute found")

    assert mp(_auth_data(loaded.ups[0])) == 0
    assert mp(_auth_data(SnmpConfig(host="x", version=SnmpVersion.v2c))) == 1


# --- battery timer survives a service restart --------------------------------
@pytest.mark.asyncio
async def test_battery_timer_persists_and_restores_across_restart():
    from app import engine as engine_mod

    th = Thresholds(on_battery_seconds=600, runtime_below_minutes=None,
                    charge_below_percent=None, on_battery_low=False,
                    unreachable_alarm_after_polls=1)
    cfg = AppConfig(dry_run=True, ups=[SnmpConfig(id="u", host="10.0.0.9")],
                    hosts=[HostConfig(name="pve01", api_url="x", ups_ids=["u"])], thresholds=th)

    eng1 = Engine(cfg)
    eng1.ups_rt["u"].state = UpsState(reachable=True, power_source="battery")
    await eng1._evaluate()
    since = eng1.ups_rt["u"].on_battery_since
    assert since is not None
    assert engine_mod.STATE_PATH.exists()  # timer was persisted

    # "Restart": a fresh engine restores the timer, and the blind countdown (UPS now
    # unreachable) keeps running and fires once it elapses.
    eng2 = Engine(cfg)
    assert eng2.ups_rt["u"].on_battery_since == since
    eng2.ups_rt["u"].on_battery_since = since - timedelta(seconds=700)
    eng2.ups_rt["u"].state = UpsState(reachable=False, error="timeout")
    await eng2._evaluate()
    assert eng2.shutdown_triggered is True


@pytest.mark.asyncio
async def test_battery_timer_state_file_cleared_on_mains():
    from app import engine as engine_mod
    import json as _json

    cfg = AppConfig(dry_run=True, ups=[SnmpConfig(id="u", host="10.0.0.9")])
    eng = Engine(cfg)
    eng.ups_rt["u"].state = UpsState(reachable=True, power_source="battery")
    await eng._evaluate()
    assert _json.loads(engine_mod.STATE_PATH.read_text())["on_battery_since"]

    eng.ups_rt["u"].state = UpsState(reachable=True, power_source="mains")
    await eng._evaluate()
    assert _json.loads(engine_mod.STATE_PATH.read_text())["on_battery_since"] == {}


def test_stale_battery_timer_is_not_restored():
    from app import engine as engine_mod
    import json as _json

    old = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
    engine_mod.STATE_PATH.write_text(
        _json.dumps({"on_battery_since": {"u": old}}), encoding="utf-8")
    eng = Engine(AppConfig(ups=[SnmpConfig(id="u", host="10.0.0.9")]))
    assert eng.ups_rt["u"].on_battery_since is None  # older than 24 h -> discarded


def test_ingest_agent_result_logs_exactly_once(tmp_path, monkeypatch):
    import json

    from app import main

    agent_dir = tmp_path / "agent"
    agent_dir.mkdir()
    result = agent_dir / "result.json"
    seen = agent_dir / "result.seen"
    monkeypatch.setattr(main, "AGENT_RESULT", result)
    monkeypatch.setattr(main, "AGENT_SEEN", seen)

    events: list = []
    monkeypatch.setattr(main.db, "log_event", lambda *a, **k: events.append(a))

    result.write_text(json.dumps({
        "job_id": "J1", "ok": True, "message": "m",
        "version_before": "1.4.0", "version_after": "1.5.0",
    }), encoding="utf-8")

    main._ingest_agent_result()
    main._ingest_agent_result()  # second call must be a no-op (seen marker)

    assert len(events) == 1
    assert seen.read_text(encoding="utf-8") == "J1"


# --- SNMP probe diagnostics (v3.1.0) ---------------------------------------
def test_probe_names_cover_every_queried_oid():
    """Every OID a profile queries must be nameable, or the probe would print bare OIDs."""
    from app import ups

    for profile in ups.PROFILES.values():
        assert set(profile.oids) <= set(ups._OBJECTS), profile.id
        assert all(ups._object_name(oid) != oid for oid in profile.oids), profile.id


def test_probe_entry_classifies_missing_objects():
    """v2c/v3 report a missing object as a per-varbind sentinel, not as an error."""
    from pysnmp.proto import rfc1905

    from app import ups

    # A list, not a dict: all three sentinels are Null values and compare equal, so as
    # dict keys they would collapse into one entry.
    cases = [
        (rfc1905.noSuchObject, "noSuchObject"),
        (rfc1905.noSuchInstance, "noSuchInstance"),
        (rfc1905.endOfMibView, "endOfMibView"),
    ]
    for sentinel, expected in cases:
        entry = ups._probe_entry(
            ups.OID_CHARGE_REMAINING, None, 0, 0, [(ups.OID_CHARGE_REMAINING, sentinel)]
        )
        assert entry.status == expected
        assert entry.name == "upsEstimatedChargeRemaining"


def test_probe_entry_maps_snmpv1_no_such_name():
    """errorStatus 2 is how SNMPv1 says 'no such object' - not a transport failure."""
    from pysnmp.proto import rfc1905

    from app import ups

    entry = ups._probe_entry(ups.OID_MINUTES_REMAINING, None, rfc1905.errorStatus.clone(2), 1, [])
    assert entry.status == "noSuchName"
    assert entry.error is None

    other = ups._probe_entry(ups.OID_MINUTES_REMAINING, None, rfc1905.errorStatus.clone(5), 3, [])
    assert other.status == "error"
    assert "index 3" in other.error


def test_probe_entry_reports_transport_errors():
    from app import ups

    entry = ups._probe_entry(ups.OID_OUTPUT_SOURCE, "No SNMP response received", 0, 0, [])
    assert entry.status == "error"
    assert entry.error == "No SNMP response received"


def test_probe_entry_interprets_enum_values():
    from pysnmp.proto.rfc1902 import Integer, OctetString

    from app import ups

    src = ups._probe_entry(
        ups.OID_OUTPUT_SOURCE, None, 0, 0, [(ups.OID_OUTPUT_SOURCE, Integer(5))]
    )
    assert src.status == "ok"
    assert src.value == "battery (5)"

    bat = ups._probe_entry(
        ups.OID_BATTERY_STATUS, None, 0, 0, [(ups.OID_BATTERY_STATUS, Integer(3))]
    )
    assert bat.value == "low (3)"

    pct = ups._probe_entry(
        ups.OID_CHARGE_REMAINING, None, 0, 0, [(ups.OID_CHARGE_REMAINING, Integer(42))]
    )
    assert pct.value == "42"

    name = ups._probe_entry(
        ups.OID_IDENT_MODEL, None, 0, 0, [(ups.OID_IDENT_MODEL, OctetString(" Smart-UPS "))]
    )
    assert name.value == "Smart-UPS"


def test_probe_entry_never_raises_on_a_hostile_value():
    from app import ups

    class Hostile:
        def prettyPrint(self):
            raise RuntimeError("boom")

        def __str__(self):
            raise RuntimeError("boom")

    entry = ups._probe_entry(ups.OID_IDENT_MODEL, None, 0, 0, [(ups.OID_IDENT_MODEL, Hostile())])
    assert entry.status == "error"
    assert "boom" in entry.error


def test_probe_entry_only_emits_declared_statuses():
    from pysnmp.proto import rfc1905
    from pysnmp.proto.rfc1902 import Integer

    from app import ups

    responses = [
        ("timeout", 0, 0, []),
        (None, rfc1905.errorStatus.clone(2), 1, []),
        (None, rfc1905.errorStatus.clone(5), 1, []),
        (None, 0, 0, []),
        (None, 0, 0, [(ups.OID_OUTPUT_SOURCE, Integer(3))]),
        (None, 0, 0, [(ups.OID_OUTPUT_SOURCE, rfc1905.noSuchObject)]),
    ]
    for response in responses:
        entry = ups._probe_entry(ups.OID_OUTPUT_SOURCE, *response)
        assert entry.status in ups.PROBE_STATUSES


@pytest.mark.asyncio
async def test_probe_of_unconfigured_ups_skips_everything():
    from app import ups

    result = await ups.probe(SnmpConfig())
    assert result.reachable is False
    # Nothing was sent, so only the profile that would have been asked first is listed.
    assert result.total == len(ups.DEFAULT_PROFILE.objects)
    assert [e.status for e in result.entries] == ["skipped"] * result.total
    assert "not configured" in result.summary


@pytest.mark.asyncio
async def test_probe_closes_engine_exactly_once_and_stops_early(monkeypatch):
    """One SnmpEngine for all single-OID GETs (no fd leak), and no seven-timeout wait."""
    from app import ups

    closed: list = []
    monkeypatch.setattr(ups, "_close_engine", lambda eng: closed.append(eng))

    cfg = SnmpConfig(host="127.0.0.1", port=1, timeout_s=0.1, retries=0)
    result = await ups.probe(cfg)

    assert len(closed) == 1
    assert closed[0] is not None
    assert result.reachable is False
    assert result.ok_count == 0
    # "auto" walks every profile, so the entry list covers all of them.
    assert len(result.entries) == sum(len(p.objects) for p in ups.PROFILES.values())
    assert result.entries[0].status == "error"
    # Everything after the first failure is reported without waiting for its own timeout.
    assert all(e.status == "skipped" for e in result.entries[1:])


@pytest.mark.asyncio
async def test_probe_summary_names_the_target_but_never_the_secret(monkeypatch):
    from app import ups

    monkeypatch.setattr(ups, "_close_engine", lambda eng: None)
    cfg = SnmpConfig(host="127.0.0.1", port=1, timeout_s=0.1, retries=0, community="s3cr3t")
    result = await ups.probe(cfg)

    assert "127.0.0.1:1" in result.summary
    assert "s3cr3t" not in result.summary


def test_probe_summary_flags_the_snmpv1_multi_get_trap():
    from app import ups

    cfg = SnmpConfig(host="10.0.0.5", port=161, version=SnmpVersion.v1)
    result = ups.ProbeResult(total=2, ok_count=1)
    result.entries = [
        ups.ProbeEntry(
            oid=ups.OID_OUTPUT_SOURCE, name="upsOutputSource", status="ok", value="mains (3)"
        ),
        ups.ProbeEntry(
            oid=ups.OID_MINUTES_REMAINING,
            name="upsEstimatedMinutesRemaining",
            status="noSuchName",
        ),
    ]
    summary = ups._probe_summary(cfg, result, None, ups.RFC1628)

    assert "upsEstimatedMinutesRemaining" in summary
    assert "v2c" in summary


# --- MIB profiles (v3.3.0) -------------------------------------------------
def test_every_profile_is_structurally_sound():
    """A profile must fill real UpsState fields and be able to feed every trigger."""
    from dataclasses import fields

    from app import ups

    state_fields = {f.name for f in fields(ups.UpsState)}
    seen: dict[str, str] = {}
    for profile in ups.PROFILES.values():
        assert profile.id in {m.value for m in SnmpMib}, profile.id
        assert profile.anchor in profile.oids, profile.id
        for obj in profile.objects:
            assert obj.oid.endswith(".0"), obj.name  # scalars only; we never walk tables
            # OIDs must be globally unique or the flat _OBJECTS registry would lose one.
            assert seen.setdefault(obj.oid, profile.id) == profile.id, obj.oid
            assert obj.field in state_fields, obj.name
            assert obj.trigger is None or obj.trigger in ups.PROBE_TRIGGERS, obj.name
            if obj.kind == ups.KIND_ENUM:
                assert obj.enum, obj.name
        # A profile that cannot feed a threshold would leave it silently dead.
        assert set(profile.trigger_oids.values()) == set(ups.PROBE_TRIGGERS), profile.id


def test_apc_timeticks_are_converted_to_seconds_and_minutes():
    """TimeTicks are hundredths of a second - the classic vendor-MIB misreading."""
    from pysnmp.proto.rfc1902 import Integer, OctetString, TimeTicks

    from app import ups

    state = ups.UpsState()
    ups._map_state(state, ups.APC, {
        ups.OID_APC_MODEL: OctetString(" Smart-UPS 1500 "),
        ups.OID_APC_OUTPUT_STATUS: Integer(3),
        ups.OID_APC_BATTERY_STATUS: Integer(3),
        ups.OID_APC_TIME_ON_BATTERY: TimeTicks(9500),
        ups.OID_APC_RUNTIME: TimeTicks(114000),
        ups.OID_APC_CAPACITY: Integer(22),
    })

    assert state.mib == "apc"
    assert state.manufacturer == "APC"        # PowerNet has no manufacturer object
    assert state.model == "Smart-UPS 1500"
    assert state.power_source == "battery" and state.on_battery is True
    assert state.battery_status == "low" and state.battery_low is True
    assert state.seconds_on_battery == 95     # 9500 / 100
    assert state.runtime_remaining_min == 19  # 114000 / 6000
    assert state.battery_charge_pct == 22
    assert state.reachable is True


def test_apc_rounds_the_runtime_down():
    """9.9 minutes must not clear a "below 10 minutes" threshold by rounding up."""
    from pysnmp.proto.rfc1902 import TimeTicks

    from app import ups

    state = ups.UpsState()
    ups._map_state(state, ups.APC, {ups.OID_APC_RUNTIME: TimeTicks(59400)})  # 9.9 min
    assert state.runtime_remaining_min == 9


def test_apc_self_test_is_not_reported_as_an_outage():
    """onBatteryTest(15) runs on battery but is a self-test - this app schedules them."""
    from pysnmp.proto.rfc1902 import Integer

    from app import ups

    state = ups.UpsState()
    ups._map_state(state, ups.APC, {ups.OID_APC_OUTPUT_STATUS: Integer(15)})
    assert state.power_source == "mains"
    assert state.on_battery is False


def test_map_state_ignores_objects_the_device_does_not_implement():
    """A missing object keeps the field's default instead of poisoning it with a sentinel."""
    from pysnmp.proto import rfc1905
    from pysnmp.proto.rfc1902 import Integer

    from app import ups

    state = ups.UpsState()
    ups._map_state(state, ups.RFC1628, {
        ups.OID_OUTPUT_SOURCE: Integer(3),
        ups.OID_CHARGE_REMAINING: rfc1905.noSuchObject,
    })
    assert state.power_source == "mains"
    assert state.battery_charge_pct is None
    assert state.reachable is True


def test_a_device_answering_no_object_of_the_mib_counts_as_unreachable():
    """Pinning a UPS to the wrong MIB must not look healthy.

    The agent replies, so the GET "succeeds" - but every object is missing. Reporting that
    as reachable would show a card with no values, no alarm and no trigger that can ever
    fire, which is exactly the fail-dangerous case the fail-safe rules exist to prevent.
    """
    from pysnmp.proto import rfc1905

    from app import ups

    state = ups.UpsState()
    ups._map_state(state, ups.APC, {oid: rfc1905.noSuchInstance for oid in ups.APC.oids})

    assert state.reachable is False
    assert state.on_battery is False        # unreachable is an alarm, never a shutdown
    assert "implements none of the APC PowerNet objects" in state.error


def test_probe_entry_interprets_apc_values():
    from pysnmp.proto.rfc1902 import Integer, TimeTicks

    from app import ups

    src = ups._probe_entry(
        ups.OID_APC_OUTPUT_STATUS, None, 0, 0, [(ups.OID_APC_OUTPUT_STATUS, Integer(3))]
    )
    assert src.name == "upsBasicOutputStatus"
    assert src.value == "battery (3)"

    # The converted value is shown, the raw one stays in .raw - a unit bug is visible.
    runtime = ups._probe_entry(
        ups.OID_APC_RUNTIME, None, 0, 0, [(ups.OID_APC_RUNTIME, TimeTicks(114000))]
    )
    assert runtime.value == "19 min"
    assert "114000" in runtime.raw


def _script_snmp_get(monkeypatch, responses):
    """Replace pysnmp's GET with a scripted response list. Returns the per-call varbind
    counts, which is enough to tell a union GET from a plain one."""
    import pysnmp.hlapi.asyncio as hlapi

    from app import ups

    asked: list[int] = []

    async def fake_get(engine, auth, transport, context, *objects):
        asked.append(len(objects))
        return responses[len(asked) - 1]

    for name in ("getCmd", "get_cmd"):
        if hasattr(hlapi, name):
            monkeypatch.setattr(hlapi, name, fake_get)
    monkeypatch.setattr(ups, "_close_engine", lambda eng: None)
    return asked


@pytest.mark.asyncio
async def test_auto_switches_to_the_vendor_mib_when_its_anchor_answers(monkeypatch):
    """v2c: the standard GET carries the vendor anchor, so detection costs no round trip."""
    from pysnmp.proto.rfc1902 import Integer, TimeTicks

    from app import ups

    responses = [
        # RFC 1628 objects + the APC anchor: the card answers the anchor, so it speaks APC.
        (None, 0, 0, [(ups.OID_APC_OUTPUT_STATUS, Integer(2))]),
        (None, 0, 0, [
            (ups.OID_APC_OUTPUT_STATUS, Integer(3)),
            (ups.OID_APC_RUNTIME, TimeTicks(114000)),
            (ups.OID_APC_CAPACITY, Integer(80)),
        ]),
    ]
    asked = _script_snmp_get(monkeypatch, responses)

    state = await ups.poll(SnmpConfig(host="127.0.0.1", mib=SnmpMib.auto))

    assert asked == [len(ups.RFC1628.objects) + 1, len(ups.APC.objects)]
    assert state.mib == "apc"
    assert state.runtime_remaining_min == 19
    assert state.reachable is True


@pytest.mark.asyncio
async def test_auto_stays_on_the_standard_when_no_vendor_anchor_answers(monkeypatch):
    """An RFC 1628 device must cost exactly one GET, as it did before MIB profiles."""
    from pysnmp.proto import rfc1905
    from pysnmp.proto.rfc1902 import Integer

    from app import ups

    responses = [(None, 0, 0, [
        (ups.OID_OUTPUT_SOURCE, Integer(3)),
        (ups.OID_MINUTES_REMAINING, Integer(42)),
        (ups.OID_APC_OUTPUT_STATUS, rfc1905.noSuchObject),
    ])]
    asked = _script_snmp_get(monkeypatch, responses)

    state = await ups.poll(SnmpConfig(host="127.0.0.1", mib=SnmpMib.auto))

    assert asked == [len(ups.RFC1628.objects) + 1]
    assert state.mib == "rfc1628"
    assert state.power_source == "mains"
    assert state.runtime_remaining_min == 42


@pytest.mark.asyncio
async def test_explicit_mib_asks_for_that_profile_only(monkeypatch):
    from pysnmp.proto.rfc1902 import Integer

    from app import ups

    responses = [(None, 0, 0, [(ups.OID_APC_OUTPUT_STATUS, Integer(3))])]
    asked = _script_snmp_get(monkeypatch, responses)

    state = await ups.poll(SnmpConfig(host="127.0.0.1", mib=SnmpMib.apc))

    assert asked == [len(ups.APC.objects)]  # no anchor appended, no detection
    assert state.mib == "apc"


@pytest.mark.asyncio
async def test_auto_falls_back_to_the_vendor_mib_under_snmpv1(monkeypatch):
    """v1 aborts a GET over one missing object - which is how an APC NMC1 answers."""
    from pysnmp.proto import rfc1905
    from pysnmp.proto.rfc1902 import Integer

    from app import ups

    responses = [
        (None, rfc1905.errorStatus.clone(2), 1, []),        # noSuchName on RFC 1628
        (None, 0, 0, [(ups.OID_APC_OUTPUT_STATUS, Integer(3))]),
    ]
    asked = _script_snmp_get(monkeypatch, responses)

    cfg = SnmpConfig(host="127.0.0.1", version=SnmpVersion.v1, mib=SnmpMib.auto)
    state = await ups.poll(cfg)

    # The anchor is never appended under v1 - it would break every non-vendor device.
    assert asked == [len(ups.RFC1628.objects), len(ups.APC.objects)]
    assert state.mib == "apc"
    assert state.power_source == "battery"


@pytest.mark.asyncio
async def test_auto_does_not_spend_a_second_timeout_on_an_unreachable_ups(monkeypatch):
    """A timeout means "not reachable", not "wrong MIB". Two timeouts per poll would
    exceed the 8 s on-battery interval and delay the outage response."""
    from app import ups

    for version in (SnmpVersion.v1, SnmpVersion.v2c):
        responses = [("No SNMP response received before timeout", 0, 0, [])] * 2
        asked = _script_snmp_get(monkeypatch, responses)

        state = await ups.poll(SnmpConfig(host="127.0.0.1", version=version, mib=SnmpMib.auto))

        assert len(asked) == 1, version
        assert state.reachable is False
        assert "timeout" in state.error


@pytest.mark.asyncio
async def test_probe_counts_only_the_resolved_profile(monkeypatch):
    """An APC card answers 6 of 13 probed objects - reporting that as a defect would make
    the wizard cry wolf on a perfectly healthy device."""
    from pysnmp.proto import rfc1905
    from pysnmp.proto.rfc1902 import Integer

    from app import ups

    def answer(oid):
        if oid in ups.APC.oids:
            return (None, 0, 0, [(oid, Integer(3 if oid == ups.OID_APC_OUTPUT_STATUS else 5))])
        return (None, 0, 0, [(oid, rfc1905.noSuchObject)])

    responses = [answer(oid) for p in ups.PROFILES.values() for oid in p.oids]
    asked = _script_snmp_get(monkeypatch, responses)

    result = await ups.probe(SnmpConfig(host="127.0.0.1", mib=SnmpMib.auto))

    assert len(asked) == sum(len(p.objects) for p in ups.PROFILES.values())
    assert result.mib == "apc"
    assert result.reachable is True
    assert (result.ok_count, result.total) == (len(ups.APC.objects), len(ups.APC.objects))
    assert result.missing_triggers == []
    # The resolved MIB is listed first; the standard's objects stay on for diagnosis.
    assert [e.oid for e in result.entries[:len(ups.APC.objects)]] == ups.APC.oids
    assert all(e.status == "noSuchObject" for e in result.entries[len(ups.APC.objects):])
    assert "does not implement RFC 1628" in result.summary


@pytest.mark.asyncio
async def test_api_test_ups_returns_probe_details_without_secrets(monkeypatch):
    """The test endpoint carries the per-object diagnosis and never echoes credentials."""
    import json

    from app import main, ups

    cfg = AppConfig(ups=[SnmpConfig(id="u1", host="10.0.0.5", community="s3cr3t")])
    monkeypatch.setattr(main, "engine", Engine(cfg))

    async def fake_poll(_cfg):
        return UpsState(reachable=True, power_source="mains", battery_status="normal")

    async def fake_probe(_cfg):
        result = ups.ProbeResult(
            reachable=True, summary="All 1 objects answered.", ok_count=1, total=1
        )
        result.entries = [
            ups.ProbeEntry(
                oid=ups.OID_OUTPUT_SOURCE,
                name="upsOutputSource",
                status="ok",
                value="mains (3)",
                raw="3",
            )
        ]
        result.missing_triggers = ["runtime"]
        return result

    monkeypatch.setattr(main.sources, "poll", fake_poll)
    monkeypatch.setattr(main.sources, "probe", fake_probe)

    # Masked community -> reconciled from the stored UPS, so the stored secret is in play.
    body = await main.api_test_ups(
        {"id": "u1", "host": "10.0.0.5", "community": main.SECRET_PLACEHOLDER}
    )

    assert body["reachable"] is True
    assert body["probe"]["entries"][0]["name"] == "upsOutputSource"
    assert body["probe"]["ok_count"] == 1
    assert body["probe"]["missing_triggers"] == ["runtime"]
    assert "s3cr3t" not in json.dumps(body)

    # /api/test/snmp stays as a 3.1.x-compatible alias for the same behaviour.
    legacy = await main.api_test_snmp({"id": "u1", "host": "10.0.0.5"})
    assert legacy["reachable"] is True


@pytest.mark.asyncio
async def test_api_test_ups_dispatches_on_the_source_type(monkeypatch):
    """A NUT entry must be validated as NutConfig, not silently as an SNMP one."""
    from app import main

    monkeypatch.setattr(main, "engine", Engine(AppConfig()))
    seen = {}

    async def fake_poll(cfg):
        seen["cls"] = type(cfg).__name__
        seen["ups_name"] = getattr(cfg, "ups_name", None)
        return UpsState(reachable=True, power_source="battery", battery_status="normal")

    async def fake_probe(_cfg):
        from app import ups as ups_mod

        return ups_mod.ProbeResult(reachable=True, summary="ok", ok_count=5, total=5)

    monkeypatch.setattr(main.sources, "poll", fake_poll)
    monkeypatch.setattr(main.sources, "probe", fake_probe)

    body = await main.api_test_ups(
        {"id": "n1", "type": "nut", "host": "10.0.0.7", "port": 3493, "ups_name": "myups"}
    )
    assert seen == {"cls": "NutConfig", "ups_name": "myups"}
    assert body["power_source"] == "battery"


# --- self-test schedule (v3.1.0) -------------------------------------------
def test_selftest_slot_is_anchored_at_the_start_hour():
    from app.engine import selftest_slot

    # 09:00 + every 6 h -> 09:00, 15:00, 21:00, 03:00
    assert selftest_slot(datetime(2026, 7, 25, 15, 7), 9, 360) == datetime(2026, 7, 25, 15, 0)
    assert selftest_slot(datetime(2026, 7, 25, 9, 0), 9, 360) == datetime(2026, 7, 25, 9, 0)


def test_selftest_slot_wraps_across_midnight():
    from app.engine import selftest_slot

    # 03:00 belongs to today's grid, not to tomorrow's.
    assert selftest_slot(datetime(2026, 7, 25, 3, 30), 9, 360) == datetime(2026, 7, 25, 3, 0)
    # Anchor 23:00, every 2 h: 00:30 falls into yesterday's 23:00 slot.
    assert selftest_slot(datetime(2026, 7, 25, 0, 30), 23, 120) == datetime(2026, 7, 24, 23, 0)


def test_selftest_slot_daily_default_matches_the_old_behaviour():
    from app.engine import selftest_slot

    assert selftest_slot(datetime(2026, 7, 25, 8, 59), 9, 1440) == datetime(2026, 7, 24, 9, 0)
    assert selftest_slot(datetime(2026, 7, 25, 9, 0), 9, 1440) == datetime(2026, 7, 25, 9, 0)
    assert selftest_slot(datetime(2026, 7, 25, 23, 59), 9, 1440) == datetime(2026, 7, 25, 9, 0)


def test_selftest_slot_grid_is_exact_for_every_supported_interval():
    from app.config import SELFTEST_INTERVALS
    from app.engine import selftest_slot

    for interval in SELFTEST_INTERVALS:
        day = datetime(2026, 7, 25)
        slots = [selftest_slot(day + timedelta(minutes=m), 9, interval) for m in range(0, 1440, 5)]
        # Compare times of day: a day's worth of samples spans one grid period more than
        # the grid itself (the 00:00 sample belongs to yesterday's last slot).
        assert len({(s.hour, s.minute) for s in slots}) == 1440 // interval, interval
        assert slots == sorted(slots), interval  # monotonically non-decreasing
        for slot in slots:
            assert (slot.hour * 60 + slot.minute - 9 * 60) % interval == 0, (interval, slot)


def test_selftest_slot_tolerates_broken_values():
    from app.engine import selftest_slot

    assert selftest_slot(datetime(2026, 7, 25, 10, 0), 99, 0) is not None
    assert selftest_slot(datetime(2026, 7, 25, 10, 0), 9, None) is not None
    assert selftest_slot(datetime(2026, 7, 25, 10, 0), -5, -60) is not None


def _selftest_engine(monkeypatch, now, **cfg_kwargs):
    """Engine with one host, a patched local clock and a counting _run_selftest."""
    from app import engine as engine_mod

    cfg = AppConfig(
        hosts=[HostConfig(name="pve01", api_url="https://10.0.0.10:8006")], **cfg_kwargs
    )
    clock = {"now": now}
    monkeypatch.setattr(engine_mod, "_local_now", lambda: clock["now"])
    eng = Engine(cfg)
    runs: list = []

    async def fake_run():
        runs.append(clock["now"])

    eng._run_selftest = fake_run  # type: ignore[method-assign]
    return eng, clock, runs


@pytest.mark.asyncio
async def test_selftest_runs_once_per_slot(monkeypatch):
    eng, clock, runs = _selftest_engine(
        monkeypatch, datetime(2026, 7, 25, 10, 0), selftest_hour=9, selftest_interval_min=15
    )

    await eng._maybe_selftest()
    await eng._maybe_selftest()  # same slot -> no second run
    assert len(runs) == 1

    clock["now"] = datetime(2026, 7, 25, 10, 14)
    await eng._maybe_selftest()
    assert len(runs) == 1

    clock["now"] = datetime(2026, 7, 25, 10, 15)
    await eng._maybe_selftest()
    assert len(runs) == 2


@pytest.mark.asyncio
async def test_selftest_daily_default_runs_once_a_day(monkeypatch):
    eng, clock, runs = _selftest_engine(
        monkeypatch, datetime(2026, 7, 25, 9, 30), selftest_hour=9, selftest_interval_min=1440
    )

    await eng._maybe_selftest()
    clock["now"] = datetime(2026, 7, 25, 20, 0)
    await eng._maybe_selftest()
    assert len(runs) == 1

    clock["now"] = datetime(2026, 7, 26, 9, 30)
    await eng._maybe_selftest()
    assert len(runs) == 2


@pytest.mark.asyncio
async def test_selftest_is_skipped_while_on_battery(monkeypatch):
    eng, clock, runs = _selftest_engine(
        monkeypatch,
        datetime(2026, 7, 25, 10, 0),
        selftest_hour=9,
        selftest_interval_min=15,
        ups=[SnmpConfig(id="u1", host="10.0.0.5")],
    )
    eng.ups_rt["u1"].on_battery_since = datetime(2026, 7, 25, 9, 55, tzinfo=timezone.utc)

    await eng._maybe_selftest()
    assert runs == []
    # No latch was taken, so the test runs as soon as mains are back.
    assert eng.last_selftest_slot is None
    eng.ups_rt["u1"].on_battery_since = None
    await eng._maybe_selftest()
    assert len(runs) == 1


@pytest.mark.asyncio
async def test_selftest_never_runs_when_disabled_or_without_hosts(monkeypatch):
    from app import engine as engine_mod

    monkeypatch.setattr(engine_mod, "_local_now", lambda: datetime(2026, 7, 25, 10, 0))

    configs = [
        AppConfig(
            hosts=[HostConfig(name="pve01", api_url="https://x:8006")], selftest_enabled=False
        ),
        AppConfig(selftest_enabled=True),  # no hosts
    ]
    for cfg in configs:
        eng = Engine(cfg)
        runs: list = []

        async def fake_run():
            runs.append(1)

        eng._run_selftest = fake_run  # type: ignore[method-assign]
        await eng._maybe_selftest()
        assert runs == []


@pytest.mark.asyncio
async def test_selftest_slot_survives_a_restart(monkeypatch):
    """Without persistence a 15-minute cadence would re-test on every service restart."""
    import json as _json

    from app import engine as engine_mod

    eng, clock, runs = _selftest_engine(
        monkeypatch, datetime(2026, 7, 25, 10, 0), selftest_hour=9, selftest_interval_min=15
    )
    await eng._maybe_selftest()
    assert len(runs) == 1

    written = _json.loads(engine_mod.STATE_PATH.read_text(encoding="utf-8"))
    assert written["selftest_slot"] == "2026-07-25T10:00:00"

    # Fresh engine, same wall clock -> latch restored, no repeat run.
    restarted = Engine(eng.cfg)
    restarted_runs: list = []

    async def fake_run():
        restarted_runs.append(1)

    restarted._run_selftest = fake_run  # type: ignore[method-assign]
    assert restarted.last_selftest_slot == datetime(2026, 7, 25, 10, 0)
    await restarted._maybe_selftest()
    assert restarted_runs == []


@pytest.mark.asyncio
async def test_selftest_outcome_survives_a_restart(monkeypatch):
    """Since a restart no longer re-runs the test, /api/status must keep the last result."""
    from app import engine as engine_mod
    from app.proxmox import TestResult

    monkeypatch.setattr(engine_mod, "_local_now", lambda: datetime(2026, 7, 25, 10, 0))
    cfg = AppConfig(hosts=[HostConfig(name="pve01", api_url="https://10.0.0.10:8006")])
    eng = Engine(cfg)

    async def fake_test(host, *a, **k):
        return TestResult(True, "ok", has_power_mgmt=True)

    monkeypatch.setattr(engine_mod.proxmox, "test_connection", fake_test)
    monkeypatch.setattr(eng, "_log_quiet", lambda *a: None)
    await eng._maybe_selftest()
    eng._persist_state()  # the loop persists again on its next _evaluate

    restarted = Engine(cfg)
    assert restarted.last_selftest_ok is True
    assert restarted.last_selftest_at == eng.last_selftest_at
    assert restarted.snapshot()["appliance"]["last_selftest_at"] is not None


def test_state_file_from_an_older_version_still_loads():
    """A state file written before the self-test slot existed must not break startup."""
    import json as _json

    from app import engine as engine_mod

    since = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    engine_mod.STATE_PATH.write_text(
        _json.dumps({"on_battery_since": {"u1": since}}), encoding="utf-8"
    )
    eng = Engine(AppConfig(ups=[SnmpConfig(id="u1", host="10.0.0.5")]))

    assert eng.last_selftest_slot is None
    assert eng.ups_rt["u1"].on_battery_since is not None


def test_selftest_slot_in_the_future_is_discarded(monkeypatch):
    """A backwards clock jump must not block self-tests until the clock catches up."""
    import json as _json

    from app import engine as engine_mod

    monkeypatch.setattr(engine_mod, "_local_now", lambda: datetime(2026, 7, 25, 10, 0))
    engine_mod.STATE_PATH.write_text(
        _json.dumps({"selftest_slot": "2026-07-25T13:00:00"}), encoding="utf-8"
    )
    assert Engine(AppConfig()).last_selftest_slot is None


@pytest.mark.asyncio
async def test_run_selftest_queries_hosts_concurrently_and_damps_success_events(monkeypatch):
    """Sequential checks would stall the loop; one 'ok' event per run would flood the log."""
    import asyncio

    from app import engine as engine_mod
    from app.proxmox import TestResult

    monkeypatch.setattr(engine_mod, "_local_now", lambda: datetime(2026, 7, 25, 10, 0))
    cfg = AppConfig(
        hosts=[
            HostConfig(name="pve01", api_url="https://10.0.0.10:8006"),
            HostConfig(name="pve02", api_url="https://10.0.0.11:8006"),
        ]
    )
    eng = Engine(cfg)

    in_flight = {"now": 0, "max": 0}

    async def fake_test(host, *a, **k):
        in_flight["now"] += 1
        in_flight["max"] = max(in_flight["max"], in_flight["now"])
        await asyncio.sleep(0.01)
        in_flight["now"] -= 1
        return TestResult(True, "ok", has_power_mgmt=True)

    logged: list = []
    monkeypatch.setattr(engine_mod.proxmox, "test_connection", fake_test)
    monkeypatch.setattr(eng, "_log_quiet", lambda s, b, sev: logged.append(s))

    await eng._run_selftest()
    assert in_flight["max"] == 2  # both hosts were in flight at the same time
    assert len(logged) == 2  # first run of the day: one quiet event per host
    assert eng.last_selftest_ok is True

    await eng._run_selftest()
    assert len(logged) == 2  # same day, still ok -> no further event-log noise


@pytest.mark.asyncio
async def test_run_selftest_always_reports_failures(monkeypatch):
    from app import engine as engine_mod
    from app.proxmox import TestResult

    monkeypatch.setattr(engine_mod, "_local_now", lambda: datetime(2026, 7, 25, 10, 0))
    eng = Engine(AppConfig(hosts=[HostConfig(name="pve01", api_url="https://10.0.0.10:8006")]))

    async def fake_test(host, *a, **k):
        return TestResult(False, "Authentication failed (token invalid?)")

    emitted: list = []

    async def fake_emit(subject, body, severity):
        emitted.append((subject, severity))

    monkeypatch.setattr(engine_mod.proxmox, "test_connection", fake_test)
    monkeypatch.setattr(eng, "_emit", fake_emit)

    await eng._run_selftest()
    await eng._run_selftest()  # failures are never damped

    assert len(emitted) == 2
    assert emitted[0][0] == "Self-test pve01: FAILED"
    assert eng.last_selftest_ok is False


def test_config_roundtrip_selftest_interval(tmp_path):
    path = tmp_path / "c.yaml"
    save_config(AppConfig(selftest_hour=3, selftest_interval_min=360), path)
    assert load_config(path).selftest_interval_min == 360


def test_selftest_fields_are_import_forgiving():
    """A backup from another version must import, not 400."""
    assert AppConfig.model_validate({"selftest_interval_min": 45}).selftest_interval_min == 1440
    assert AppConfig.model_validate({"selftest_interval_min": None}).selftest_interval_min == 1440
    assert AppConfig.model_validate({"selftest_interval_min": "360"}).selftest_interval_min == 360
    assert AppConfig.model_validate({"selftest_hour": 99}).selftest_hour == 23
    assert AppConfig.model_validate({"selftest_hour": -1}).selftest_hour == 0
    assert AppConfig.model_validate({"selftest_hour": "abc"}).selftest_hour == 9
    assert AppConfig().selftest_interval_min == 1440  # default = previous behaviour


# --- config export / import round-trip -------------------------------------
def _full_config() -> AppConfig:
    """A config with every notable field populated, for round-trip coverage."""
    from app.config import Notifications, WebhookConfig

    return AppConfig(
        configured=True,
        dry_run=False,
        ups=[
            SnmpConfig(id="a", name="UPS A", host="10.0.0.1", community="comm-a",
                       mib=SnmpMib.apc),
            SnmpConfig(
                id="b", name="UPS B", host="10.0.0.2", port=1161, version=SnmpVersion.v3,
                v3_user="mon", v3_auth_pass="auth-b", v3_priv_pass="priv-b",
                overrides=UpsThresholdOverride(runtime_below_minutes=2, on_battery_low=True),
            ),
        ],
        hosts=[
            HostConfig(name="pve01", api_url="https://10.0.0.10:8006",
                       token_id="ups@pve!sd", token_secret="tok-1", ups_ids=["a"]),
            HostConfig(name="pve02", api_url="https://10.0.0.11:8006",
                       token_id="ups@pve!sd", token_secret="tok-2",
                       ups_ids=["a", "b"], ups_policy="any", this_host=True),
        ],
        thresholds=Thresholds(runtime_below_minutes=7, comm_loss_shutdown_after_min=15),
        notifications=Notifications(webhook=WebhookConfig(enabled=True, url="https://hook/x")),
        selftest_enabled=True,
        selftest_hour=3,
        selftest_interval_min=360,
        ntp_server="pool.ntp.org",
        timezone="Europe/Berlin",
    )


def test_export_reveals_secrets_but_drops_auth_material():
    import json

    from app import main

    data = main._exportable_config(_full_config())

    assert data["ups"][0]["community"] == "comm-a"
    assert data["ups"][1]["v3_auth_pass"] == "auth-b"
    assert data["hosts"][0]["token_secret"] == "tok-1"
    assert main.SECRET_PLACEHOLDER not in json.dumps(data)  # a backup must be restorable
    assert "session_secret" not in data and "ui_password_hash" not in data


def test_sanitized_config_masks_secrets_for_the_ui():
    import json

    from app import main

    data = main._sanitized_config(_full_config())

    assert data["ups"][0]["community"] == main.SECRET_PLACEHOLDER
    assert "comm-a" not in json.dumps(data)
    assert "tok-1" not in json.dumps(data)
    assert "session_secret" not in data and "ui_password_hash" not in data


@pytest.fixture
def _import_target(monkeypatch, tmp_path):
    """A running engine whose imports are captured instead of touching the system."""
    from app import main

    saved: list = []
    running = AppConfig(ui_password_hash="hash-of-the-running-instance",
                        session_secret="session-of-the-running-instance")
    monkeypatch.setattr(main, "engine", Engine(running))
    monkeypatch.setattr(main, "save_config", lambda cfg, *a, **k: saved.append(cfg))
    monkeypatch.setattr(main, "IS_DOCKER", True)  # no privileged agent to enqueue jobs to
    monkeypatch.setattr(main.db, "log_event", lambda *a, **k: None)
    return main, saved


@pytest.mark.asyncio
async def test_export_import_round_trip_preserves_every_field(_import_target):
    main, saved = _import_target
    original = _full_config()

    await main.api_config_import(main._exportable_config(original))
    restored = main.engine.cfg

    assert [u.id for u in restored.ups] == ["a", "b"]
    assert restored.ups[0].community.get_secret_value() == "comm-a"
    assert restored.ups[1].v3_auth_pass.get_secret_value() == "auth-b"
    assert restored.ups[1].v3_priv_pass.get_secret_value() == "priv-b"
    assert restored.ups[1].port == 1161
    assert restored.ups[1].overrides.runtime_below_minutes == 2
    assert restored.ups[1].overrides.on_battery_low is True
    assert [h.name for h in restored.hosts] == ["pve01", "pve02"]
    assert restored.hosts[1].token_secret.get_secret_value() == "tok-2"
    assert restored.hosts[1].ups_policy == "any"
    assert restored.hosts[1].this_host is True
    assert restored.thresholds.runtime_below_minutes == 7
    assert restored.thresholds.comm_loss_shutdown_after_min == 15
    assert restored.notifications.webhook.url == "https://hook/x"
    assert restored.dry_run is False
    assert restored.ntp_server == "pool.ntp.org"
    assert restored.timezone == "Europe/Berlin"
    assert restored.selftest_hour == 3
    assert restored.selftest_interval_min == 360

    # The running instance keeps its own login and session signing key.
    assert restored.ui_password_hash == "hash-of-the-running-instance"
    assert restored.session_secret == "session-of-the-running-instance"
    assert saved and saved[0].configured is True


@pytest.mark.asyncio
async def test_import_of_an_older_backup_survives_unknown_values(_import_target):
    """A backup written by another version must import, not fail with 400."""
    main, _ = _import_target

    result = await main.api_config_import(
        {"selftest_interval_min": 45, "selftest_hour": 42, "unknown_future_key": True}
    )

    assert result["selftest_interval_min"] == 1440  # snapped to the daily default
    assert result["selftest_hour"] == 23


@pytest.mark.asyncio
async def test_import_of_a_pre_2x_backup_migrates_the_single_ups(_import_target):
    main, _ = _import_target

    await main.api_config_import({
        "snmp": {"host": "10.0.0.9", "community": "sec", "version": "v2c"},
        "hosts": [{"name": "pve01", "api_url": "https://x:8006"}],
    })
    restored = main.engine.cfg

    assert [u.id for u in restored.ups] == ["ups1"]
    assert restored.ups[0].community.get_secret_value() == "sec"
    assert restored.hosts[0].ups_ids == ["ups1"]


@pytest.mark.asyncio
async def test_import_rejects_a_broken_payload(_import_target):
    from fastapi import HTTPException

    main, saved = _import_target

    with pytest.raises(HTTPException) as excinfo:
        await main.api_config_import({"ups": "not-a-list"})

    assert excinfo.value.status_code == 400
    assert saved == []  # nothing was written


def test_buildconfig_sends_every_system_field():
    """Guard against the silent-reset trap: the server rebuilds the config from this
    payload alone, so a field the UI omits falls back to its default on every save."""
    import re
    from pathlib import Path

    app_js = (Path(__file__).resolve().parents[1] / "app" / "web" / "app.js").read_text(
        encoding="utf-8"
    )
    body = re.search(r"function buildConfig\(\)\s*\{(.*?)\n\}", app_js, re.DOTALL)
    assert body, "buildConfig() not found in app.js"

    for field in ("selftest_enabled", "selftest_hour", "selftest_interval_min",
                  "ntp_server", "timezone", "dry_run"):
        assert field in body.group(1), f"buildConfig() does not send {field}"


# --- SNMPv3 privacy ciphers -------------------------------------------------
def test_snmpv3_privacy_ciphers_are_available():
    """pysnmp 7.x ships no ciphers of its own — it needs the `cryptography` package.

    Without it every authPriv poll fails with "Ciphering services not available" while
    authNoPriv keeps working, which is exactly what a user reported. The flags below are
    what pysnmp sets when its import of `cryptography` failed.
    """
    # Import through the public entry point first: pulling a priv module in on its own
    # trips a circular import inside pysnmp.
    import pysnmp.hlapi.asyncio  # noqa: F401
    from pysnmp.proto.secmod.rfc3414.priv import des
    from pysnmp.proto.secmod.rfc3826.priv import aes

    assert des.PysnmpCryptoError is False, "SNMPv3 DES privacy unavailable"
    # AES-192/256 inherit encrypt_data from this module, so one check covers all three.
    assert aes.PysnmpCryptoError is False, "SNMPv3 AES privacy unavailable"


def test_cryptography_still_exposes_the_apis_pysnmp_uses():
    """Guard the two symbols pysnmp reaches for — the import flags above would not notice.

    A missing package trips PysnmpCryptoError, but an API that merely *moved* still
    imports and only blows up while encrypting, i.e. on the user's box. cryptography 49
    already deprecates primitives.ciphers.modes.CFB (used by pysnmp's AES) and announces
    its removal; this test fails the day it happens instead of the privacy silently
    breaking again. See the version cap in pyproject.toml.
    """
    from cryptography.hazmat.decrepit.ciphers import algorithms as decrepit_algorithms
    from cryptography.hazmat.primitives.ciphers import modes

    assert hasattr(modes, "CFB"), "pysnmp AES needs primitives.ciphers.modes.CFB"
    assert hasattr(
        decrepit_algorithms, "TripleDES"
    ), "pysnmp DES needs decrepit.ciphers.algorithms.TripleDES"


def test_cryptography_is_a_declared_dependency():
    """Guard the declaration itself: the venv may have it, a fresh install must too."""
    from pathlib import Path

    pyproject = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(
        encoding="utf-8"
    )
    # Cut at the closing bracket on its own line — extras like uvicorn[standard] contain
    # brackets, so splitting on a bare "]" would truncate the list.
    block = pyproject.split("dependencies = [", 1)[1].split("\n]", 1)[0]
    assert "cryptography" in block, "cryptography missing from [project].dependencies"


def test_privacy_unavailable_only_applies_to_v3_with_privacy(monkeypatch):
    import builtins

    from app import ups

    real_import = builtins.__import__

    def no_crypto(name, *args, **kwargs):
        if name.startswith("cryptography"):
            raise ImportError("simulated: cryptography not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_crypto)

    from app.config import SnmpAuthProto, SnmpPrivProto

    def cfg(**kw):
        base = dict(host="10.0.0.5", version=SnmpVersion.v3, v3_user="mon",
                    v3_auth_proto=SnmpAuthProto.md5, v3_auth_pass="a")
        base.update(kw)
        return SnmpConfig(**base)

    # v1/v2c never encrypt.
    assert ups._privacy_unavailable(SnmpConfig(host="10.0.0.5", version=SnmpVersion.v2c)) is False
    # v3 authNoPriv works without ciphers — the workaround we point users at.
    assert ups._privacy_unavailable(cfg(v3_priv_proto=SnmpPrivProto.none)) is False
    # v3 authPriv cannot work.
    for proto in (SnmpPrivProto.des, SnmpPrivProto.aes, SnmpPrivProto.aes256):
        assert ups._privacy_unavailable(cfg(v3_priv_proto=proto)) is True, proto


def test_privacy_unavailable_is_false_when_ciphers_are_installed():
    from app import ups
    from app.config import SnmpAuthProto, SnmpPrivProto

    cfg = SnmpConfig(host="10.0.0.5", version=SnmpVersion.v3, v3_user="mon",
                     v3_auth_proto=SnmpAuthProto.md5, v3_auth_pass="a",
                     v3_priv_proto=SnmpPrivProto.des, v3_priv_pass="p")
    assert ups._privacy_unavailable(cfg) is False


@pytest.mark.asyncio
async def test_poll_reports_missing_ciphers_instead_of_unreachable(monkeypatch):
    """The failure is local — nothing is sent — so it must not read like a network fault."""
    from app import ups
    from app.config import SnmpAuthProto, SnmpPrivProto

    monkeypatch.setattr(ups, "_privacy_unavailable", lambda cfg: True)
    sent: list = []
    monkeypatch.setattr(ups, "_auth_data", lambda cfg: sent.append(cfg))

    cfg = SnmpConfig(host="10.0.0.5", version=SnmpVersion.v3, v3_user="mon",
                     v3_auth_proto=SnmpAuthProto.md5, v3_auth_pass="a",
                     v3_priv_proto=SnmpPrivProto.des, v3_priv_pass="p")
    state = await ups.poll(cfg)

    assert state.reachable is False  # fail-safe unchanged: alarm, never a shutdown
    assert state.error == ups.PRIVACY_MISSING
    assert "cryptography" in state.error and "authNoPriv" in state.error
    assert sent == []  # bailed out before building the request


@pytest.mark.asyncio
async def test_probe_reports_missing_ciphers_without_firewall_advice(monkeypatch):
    from app import ups
    from app.config import SnmpAuthProto, SnmpPrivProto

    monkeypatch.setattr(ups, "_privacy_unavailable", lambda cfg: True)

    cfg = SnmpConfig(host="10.0.0.5", version=SnmpVersion.v3, v3_user="mon",
                     v3_auth_proto=SnmpAuthProto.md5, v3_auth_pass="a",
                     v3_priv_proto=SnmpPrivProto.des, v3_priv_pass="p")
    result = await ups.probe(cfg)

    assert result.reachable is False
    assert result.summary == ups.PRIVACY_MISSING
    assert "firewall" not in result.summary.lower()
    assert [e.status for e in result.entries] == ["skipped"] * result.total
