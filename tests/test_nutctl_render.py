"""Tests for nutctl.render: byte-exact client config rendering."""
from pathlib import Path

import pytest

from app.nutctl.topology import load_topology
from app.nutctl.render import render_host, render_server

FIX = Path(__file__).parent / "fixtures" / "nutctl"
TOPO = load_topology(FIX / "example-topology.yaml")
SECRETS = {"nutnode_pass": "s3cret"}
SECRETS_SRV = {"nutnode_pass": "s3cret", "monuser_pass": "m4ster"}


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


def test_nas_host_renders_only_nut_dw_plugin_files():
    """nas-nut-client (a NAS running the nut-dw plugin) is a GUI-managed
    appliance, not a scriptable Debian nut-client -- render_host() must emit
    only the two files the live plugin actually owns (per the live NAS
    capture in the private ops repo), never the pve-node upssched/sudoers
    set."""
    files = render_host(TOPO, "nas1", {"monuser_pass": "m4ster"})
    assert set(files) == {"/etc/nut/upsmon.conf", "/etc/nut/nut.conf"}


def test_nas_upsmon_conf_matches_live_plugin_layout():
    files = render_host(TOPO, "nas1", {"monuser_pass": "m4ster"})
    assert files["/etc/nut/upsmon.conf"] == (
        "MONITOR alpha@192.0.2.10 1 monuser m4ster slave\n"
        'SHUTDOWNCMD "/sbin/poweroff"\n'
        'POWERDOWNFLAG "/etc/nut/no_killpower"\n'
        'NOTIFYCMD "/usr/sbin/nut-notify"\n'
        "NOTIFYFLAG ONBATT SYSLOG+EXEC\n"
        "NOTIFYFLAG ONLINE SYSLOG+EXEC\n"
        "NOTIFYFLAG REPLBATT SYSLOG+EXEC\n"
        + "\n" * 11
        + "# If not in manual mode, the following lines are reserved and overwritten by GUI:\n"
        "# L1:MONITOR/L3:POWERDOWNFLAG/L8:DEBUG_MIN\n"
    )


def test_nas_upsmon_conf_redaction():
    files = render_host(TOPO, "nas1", None)
    mon = files["/etc/nut/upsmon.conf"]
    assert "m4ster" not in mon
    assert "@SECRET:monuser_pass@" in mon
    assert " monuser " in mon  # NAS plugin authenticates as monuser, not nutnode


def test_nas_nut_conf_matches_live_plugin_layout():
    files = render_host(TOPO, "nas1", {"monuser_pass": "m4ster"})
    assert files["/etc/nut/nut.conf"] == (
        "MODE = slave\n"
        + "\n" * 17
        + "# If not in manual mode, the following lines are reserved and overwritten by GUI:\n"
        "# L1:MODE\n"
    )


def test_server_ups_conf_stanzas():
    files = render_server(TOPO, SECRETS_SRV)
    conf = files["/etc/nut/ups.conf"]
    assert "[alpha]" in conf and "[beta]" in conf
    assert '        driver = "usbhid-ups"' in conf
    assert '        port = "auto"' in conf
    assert '        serial = "AAA1"' in conf
    assert "        onlinedischarge" in conf
    assert "        override.battery.runtime.low = 420" in conf   # alpha
    assert "        override.battery.runtime.low = 600" in conf   # beta


def test_server_ups_conf_stanza_body_is_indented_8_spaces():
    """Matches the live NUT server's /etc/nut/ups.conf convention (captured
    in the private ops repo): every stanza body line -- not just the header
    -- is indented, the header itself is not."""
    files = render_server(TOPO, SECRETS_SRV)
    conf = files["/etc/nut/ups.conf"]
    alpha = conf.split("[alpha]\n", 1)[1].split("\n\n", 1)[0]
    for line in alpha.splitlines():
        assert line.startswith(" " * 8), line


def test_server_ups_conf_desc_productid_product_rendered_between_vendorid_and_serial():
    """alpha carries desc/productid/product -- matches the 3 of 5 stanzas in
    the live NUT server capture that have an active `product` line."""
    files = render_server(TOPO, SECRETS_SRV)
    conf = files["/etc/nut/ups.conf"]
    assert '        desc = "CyberPower CP1500PFCLCD"' in conf
    assert '        productid = "0601"' in conf
    assert '        product = "CP1500AVRLCD3"' in conf
    vendorid_i = conf.index('vendorid = "0764"')
    desc_i = conf.index('desc = "CyberPower CP1500PFCLCD"')
    productid_i = conf.index('productid = "0601"')
    product_i = conf.index('product = "CP1500AVRLCD3"')
    serial_i = conf.index('serial = "AAA1"')
    assert vendorid_i < desc_i < productid_i < product_i < serial_i


def test_server_ups_conf_desc_productid_product_optional():
    """beta carries no desc/productid/product in the fixture -- must not
    render an empty/None field."""
    files = render_server(TOPO, SECRETS_SRV)
    conf = files["/etc/nut/ups.conf"]
    beta = conf.split("[beta]\n", 1)[1]
    stanza = beta.split("\n\n", 1)[0]
    assert "desc" not in stanza
    assert "productid" not in stanza
    assert 'product = "' not in stanza


def test_server_no_override_when_null():
    topo2 = TOPO.model_copy(deep=True)
    topo2.ups["alpha"].runtime_low_s = None
    conf = render_server(topo2, SECRETS_SRV)["/etc/nut/ups.conf"]
    assert conf.count("override.battery.runtime.low") == 1


def test_upsd_users_redaction():
    files = render_server(TOPO, None)
    users = files["/etc/nut/upsd.users"]
    assert "@SECRET:nutnode_pass@" in users and "upsmon slave" in users


def test_upsd_users_matches_live_layout():
    """Matches the live NUT server's /etc/nut/upsd.users: exactly two
    accounts (monuser master, nutnode slave), body lines 2-space indented.
    No fictitious synology-monuser account -- the DSM-based NAS client
    authenticates as monuser directly."""
    files = render_server(TOPO, None)
    users = files["/etc/nut/upsd.users"]
    assert users == (
        "[monuser]\n"
        "  password = @SECRET:monuser_pass@\n"
        "  upsmon master\n"
        "\n"
        "[nutnode]\n"
        "  password = @SECRET:nutnode_pass@\n"
        "  upsmon slave\n"
    )
    assert "synology" not in users
