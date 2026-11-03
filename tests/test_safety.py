"""Config lookup, VPN / wrong-network detection, `set` keeps DNS and logs in, CLI guards."""
from dataclasses import replace

import pytest
from typer.testing import CliRunner

from dorm_ip import applier, cli, hunter, netinfo
from dorm_ip import tests as nt
from dorm_ip.config import ConfigError, find_config
from dorm_ip.models import NetProfile

PROFILE = NetProfile("wlan0", "Khabgah", "manual", "172.18.40.123", 21, "172.18.47.254", ["8.8.8.8"], "aa:bb")


def test_user_config_wins_over_local_file(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.toml").write_text("")
    assert find_config(None).resolve() == (tmp_path / "config.toml").resolve()  # only the local one exists
    user = tmp_path / "cfg" / "dorm-ip" / "config.toml"
    user.parent.mkdir(parents=True)
    user.write_text("")
    assert find_config(None) == user
    explicit = tmp_path / "x.toml"
    explicit.write_text("")
    assert find_config(explicit) == explicit


def test_no_config_error_points_to_init(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "none"))
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ConfigError, match="dorm-ip init"):
        find_config(None)


# ---- netinfo
def test_egress_and_tunnel(monkeypatch):
    monkeypatch.setattr(netinfo, "run", lambda cmd, timeout=30: "1.1.1.1 via 172.18.47.254 dev wlan0 src 172.18.40.9 uid 1000\n    cache")
    assert netinfo.egress_device() == "wlan0" and netinfo.tunnel_device("wlan0") is None
    monkeypatch.setattr(netinfo, "run", lambda cmd, timeout=30: "1.1.1.1 dev wg0 table 51820 src 10.2.0.2 uid 1000\n    cache")
    assert netinfo.tunnel_device("wlan0") == "wg0"
    assert netinfo.tunnel_device("") is None


def test_egress_unknown_is_not_a_vpn(monkeypatch):
    def boom(cmd, timeout=30):
        raise netinfo.NetError("Network is unreachable")

    monkeypatch.setattr(netinfo, "run", boom)
    assert netinfo.egress_device() is None and netinfo.tunnel_device("wlan0") is None


def test_check_dorm_network(cfg):
    assert netinfo.check_dorm_network(PROFILE, cfg) is None
    other = NetProfile("wlan0", "Home", "auto", "192.168.1.5", 24, "192.168.1.1", [], "aa")
    assert "does not look like the dorm wifi" in netinfo.check_dorm_network(other, cfg)
    assert netinfo.check_dorm_network(replace(other, gateway=None), cfg) is None


def test_iface_bytes_reads_counters():
    assert isinstance(netinfo.iface_bytes("lo"), int)


def test_iface_bytes_missing_device():
    assert netinfo.iface_bytes("definitely-not-a-device0") is None


# ---- CLI
@pytest.fixture
def run_cli(cfg, monkeypatch, tmp_path):
    calls = {"apply": [], "tun": None, "portal": ("open", 0, None), "login": []}
    cfgfile = tmp_path / "config.toml"
    cfgfile.write_text(cfg.source.read_text())
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setattr(netinfo, "get_profile", lambda i, c: calls.get("profile", PROFILE))
    monkeypatch.setattr(netinfo, "tunnel_device", lambda i: calls["tun"])
    monkeypatch.setattr(applier, "begin_change", lambda i, c, dry_run=False, notify=None: applier.Target("Khabgah", "wlan0"))
    calls["mode"] = "reconnect"
    calls["persist"] = []

    def switch(ip, prefix, gw, dns, *, target, live, dry_run=False, sleep=None, clock=None):
        calls["apply"].append((ip, list(dns)))
        calls["live_requested"] = live
        if live and calls["mode"] == "live":
            return applier.SwitchResult("live")
        return applier.SwitchResult("reconnect", "live IP switching is not working here (test)" if live else "")

    monkeypatch.setattr(applier, "switch_static", switch)
    monkeypatch.setattr(applier, "persist_static", lambda ip, p, g, d, *, connection, dry_run=False: calls["persist"].append(ip))
    monkeypatch.setattr(nt, "ping", lambda t, n, wait=2: (20.0, 0.0, 1.0))
    monkeypatch.setattr(nt, "check_portal", lambda c: calls["portal"])
    monkeypatch.setattr(hunter, "_login", lambda c, ip="", mac="": calls["login"].append((ip, mac)) or (True, "HTTP 200"))

    def invoke(*args):
        return CliRunner().invoke(cli.app, ["--config", str(cfgfile), *args])

    invoke.calls = calls
    return invoke


def sleepless(monkeypatch):
    real = hunter.settle_portal
    monkeypatch.setattr(hunter, "settle_portal", lambda *a, **k: real(*a, sleep=lambda s: None, **k))


def test_set_keeps_current_dns(run_cli, monkeypatch):
    sleepless(monkeypatch)
    r = run_cli("set", "172.18.40.130")
    assert r.exit_code == 0, r.output
    assert run_cli.calls["apply"] == [("172.18.40.130", ["8.8.8.8"])]  # override stays override


def test_set_dns_flag_wins_and_empty_current_dns_falls_back(run_cli, monkeypatch):
    sleepless(monkeypatch)
    run_cli("set", "172.18.40.130", "--dns", "9.9.9.9")
    assert run_cli.calls["apply"][-1][1] == ["9.9.9.9"]
    run_cli.calls["profile"] = replace(PROFILE, dns=[])
    run_cli("set", "172.18.40.131")
    assert run_cli.calls["apply"][-1][1] == ["172.18.32.1"]


def test_set_logs_in_when_portal_shows(run_cli, monkeypatch):
    sleepless(monkeypatch)
    states = iter([("portal", 0, "http://portal/"), ("open", 0, None)])
    monkeypatch.setattr(nt, "check_portal", lambda c: next(states))
    cfg_text = None
    import dorm_ip.config as C
    orig = C.load_config
    monkeypatch.setattr(cli, "load_config", lambda p=None: _with_portal(orig(p)))
    r = run_cli("set", "172.18.40.130")
    assert r.exit_code == 0 and "logged in automatically" in r.output
    assert run_cli.calls["login"] == [("172.18.40.130", "aa:bb")]


def _with_portal(cfg):
    from dataclasses import replace as rp

    return rp(cfg, portal=rp(cfg.portal, enabled=True, url="http://portal/login"))


def test_set_no_login_flag(run_cli, monkeypatch):
    sleepless(monkeypatch)
    monkeypatch.setattr(nt, "check_portal", lambda c: ("portal", 0, "http://portal/"))
    monkeypatch.setattr(cli, "load_config", lambda p=None, orig=cli.load_config: _with_portal(orig(p)))
    r = run_cli("set", "172.18.40.130", "--no-login")
    assert run_cli.calls["login"] == [] and "Login required" in r.output


def test_set_refuses_other_network_unless_forced(run_cli, monkeypatch):
    sleepless(monkeypatch)
    run_cli.calls["profile"] = NetProfile("wlan0", "Home", "auto", "192.168.1.5", 24, "192.168.1.1", ["1.1.1.1"], "aa")
    r = run_cli("set", "172.18.40.130")
    assert r.exit_code == 1 and "does not look like the dorm wifi" in str(r.exception) and run_cli.calls["apply"] == []
    assert run_cli("set", "172.18.40.130", "--force").exit_code == 0


def test_test_and_hunt_refuse_when_vpn_is_active(run_cli, monkeypatch):
    run_cli.calls["tun"] = "tun0"
    for cmd in (["test"], ["hunt"]):
        r = run_cli(*cmd)
        assert r.exit_code == 1 and "tun0" in str(r.exception) and "measure the VPN" in str(r.exception)
    monkeypatch.setattr(nt, "run_all", lambda *a, **k: pytest.fail("must not run"))


def test_path_command(run_cli, tmp_path):
    assert run_cli("path", "config").output.strip().endswith("config.toml")
    assert run_cli("path", "db").output.strip().endswith("history.db")
    assert run_cli("path", "backup").output.strip().endswith("backup.json")
    assert run_cli("path", "credentials").output.strip().endswith("credentials.toml")
    assert run_cli("path", "nope").exit_code == 1


def test_set_switches_live_and_saves_the_profile(run_cli, monkeypatch):
    sleepless(monkeypatch)
    run_cli.calls["mode"] = "live"
    r = run_cli("set", "172.18.40.130")
    assert r.exit_code == 0 and "live, no reconnect" in " ".join(r.output.split())
    assert run_cli.calls["live_requested"] is True and run_cli.calls["persist"] == ["172.18.40.130"]


def test_set_reports_when_live_switching_does_not_work(run_cli, monkeypatch):
    sleepless(monkeypatch)
    r = run_cli("set", "172.18.40.130")
    flat = " ".join(r.output.split())
    assert r.exit_code == 0 and "not working here" in flat and "reconnected" in flat
    assert run_cli.calls["persist"] == []  # the reconnect path already saved the profile


# ---- hunt flags and the standby command (phase 2)
def test_hunt_flags_reach_the_config(run_cli, monkeypatch):
    seen = {}
    monkeypatch.setattr(hunter, "hunt", lambda cfg, **k: seen.update(cfg=cfg, kw=k) or None)
    r = run_cli("hunt", "--find", "3", "--no-triage", "--max", "7")
    assert r.exit_code == 1  # nothing passed (stub)
    assert seen["cfg"].hunt.find == 3 and seen["cfg"].hunt.triage_batch == 0 and seen["cfg"].hunt.max_candidates == 7
    assert callable(seen["kw"]["on_standby"]) and callable(seen["kw"]["on_scan"])


def test_hunt_without_flags_keeps_the_config_values(run_cli, monkeypatch):
    seen = {}
    monkeypatch.setattr(hunter, "hunt", lambda cfg, **k: seen.update(cfg=cfg) or None)
    run_cli("hunt")
    assert seen["cfg"].hunt.find == 1 and seen["cfg"].hunt.triage_batch == 12


def test_standby_command_lists_and_clears(run_cli):
    import time as _t

    from dorm_ip.db import open_db
    from dorm_ip.models import TestResult

    assert "No standby IPs" in run_cli("standby").output
    with open_db() as d:
        d.save_standby([TestResult(_t.time(), "172.18.40.8", "aa", "override", False, True, "open", 20.0, 0.0, 1.0, 10.0,
                                   30.0, None, None, None, 1, 88.0, True, None)])
    out = run_cli("standby").output
    assert "172.18.40.8" in out and "88" in out and "standby.max_age_hours" in " ".join(out.split())
    assert "Removed 1" in run_cli("standby", "--clear").output
    assert "No standby IPs" in run_cli("standby").output


# ---- hunt --watch (phase 3)
def test_hunt_watch_starts_the_watchdog_after_a_good_ip(run_cli, monkeypatch):
    from dorm_ip.models import TestResult as TR
    import time as _t

    good = TR(_t.time(), "172.18.40.8", "aa", "override", False, True, "open", 20.0, 0.0, 1.0, 10.0, 30.0,
              25.0, 20.0, None, 1, 88.0, True, None)
    monkeypatch.setattr(hunter, "hunt", lambda cfg, **k: good)
    started = []
    monkeypatch.setattr(cli, "_watch_loop", lambda st, cfg: started.append(cfg))
    r = run_cli("hunt", "--watch")
    assert r.exit_code == 0 and len(started) == 1 and "Starting the watchdog" in r.output


def test_hunt_without_watch_does_not_start_it(run_cli, monkeypatch):
    from dorm_ip.models import TestResult as TR
    import time as _t

    good = TR(_t.time(), "172.18.40.8", "aa", "override", False, True, "open", 20.0, 0.0, 1.0, 10.0, 30.0,
              25.0, 20.0, None, 1, 88.0, True, None)
    monkeypatch.setattr(hunter, "hunt", lambda cfg, **k: good)
    monkeypatch.setattr(cli, "_watch_loop", lambda st, cfg: pytest.fail("must not start"))
    assert run_cli("hunt").exit_code == 0


def test_hunt_watch_does_not_start_when_nothing_passed(run_cli, monkeypatch):
    monkeypatch.setattr(hunter, "hunt", lambda cfg, **k: None)
    monkeypatch.setattr(cli, "_watch_loop", lambda st, cfg: pytest.fail("must not start"))
    assert run_cli("hunt", "--watch").exit_code == 1


def test_hunt_watch_dry_run_only_says_what_it_would_do(run_cli, monkeypatch):
    monkeypatch.setattr(hunter, "hunt", lambda cfg, **k: None)
    monkeypatch.setattr(cli, "_watch_loop", lambda st, cfg: pytest.fail("must not start"))
    r = run_cli("--dry-run", "hunt", "--watch")
    assert r.exit_code == 0 and "would start the watchdog" in r.output


def test_watch_command_and_hunt_watch_share_one_loop(run_cli, monkeypatch):
    seen = []
    monkeypatch.setattr(cli, "_watch_loop", lambda st, cfg: seen.append(cfg.watchdog.notify))
    run_cli("watch", "--no-notify")
    assert seen == [False]
