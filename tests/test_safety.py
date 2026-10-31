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
    monkeypatch.setattr(applier, "apply_static", lambda ip, prefix, gw, dns, *, connection, dry_run=False: calls["apply"].append((ip, list(dns))))
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
