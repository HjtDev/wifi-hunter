import json

import pytest

from dorm_ip import applier, netinfo
from dorm_ip.models import NetProfile


@pytest.fixture
def state(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    calls = []
    monkeypatch.setattr(netinfo, "run", lambda cmd, timeout=30: calls.append(cmd) or "")
    monkeypatch.setattr(
        netinfo, "saved_settings",
        lambda c: {"ipv4.method": "auto", "ipv4.addresses": "", "ipv4.gateway": "",
                   "ipv4.dns": "", "ipv4.ignore-auto-dns": "no"},
    )
    return calls


def profile(conn="Dorm"):
    return NetProfile("wlan0", conn, "auto", "172.18.40.5", 21, "172.18.47.254", ["172.18.32.1"], "aa:bb")


def test_apply_static_commands(state):
    applier.apply_static("172.18.40.9", 21, "172.18.47.254", ["1.1.1.1", "8.8.8.8"], connection="Dorm")
    assert state[0] == [
        "nmcli", "con", "mod", "Dorm", "ipv4.method", "manual", "ipv4.addresses", "172.18.40.9/21",
        "ipv4.gateway", "172.18.47.254", "ipv4.dns", "1.1.1.1,8.8.8.8", "ipv4.ignore-auto-dns", "yes",
    ]
    assert state[1] == ["nmcli", "con", "up", "Dorm"]


def test_dry_run_prints_and_runs_nothing(state, capsys):
    applier.apply_static("172.18.40.9", 21, "172.18.47.254", ["1.1.1.1"], connection="My Wifi", dry_run=True)
    applier.apply_dhcp(connection="My Wifi", dry_run=True)
    applier.set_dns(["1.1.1.1"], connection="My Wifi", dry_run=True)
    out = capsys.readouterr().out
    assert state == []
    assert "[dry-run] nmcli con mod 'My Wifi' ipv4.method manual" in out
    assert "ipv4.method auto ipv4.addresses '' ipv4.gateway ''" in out
    assert out.count("con up 'My Wifi'") == 3


def test_set_dns_touches_only_dns(state):
    applier.set_dns(["1.1.1.1"], connection="Dorm")
    assert "ipv4.addresses" not in state[0] and "ipv4.method" not in state[0]


def test_backup_written_once_then_kept(state, tmp_path):
    path = applier.backup_profile(profile())
    assert json.loads(path.read_text())["profile"]["ip"] == "172.18.40.5"
    modified = profile()
    modified.ip, modified.method = "172.18.40.99", "manual"
    applier.backup_profile(modified)
    assert json.loads(path.read_text())["profile"]["ip"] == "172.18.40.5"  # original kept
    assert oct(path.stat().st_mode & 0o777) == "0o600"


def test_backup_replaced_for_other_connection(state):
    applier.backup_profile(profile("A"))
    path = applier.backup_profile(profile("B"))
    assert json.loads(path.read_text())["profile"]["connection"] == "B"


def test_dry_run_backup_writes_nothing(state):
    path = applier.backup_profile(profile(), dry_run=True)
    assert not path.exists()


def test_restore_static_backup(state, monkeypatch):
    monkeypatch.setattr(
        netinfo, "saved_settings",
        lambda c: {"ipv4.method": "manual", "ipv4.addresses": "172.18.40.9/21", "ipv4.gateway": "172.18.47.254",
                   "ipv4.dns": "1.1.1.1, 8.8.8.8", "ipv4.ignore-auto-dns": "yes"},
    )
    path = applier.backup_profile(profile())
    conn = applier.restore()
    assert conn == "Dorm" and not path.exists()
    mod = state[0]
    assert mod[mod.index("ipv4.dns") + 1] == "1.1.1.1,8.8.8.8"
    assert mod[mod.index("ipv4.method") + 1] == "manual"


def test_restore_dhcp_backup_and_dry_run_keeps_file(state):
    path = applier.backup_profile(profile())
    applier.restore(dry_run=True)
    assert path.exists() and state == []
    applier.restore()
    assert state[0][state[0].index("ipv4.addresses") + 1] == ""


def test_restore_without_backup(state):
    with pytest.raises(netinfo.NetError, match="nothing to restore"):
        applier.restore()