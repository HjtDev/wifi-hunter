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


# ---- live IP switching (phase 1)
LIVE_SHOW = "IP4.ADDRESS[1]:{ip}/21\nIP4.GATEWAY:172.18.47.254\n"


def tgt():
    return applier.Target("Dorm", "wlan0")


def test_apply_live_uses_device_modify_and_never_touches_the_profile(state):
    applier.apply_live("172.18.40.9", 21, "172.18.47.254", ["8.8.8.8"], device="wlan0")
    assert state == [[
        "nmcli", "device", "modify", "wlan0", "ipv4.method", "manual", "ipv4.addresses", "172.18.40.9/21",
        "ipv4.gateway", "172.18.47.254", "ipv4.dns", "8.8.8.8", "ipv4.ignore-auto-dns", "yes",
    ]]
    assert not any("con" in c[1:2] for c in state)  # no `con mod`, no `con up`


def test_persist_static_saves_without_reconnecting(state):
    applier.persist_static("172.18.40.9", 21, "172.18.47.254", ["8.8.8.8"], connection="Dorm")
    assert [c[1:3] for c in state] == [["con", "mod"]]


def fake_nmcli(monkeypatch, shown):
    """`nmcli dev show` returns whatever `shown()` says; everything else succeeds."""
    monkeypatch.setattr(netinfo, "nmcli", lambda *a: shown())


class Clock:
    def __init__(self):
        self.t = 0.0

    def sleep(self, s): self.t += s
    def now(self): return self.t


def test_switch_live_verified(state, monkeypatch):
    fake_nmcli(monkeypatch, lambda: LIVE_SHOW.format(ip="172.18.40.9"))
    c = Clock()
    r = applier.switch_static("172.18.40.9", 21, "172.18.47.254", ["8.8.8.8"], target=tgt(), live=True,
                              sleep=c.sleep, clock=c.now)
    assert r.mode == "live" and r.note == ""
    assert len(state) == 1 and state[0][1:3] == ["device", "modify"]


def test_switch_falls_back_when_the_address_did_not_change(state, monkeypatch):
    fake_nmcli(monkeypatch, lambda: LIVE_SHOW.format(ip="172.18.40.5"))  # still the old address
    c = Clock()
    r = applier.switch_static("172.18.40.9", 21, "172.18.47.254", ["8.8.8.8"], target=tgt(), live=True,
                              sleep=c.sleep, clock=c.now)
    assert r.mode == "reconnect" and "did not change" in r.note and "not working here" in r.note
    assert [c_[1:3] for c_ in state] == [["device", "modify"], ["con", "mod"], ["con", "up"]]


def test_switch_falls_back_when_the_address_is_added_next_to_the_old_one(state, monkeypatch):
    fake_nmcli(monkeypatch, lambda: "IP4.ADDRESS[1]:172.18.40.9/21\nIP4.ADDRESS[2]:172.18.40.5/21\n")
    c = Clock()
    r = applier.switch_static("172.18.40.9", 21, "gw", [], target=tgt(), live=True, sleep=c.sleep, clock=c.now)
    assert r.mode == "reconnect"  # two addresses = not a clean switch


def test_switch_falls_back_when_nmcli_refuses(monkeypatch):
    calls = []

    def run(cmd, timeout=30):
        calls.append(cmd)
        if cmd[1:3] == ["device", "modify"]:
            raise netinfo.NetError("Error: Device 'wlan0' is not connected")
        return ""

    monkeypatch.setattr(netinfo, "run", run)
    r = applier.switch_static("172.18.40.9", 21, "gw", ["8.8.8.8"], target=tgt(), live=True)
    assert r.mode == "reconnect" and "not connected" in r.note
    assert [c[1:3] for c in calls][-2:] == [["con", "mod"], ["con", "up"]]


def test_switch_without_live_is_the_old_reconnect(state):
    r = applier.switch_static("172.18.40.9", 21, "gw", ["8.8.8.8"], target=tgt(), live=False)
    assert r.mode == "reconnect" and r.note == "" and [c[1:3] for c in state] == [["con", "mod"], ["con", "up"]]


def test_switch_live_dry_run_prints_without_verifying(state, capsys):
    r = applier.switch_static("172.18.40.9", 21, "gw", ["8.8.8.8"], target=tgt(), live=True, dry_run=True)
    assert r.mode == "live" and state == [] and "[dry-run] nmcli device modify wlan0" in capsys.readouterr().out


def test_switch_without_a_device_cannot_go_live(state):
    r = applier.switch_static("172.18.40.9", 21, "gw", [], target=applier.Target("Dorm", ""), live=True)
    assert r.mode == "reconnect"


def test_restore_can_keep_the_backup(state):
    path = applier.backup_profile(profile())
    applier.restore(keep_backup=True)
    assert path.exists()
    applier.restore()
    assert not path.exists()


# ---- several addresses at once (parallel triage)
def test_apply_live_many_sets_all_addresses_first_one_primary(state):
    applier.apply_live_many(["172.18.40.1", "172.18.40.2", "172.18.40.3"], 21, "172.18.47.254", ["8.8.8.8"], device="wlan0")
    cmd = state[0]
    assert cmd[1:4] == ["device", "modify", "wlan0"]
    assert cmd[cmd.index("ipv4.addresses") + 1] == "172.18.40.1/21,172.18.40.2/21,172.18.40.3/21"
    assert len(state) == 1  # one command, no reconnect


def test_switch_many_verifies_the_whole_set(state, monkeypatch):
    fake_nmcli(monkeypatch, lambda: "IP4.ADDRESS[1]:172.18.40.2/21\nIP4.ADDRESS[2]:172.18.40.1/21\n")
    c = Clock()
    r = applier.switch_many(["172.18.40.1", "172.18.40.2"], 21, "gw", [], target=tgt(), sleep=c.sleep, clock=c.now)
    assert r.mode == "live"  # order does not matter


def test_switch_many_reports_missing_addresses_without_reconnecting(state, monkeypatch):
    fake_nmcli(monkeypatch, lambda: "IP4.ADDRESS[1]:172.18.40.1/21\n")
    c = Clock()
    r = applier.switch_many(["172.18.40.1", "172.18.40.2"], 21, "gw", [], target=tgt(), sleep=c.sleep, clock=c.now)
    assert r.mode == "unsupported" and "did not appear" in r.note
    assert not any(cmd[1:3] == ["con", "up"] for cmd in state)  # there is no reconnect fallback for this


def test_switch_many_handles_nmcli_errors_and_no_device(monkeypatch):
    def refuse(cmd, timeout=30):
        raise netinfo.NetError("not connected")

    monkeypatch.setattr(netinfo, "run", refuse)
    assert applier.switch_many(["172.18.40.1"], 21, "gw", [], target=tgt()).mode == "unsupported"
    assert applier.switch_many(["172.18.40.1"], 21, "gw", [], target=applier.Target("Dorm", "")).mode == "unsupported"
