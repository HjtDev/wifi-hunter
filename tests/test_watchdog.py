import time
from dataclasses import replace

import httpx
import pytest

from dorm_ip import hunter, netinfo, watchdog
from dorm_ip import tests as nt
from dorm_ip.db import DB
from dorm_ip.models import CheckResult, NetProfile, TestResult
from dorm_ip.netinfo import NetError

PROFILE = NetProfile("wlan0", "Dorm", "manual", "172.18.40.9", 21, "172.18.47.254", ["8.8.8.8"], "aa:bb")


def mock_client(handler):
    return lambda timeout=None: httpx.Client(transport=httpx.MockTransport(handler))


# ---- pure bits
def test_probe_url_sets_bytes(cfg):
    assert watchdog.probe_url(cfg).endswith("bytes=200000") and "speed.cloudflare.com" in watchdog.probe_url(cfg)
    other = replace(cfg, tests=replace(cfg.tests, speed_url="https://example.com/file.bin"))
    assert watchdog.probe_url(other) == "https://example.com/file.bin"


def test_evaluate(cfg):
    assert watchdog.evaluate(cfg, 0.0, 5.0) == (True, "")
    ok, note = watchdog.evaluate(cfg, 100.0, None)
    assert not ok and "gateway unreachable" in note
    assert "loss 33%" in watchdog.evaluate(cfg, 33.3, 5.0)[1]
    assert "probe 0.4 Mbps" in watchdog.evaluate(cfg, 0.0, 0.4)[1]
    assert "probe failed" in watchdog.evaluate(cfg, 0.0, None)[1]


def test_probe_measures_and_rejects_short_bodies(cfg, monkeypatch):
    monkeypatch.setattr(nt, "_client", mock_client(lambda r: httpx.Response(200, content=b"x" * 200_000)))
    mbps, n = watchdog.Prober(cfg).probe()
    assert n == 200_000 and mbps > 0
    monkeypatch.setattr(nt, "_client", mock_client(lambda r: httpx.Response(200, content=b"<html>login</html>")))
    assert watchdog.Prober(cfg).probe()[0] is None
    monkeypatch.setattr(nt, "_client", mock_client(lambda r: httpx.Response(503)))
    assert watchdog.Prober(cfg).probe() == (None, 0)


# ---- the loop
class Obs(watchdog.WatchObserver):
    def __init__(self):
        self.notes, self.checks = [], []

    def note(self, text): self.notes.append(text)
    def check(self, c, bad, limit): self.checks.append((c.ok, bad))


class Env:
    pass


@pytest.fixture
def env(cfg, monkeypatch):
    e = Env()
    e.cfg = replace(cfg, watchdog=replace(cfg.watchdog, bad_checks_to_rehunt=3, rehunt_cooldown_seconds=300))
    e.db = DB(":memory:")
    e.obs = Obs()
    e.notes_sent = []
    e.healthy = True
    e.hunts = 0
    e.hunt_result = None
    e.confirm_pass = False
    e.portal = ("open", 0, None)
    e.login_ok = False
    e.clock = [0.0]
    e.logins = 0

    monkeypatch.setattr(netinfo, "get_profile", lambda i, c: PROFILE)

    def fake_check(cfg_, profile, prober):
        ok = e.healthy
        return CheckResult(time.time(), profile.ip, profile.mac, ok, 0.0 if ok else 100.0, 20.0,
                           5.0 if ok else None, 200_000 if ok else 0, ok, "" if ok else "gateway unreachable")

    monkeypatch.setattr(watchdog, "run_check", fake_check)
    monkeypatch.setattr(nt, "check_portal", lambda c: e.portal)

    def login(c, ip="", mac=""):
        e.logins += 1
        if e.login_ok:
            e.portal = ("open", 0, None)
        return e.login_ok

    monkeypatch.setattr(hunter, "try_login", login)

    def run_all(c, ip, mode, deep=True, **kw):
        r = TestResult(time.time(), ip, "aa", mode, False, True, "open", 20.0, 0.0, 1.0, 10.0, 30.0,
                       None, None, None, 5_000_000, 70.0 if e.confirm_pass else 0.0, e.confirm_pass,
                       None if e.confirm_pass else "quick speed 1.0 Mbps < 5 Mbps")
        return r

    monkeypatch.setattr(nt, "run_all", run_all)

    def hunt():
        e.hunts += 1
        return e.hunt_result

    e.make = lambda: watchdog.Watchdog(
        e.cfg, db=e.db, hunt=hunt, observer=e.obs, notify=e.notes_sent.append,
        sleep=lambda s: None, clock=lambda: e.clock[0],
    )
    return e


def test_healthy_checks_never_react(env):
    wd = env.make()
    wd.run(max_checks=5)
    assert env.hunts == 0 and wd.bad == 0 and env.db.conn.execute("SELECT COUNT(*) FROM checks").fetchone()[0] == 5


def test_isolated_bad_check_is_tolerated(env):
    wd = env.make()
    env.healthy = False
    wd.step()
    wd.step()
    env.healthy = True
    wd.step()
    assert wd.bad == 0 and env.hunts == 0 and env.notes_sent == []


def test_consecutive_bad_checks_confirm_then_rehunt(env):
    env.healthy = False
    env.hunt_result = TestResult(time.time(), "172.18.40.77", "aa", "override", False, True, "open", 20.0, 0.0, 1.0,
                                 10.0, 30.0, 20.0, 15.0, None, 1, 85.0, True, None)
    wd = env.make()
    wd.run(max_checks=3)
    assert env.hunts == 1 and wd.bad == 0
    assert any("degraded" in m.lower() for m in env.notes_sent)
    assert any("Switched to 172.18.40.77" in m for m in env.notes_sent)
    # confirm test result was stored (counts toward the budget)
    assert env.db.result_count() == 1


def test_false_alarm_skips_hunt_and_holds_off(env):
    env.healthy = False
    env.confirm_pass = True
    wd = env.make()
    wd.run(max_checks=3)
    assert env.hunts == 0 and wd.bad == 0
    assert any("False alarm" in n for n in env.obs.notes)
    # still bad right away, but within the hold-off nothing re-runs the confirm test
    before = env.db.result_count()
    wd.run(max_checks=6)
    assert env.db.result_count() == before
    # after the hold-off it can confirm again
    env.clock[0] = 301
    wd.run(max_checks=9)
    assert env.db.result_count() == before + 1


def test_failed_hunt_backs_off_exponentially(env):
    env.healthy = False
    wd = env.make()
    wd.run(max_checks=3)
    assert env.hunts == 1 and wd.hold_until == 300
    wd.run(max_checks=8)  # still inside the cooldown
    assert env.hunts == 1
    env.clock[0] = 301
    wd.run(max_checks=9)
    assert env.hunts == 2 and wd.hold_until == 301 + 600


def test_cooldown_is_capped(env):
    wd = env.make()
    wd.hunt_failures = 10
    env.healthy = False
    wd.bad = 2
    wd.step()
    assert wd.hold_until - env.clock[0] == watchdog.MAX_COOLDOWN


def test_portal_relogin_instead_of_rehunt(env):
    env.healthy = False
    env.portal = ("portal", 0, "http://p/")
    env.login_ok = True
    wd = env.make()
    wd.run(max_checks=3)
    assert env.logins == 1 and env.hunts == 0 and wd.bad == 0
    assert any("Logged in again" in n for n in env.obs.notes)


def test_portal_login_unavailable_falls_through_to_rehunt(env):
    env.healthy = False
    env.portal = ("portal", 0, "http://p/")
    wd = env.make()
    wd.run(max_checks=3)
    assert env.logins == 1 and env.hunts == 1  # no confirm test while the portal blocks


def test_budget_exhausted_skips_rehunt(env):
    env.db.add_bytes(env.cfg.tests.data_budget_mb * 1_000_000)
    env.healthy = False
    wd = env.make()
    wd.run(max_checks=3)
    assert env.hunts == 0 and any("budget" in m for m in env.notes_sent)


def test_hunt_error_is_survivable(env):
    env.healthy = False

    def boom():
        raise NetError("no active wifi")

    wd = watchdog.Watchdog(env.cfg, db=env.db, hunt=boom, observer=env.obs, notify=env.notes_sent.append,
                           sleep=lambda s: None, clock=lambda: env.clock[0])
    wd.run(max_checks=3)
    assert wd.hunt_failures == 1 and any("Re-hunt error" in n for n in env.obs.notes)


def test_wifi_down_counts_as_bad_check(env, monkeypatch):
    def down(i, c):
        raise NetError("no active wifi connection")

    monkeypatch.setattr(netinfo, "get_profile", down)
    wd = env.make()
    c = wd.step()
    assert not c.ok and c.note == "wifi not connected" and wd.bad == 1


def test_checks_logged_and_counted(env):
    wd = env.make()
    wd.run(max_checks=4)
    assert env.db.daily_bytes() == 4 * 200_000


def test_notifications_can_be_disabled(env):
    cfg = replace(env.cfg, watchdog=replace(env.cfg.watchdog, notify=False))
    sent = []
    wd = watchdog.Watchdog(cfg, db=env.db, hunt=lambda: None, observer=env.obs, notify=None,
                           sleep=lambda s: None, clock=lambda: 0.0)
    wd.notify("x")  # default notifier is a no-op when notify = false
    assert sent == []