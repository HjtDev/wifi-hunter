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
    return lambda timeout=None, source=None: httpx.Client(transport=httpx.MockTransport(handler))


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

    e.probe_flags = []
    e.tunnel = None
    e.busy_bytes = None
    e.wall = [1000.0]
    e.slow_probe = False

    def fake_check(cfg_, profile, prober, probe=True):
        e.probe_flags.append(probe)
        if e.slow_probe:
            return CheckResult(time.time(), profile.ip, profile.mac, True, 0.0, 20.0, 0.4, 200_000, False, "probe 0.4 Mbps")
        ok = e.healthy
        return CheckResult(time.time(), profile.ip, profile.mac, ok, 0.0 if ok else 100.0, 20.0,
                           5.0 if ok and probe else None, 200_000 if ok and probe else 0, ok, "" if ok else "gateway unreachable")

    monkeypatch.setattr(netinfo, "tunnel_device", lambda i: e.tunnel)
    monkeypatch.setattr(netinfo, "iface_bytes", lambda d: e.busy_bytes)

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
        sleep=lambda s: None, clock=lambda: e.clock[0], wall=lambda: e.wall[0],
    )
    return e


def test_healthy_checks_never_react(env):
    wd = env.make()
    wd.run(max_steps=5)
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
    wd.run(max_steps=3)
    assert env.hunts == 1 and wd.bad == 0
    assert any("degraded" in m.lower() for m in env.notes_sent)
    assert any("Switched to 172.18.40.77" in m for m in env.notes_sent)
    # confirm test result was stored (counts toward the budget)
    assert env.db.result_count() == 1


def test_false_alarm_skips_hunt_and_holds_off(env):
    env.healthy = False
    env.confirm_pass = True
    wd = env.make()
    wd.run(max_steps=3)
    assert env.hunts == 0 and wd.bad == 0
    assert any("False alarm" in n for n in env.obs.notes)
    # still bad right away, but within the hold-off nothing re-runs the confirm test
    before = env.db.result_count()
    wd.run(max_steps=6)
    assert env.db.result_count() == before
    # after the hold-off it can confirm again
    env.clock[0] = 301
    wd.run(max_steps=9)
    assert env.db.result_count() == before + 1


def test_failed_hunt_backs_off_exponentially(env):
    env.healthy = False
    wd = env.make()
    wd.run(max_steps=3)
    assert env.hunts == 1 and wd.hold_until == 300
    wd.run(max_steps=8)  # still inside the cooldown
    assert env.hunts == 1
    env.clock[0] = 301
    wd.run(max_steps=9)
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
    wd.run(max_steps=3)
    assert env.logins == 1 and env.hunts == 0 and wd.bad == 0
    assert any("Logged in again" in n for n in env.obs.notes)


def test_portal_login_unavailable_falls_through_to_rehunt(env):
    env.healthy = False
    env.portal = ("portal", 0, "http://p/")
    wd = env.make()
    wd.run(max_steps=3)
    assert env.logins == 1 and env.hunts == 1  # no confirm test while the portal blocks


def test_budget_exhausted_skips_rehunt(env):
    env.db.add_bytes(env.cfg.tests.data_budget_mb * 1_000_000)
    env.healthy = False
    wd = env.make()
    wd.run(max_steps=3)
    assert env.hunts == 0 and any("budget" in m for m in env.notes_sent)


def test_hunt_error_is_survivable(env):
    env.healthy = False

    def boom():
        raise NetError("no active wifi")

    wd = watchdog.Watchdog(env.cfg, db=env.db, hunt=boom, observer=env.obs, notify=env.notes_sent.append,
                           sleep=lambda s: None, clock=lambda: env.clock[0], wall=lambda: env.wall[0])
    wd.run(max_steps=3)
    assert wd.hunt_failures == 1 and any("Re-hunt error" in n for n in env.obs.notes)


def test_wifi_down_pauses_instead_of_counting(env, monkeypatch):
    def down(i, c):
        raise NetError("no active wifi connection")

    monkeypatch.setattr(netinfo, "get_profile", down)
    wd = env.make()
    for _ in range(6):
        assert wd.step() is None
    assert wd.bad == 0 and env.hunts == 0 and env.db.conn.execute("SELECT COUNT(*) FROM checks").fetchone()[0] == 0
    assert sum("Paused" in n for n in env.obs.notes) == 1  # announced once, not every check


def test_other_network_never_triggers_rehunt(env, monkeypatch):
    other = NetProfile("wlan0", "HomeWifi", "auto", "192.168.1.20", 24, "192.168.1.1", ["1.1.1.1"], "aa")
    monkeypatch.setattr(netinfo, "get_profile", lambda i, c: other)
    env.healthy = False
    wd = env.make()
    wd.run(max_steps=8)
    assert env.hunts == 0 and wd.bad == 0 and any("does not look like the dorm wifi" in n for n in env.obs.notes)


def test_resumes_when_back_on_dorm_wifi(env, monkeypatch):
    seq = [None, PROFILE]

    def prof(i, c):
        p = seq[0] if len(seq) > 1 else seq[0]
        if p is None:
            raise NetError("no wifi")
        return p

    monkeypatch.setattr(netinfo, "get_profile", prof)
    wd = env.make()
    wd.step()
    seq.pop(0)
    wd.step()
    assert any("Resumed: connected" in n for n in env.obs.notes) and wd.checks == 1


def test_vpn_means_gateway_only_and_no_rehunt(env):
    env.tunnel = "tun0"
    wd = env.make()
    wd.run(max_steps=3)
    assert env.probe_flags == [False, False, False]
    assert any("VPN" in n for n in env.obs.notes)
    # now the gateway really dies while the VPN is up: notify, but never re-hunt
    env.healthy = False
    wd.run(max_steps=8)
    assert env.hunts == 0 and any("not re-hunting" in n for n in env.obs.notes)


def test_vpn_gone_resumes_full_checks(env):
    env.tunnel = "wg0"
    wd = env.make()
    wd.step()
    env.tunnel = None
    wd.step()
    assert env.probe_flags == [False, True] and any("VPN/tunnel is gone" in n for n in env.obs.notes)


def test_suspend_resume_gets_a_grace_period(env):
    wd = env.make()
    wd.step()
    env.healthy = False
    env.wall[0] += 3600  # laptop slept for an hour
    for _ in range(3):  # 3 x 15 s, all inside the 60 s grace period
        env.wall[0] += 15
        wd.step()
    assert env.hunts == 0 and wd.bad == 0 and any("Resumed after" in n for n in env.obs.notes)
    # after the grace period real failures count again
    env.wall[0] += 30  # grace over, and a normal gap between checks
    wd.step()
    assert wd.bad == 1


def test_slow_probe_ignored_when_link_is_busy(env):
    wd = env.make()
    env.busy_bytes = 0
    wd.step()  # baseline counters
    env.slow_probe = True
    env.wall[0] += 30
    env.busy_bytes = 30 * 1_000_000  # ~8 Mbps of the user's own traffic over 30 s
    c = wd.step()
    assert c.ok and "link busy" in c.note and wd.bad == 0


def test_slow_probe_counts_when_link_is_idle(env):
    wd = env.make()
    env.busy_bytes = 0
    wd.step()
    env.slow_probe = True
    env.wall[0] += 30
    env.busy_bytes = 10_000
    assert not wd.step().ok and wd.bad == 1


def test_busy_rule_can_be_disabled(env):
    env.cfg = replace(env.cfg, watchdog=replace(env.cfg.watchdog, busy_mbps=0))
    wd = env.make()
    env.busy_bytes = 0
    wd.step()
    env.slow_probe = True
    env.wall[0] += 30
    env.busy_bytes = 50_000_000
    assert not wd.step().ok


def test_checks_logged_and_counted(env):
    wd = env.make()
    wd.run(max_steps=4)
    assert env.db.daily_bytes() == 4 * 200_000


def test_notifications_can_be_disabled(env):
    cfg = replace(env.cfg, watchdog=replace(env.cfg.watchdog, notify=False))
    sent = []
    wd = watchdog.Watchdog(cfg, db=env.db, hunt=lambda: None, observer=env.obs, notify=None,
                           sleep=lambda s: None, clock=lambda: 0.0)
    wd.notify("x")  # default notifier is a no-op when notify = false
    assert sent == []


# ---- standby failover (phase 2)
def make_with_failover(env, failover):
    return watchdog.Watchdog(
        env.cfg, db=env.db, hunt=lambda: (setattr(env, "hunts", env.hunts + 1) or env.hunt_result),
        failover=failover, observer=env.obs, notify=env.notes_sent.append,
        sleep=lambda s: None, clock=lambda: env.clock[0], wall=lambda: env.wall[0],
    )


def a_result(ip):
    return TestResult(time.time(), ip, "aa", "override", False, True, "open", 20.0, 0.0, 1.0, 10.0, 30.0,
                      None, None, None, 5_000_000, 70.0, True, None)


def test_standby_failover_replaces_the_hunt(env):
    env.healthy = False
    wd = make_with_failover(env, lambda: a_result("172.18.40.99"))
    wd.run(max_steps=3)
    assert env.hunts == 0 and wd.rehunts == 0 and wd.bad == 0
    assert any("standby IP 172.18.40.99" in n for n in env.obs.notes) and any("Switched to 172.18.40.99" in m for m in env.notes_sent)


def test_failover_without_a_working_standby_falls_back_to_the_hunt(env):
    env.healthy = False
    env.hunt_result = a_result("172.18.40.77")
    wd = make_with_failover(env, lambda: None)
    wd.run(max_steps=3)
    assert env.hunts == 1 and wd.rehunts == 1 and any("Trying standby IPs first" in n for n in env.obs.notes)


def test_failover_errors_do_not_stop_the_watchdog(env):
    env.healthy = False

    def boom():
        raise NetError("no wifi")

    wd = make_with_failover(env, boom)
    wd.run(max_steps=3)
    assert env.hunts == 1 and any("Standby failover error" in n for n in env.obs.notes)


def test_no_failover_function_means_the_old_behavior(env):
    env.healthy = False
    wd = make_with_failover(env, None)
    wd.run(max_steps=3)
    assert env.hunts == 1 and not any("standby" in n.lower() for n in env.obs.notes)


def test_failover_is_not_tried_during_a_vpn(env):
    env.tunnel = "tun0"
    env.healthy = False
    called = []
    wd = make_with_failover(env, lambda: called.append(1))
    wd.run(max_steps=6)
    assert called == [] and env.hunts == 0
