import os
import random
import signal
import time
from dataclasses import replace

import pytest

from dorm_ip import applier, hunter, netinfo, scanner
from dorm_ip import tests as nt
from dorm_ip.models import TestResult
from dorm_ip.netinfo import NetError


def result(ip, passed=False, reason="quick speed 1.0 Mbps < 5 Mbps", bytes_used=1_000_000, portal="open"):
    return TestResult(
        ts=time.time(), ip=ip, mac="aa", dns_mode="override", seen_in_use=False, gateway_ok=True,
        portal_state=portal, ping_avg_ms=20.0, ping_loss_pct=0.0, ping_jitter_ms=1.0, dns_ms=10.0,
        quick_mbps=30.0, sustained_avg_mbps=25.0, sustained_min_mbps=20.0, collapse_after_mb=None,
        bytes_used=bytes_used, score=80.0 if passed else 0.0, passed=passed,
        fail_reason=None if passed else reason,
    )


class Rec(hunter.HuntObserver):
    def __init__(self):
        self.events = []
        self.final = None

    def note(self, text): self.events.append(("note", text))
    def scanned(self, used, candidates): self.events.append(("scanned", len(used), len(candidates)))
    def trying(self, ip, index, total): self.events.append(("trying", ip))
    def skipped(self, ip, why): self.events.append(("skipped", ip))
    def result(self, r): self.events.append(("result", r.ip, r.passed))
    def finalized(self, f): self.final = f


class FakeTime:
    """sleep() advances a fake clock, so waiting loops finish instantly."""

    def __init__(self):
        self.now = 0.0
        self.slept = []

    def sleep(self, s):
        self.slept.append(s)
        self.now += s

    def clock(self):
        return self.now


FT = FakeTime()


@pytest.fixture
def env(cfg, monkeypatch):
    """Stub every side effect; record applier calls."""
    FT.now, FT.slept = 0.0, []
    log = {"apply": [], "dns": [], "restore": 0, "tested": [], "saved": [], "persist": [], "mode": "reconnect",
           "gateway": True, "gw_args": []}
    cfg = replace(cfg, hunt=replace(cfg.hunt, max_candidates=5, order="sequential"))
    monkeypatch.setattr(applier, "begin_change", lambda i, c, dry_run=False, notify=None: applier.Target("Dorm", "wlan0"))
    def switch(ip, prefix, gw, dns, *, target, live, dry_run=False, sleep=None, clock=None):
        log["apply"].append((ip, tuple(dns)))
        log.setdefault("live_flags", []).append(live)
        mode = log["mode"] if live else "reconnect"
        if live and log["mode"] == "reconnect":
            return applier.SwitchResult("reconnect", "live IP switching is not working here (test)")
        return applier.SwitchResult(mode)

    monkeypatch.setattr(applier, "switch_static", switch)
    monkeypatch.setattr(applier, "persist_static", lambda ip, prefix, gw, dns, *, connection, dry_run=False: log["persist"].append(ip))
    monkeypatch.setattr(nt, "ping", lambda t, n, wait=2: (20.0, 0.0 if log["gateway"] else 100.0, 1.0))
    monkeypatch.setattr(applier, "set_dns", lambda dns, *, connection, dry_run=False: log["dns"].append(tuple(dns)))
    monkeypatch.setattr(applier, "restore", lambda dry_run=False: log.__setitem__("restore", log["restore"] + 1) or "Dorm")
    monkeypatch.setattr(scanner, "scan_used", lambda cfg, iface=None, dry_run=False: set())
    monkeypatch.setattr(netinfo, "read_mac", lambda d: "aa:bb")
    monkeypatch.setattr(nt, "check_portal", lambda c: ("open", 0, None))
    log["cfg"] = cfg

    def set_tests(fn):
        def run_all(c, ip, mode, deep=True, **kw):
            log["tested"].append(ip)
            log["gw_args"].append(kw.get("gateway_ok"))
            return fn(ip)
        monkeypatch.setattr(nt, "run_all", run_all)

    log["set_tests"] = set_tests
    return log


NOSLEEP = dict(sleep=FT.sleep, clock=FT.clock)


def test_stops_at_first_pass_and_keeps_ip(env):
    env["set_tests"](lambda ip: result(ip, passed=(ip == "172.18.40.3")))
    obs = Rec()
    r = hunter.hunt(env["cfg"], observer=obs, **NOSLEEP)
    assert r.ip == "172.18.40.3"
    assert env["tested"] == ["172.18.40.1", "172.18.40.2", "172.18.40.3"]
    assert env["restore"] == 0
    assert obs.final.portal_state == "open"


def test_uses_override_dns_while_hunting(env):
    env["set_tests"](lambda ip: result(ip, passed=True))
    hunter.hunt(env["cfg"], **NOSLEEP)
    assert env["apply"][0][1] == ("8.8.8.8",)


def test_none_pass_restores_backup(env):
    env["set_tests"](lambda ip: result(ip))
    assert hunter.hunt(env["cfg"], observer=Rec(), **NOSLEEP) is None
    assert len(env["tested"]) == 5 and env["restore"] == 1


def test_save_called_for_every_result(env):
    env["set_tests"](lambda ip: result(ip))
    saved = []
    hunter.hunt(env["cfg"], save=saved.append, **NOSLEEP)
    assert len(saved) == 5


def test_unused_tried_first(env, monkeypatch):
    monkeypatch.setattr(scanner, "scan_used", lambda cfg, iface=None, dry_run=False: {"172.18.40.1", "172.18.40.2"})
    env["set_tests"](lambda ip: result(ip))
    hunter.hunt(env["cfg"], **NOSLEEP)
    assert env["tested"] == ["172.18.40.3", "172.18.40.4", "172.18.40.5", "172.18.40.6", "172.18.40.7"]


def test_seen_in_use_flag_is_passed(cfg, env, monkeypatch):
    seen = []
    monkeypatch.setattr(scanner, "scan_used", lambda cfg, iface=None, dry_run=False: {"172.18.40.1"})

    def run_all(c, ip, mode, deep=True, *, seen_in_use=False, **kw):
        seen.append((ip, seen_in_use))
        return result(ip, passed=True)

    monkeypatch.setattr(nt, "run_all", run_all)
    c = replace(env["cfg"], network=replace(env["cfg"].network, prefer_unused=False))
    hunter.hunt(c, **NOSLEEP)
    assert seen[0] == ("172.18.40.1", True)


def test_budget_stops_hunt(env):
    c = replace(env["cfg"], tests=replace(env["cfg"].tests, data_budget_mb=2))
    env["set_tests"](lambda ip: result(ip, bytes_used=1_500_000))
    obs = Rec()
    assert hunter.hunt(c, observer=obs, **NOSLEEP) is None
    assert env["tested"] == ["172.18.40.1", "172.18.40.2"] and env["restore"] == 1
    assert any(e[0] == "note" and "budget" in e[1] for e in obs.events)


def test_budget_already_spent_tests_nothing(env):
    env["set_tests"](lambda ip: result(ip))
    c = replace(env["cfg"], tests=replace(env["cfg"].tests, data_budget_mb=1))
    assert hunter.hunt(c, spent=lambda: 5_000_000, **NOSLEEP) is None
    assert env["tested"] == [] and env["restore"] == 1


def test_ctrl_c_restores_and_reraises(env):
    def boom(ip):
        raise KeyboardInterrupt

    env["set_tests"](boom)
    with pytest.raises(KeyboardInterrupt):
        hunter.hunt(env["cfg"], **NOSLEEP)
    assert env["restore"] == 1


def test_sigterm_restores(env):
    def term(ip):
        os.kill(os.getpid(), signal.SIGTERM)
        time.sleep(0.5)
        return result(ip)

    env["set_tests"](term)
    old = signal.getsignal(signal.SIGTERM)
    with pytest.raises(KeyboardInterrupt):
        hunter.hunt(env["cfg"], **NOSLEEP)
    assert env["restore"] == 1 and signal.getsignal(signal.SIGTERM) == old


def test_unexpected_error_restores(env):
    def boom(ip):
        raise RuntimeError("bug")

    env["set_tests"](boom)
    with pytest.raises(RuntimeError):
        hunter.hunt(env["cfg"], **NOSLEEP)
    assert env["restore"] == 1


def test_three_apply_failures_abort_and_restore(env, monkeypatch):
    def bad(ip, prefix, gw, dns, *, target, live, dry_run=False, sleep=None, clock=None):
        raise NetError("activation failed")

    monkeypatch.setattr(applier, "switch_static", bad)
    env["set_tests"](lambda ip: result(ip))
    obs = Rec()
    with pytest.raises(NetError, match="consecutive"):
        hunter.hunt(env["cfg"], observer=obs, **NOSLEEP)
    assert env["restore"] == 1 and env["tested"] == []
    assert [e for e in obs.events if e[0] == "skipped"].__len__() == 3


def test_dead_ip_is_recorded_without_running_the_tests(env, monkeypatch):
    env["gateway"] = False
    monkeypatch.setattr(nt, "run_all", lambda c, ip, mode, deep=True, **kw: (env["tested"].append(ip), env["gw_args"].append(kw["gateway_ok"]), result(ip, reason="gateway unreachable"))[2])
    assert hunter.hunt(env["cfg"], **NOSLEEP) is None
    assert env["gw_args"] == [False] * 5 and env["restore"] == 1  # run_all told: gateway is down, skip pinging again


def test_readiness_wait_is_polled_not_fixed(env):
    env["set_tests"](lambda ip: result(ip, passed=True))
    hunter.hunt(env["cfg"], **NOSLEEP)
    assert FT.slept == []  # gateway answered at once: no waiting at all
    assert env["gw_args"] == [True]


def test_reconnect_waits_longer_than_live(env, monkeypatch):
    env["gateway"] = False
    env["set_tests"](lambda ip: result(ip))
    hunter.hunt(replace(env["cfg"], hunt=replace(env["cfg"].hunt, max_candidates=1, live_change="off")), **NOSLEEP)
    reconnect_wait = FT.now
    FT.now, FT.slept = 0.0, []
    env["mode"] = "live"
    hunter.hunt(replace(env["cfg"], hunt=replace(env["cfg"].hunt, max_candidates=1)), **NOSLEEP)
    assert reconnect_wait >= 8.0 and FT.now < reconnect_wait


def test_dry_run_changes_nothing(env, monkeypatch, capsys):
    env["set_tests"](lambda ip: result(ip, passed=True))
    assert hunter.hunt(env["cfg"], dry_run=True, **NOSLEEP) is None
    assert env["tested"] == [] and env["restore"] == 0
    assert len(env["apply"]) == hunter.DRY_RUN_CANDIDATES


# ---- live IP switching
def test_live_switching_used_and_winner_persisted(env):
    env["mode"] = "live"
    env["set_tests"](lambda ip: result(ip, passed=(ip == "172.18.40.2")))
    obs = Rec()
    r = hunter.hunt(env["cfg"], observer=obs, **NOSLEEP)
    assert r.ip == "172.18.40.2" and env["live_flags"] == [True, True]
    assert env["persist"] == ["172.18.40.2"]  # only the winner is written to the saved profile
    assert any("Live IP switching works" in e[1] for e in obs.events if e[0] == "note")


def test_live_failure_falls_back_for_the_rest_of_the_run(env):
    env["mode"] = "reconnect"  # live attempt reports "not working"
    env["set_tests"](lambda ip: result(ip))
    obs = Rec()
    hunter.hunt(env["cfg"], observer=obs, **NOSLEEP)
    assert env["live_flags"] == [True, False, False, False, False]  # tried once, then never again
    assert sum("not working here" in e[1] for e in obs.events if e[0] == "note") == 1
    assert env["persist"] == []


def test_live_change_off_never_tries_live(env):
    env["mode"] = "live"
    env["set_tests"](lambda ip: result(ip, passed=True))
    hunter.hunt(replace(env["cfg"], hunt=replace(env["cfg"].hunt, live_change="off")), **NOSLEEP)
    assert env["live_flags"] == [False] and env["persist"] == []


def test_reconnect_winner_is_not_persisted_again(env):
    env["set_tests"](lambda ip: result(ip, passed=True))
    hunter.hunt(env["cfg"], **NOSLEEP)
    assert env["persist"] == []  # the reconnect path already saved the profile


# ---- smart ordering inputs
def test_recently_failed_ips_are_skipped_and_reported(env):
    from dorm_ip.db import Ranking

    env["set_tests"](lambda ip: result(ip))
    obs = Rec()
    rk = Ranking(skip={"172.18.40.1": 10.0, "172.18.40.2": 5.0})
    hunter.hunt(env["cfg"], observer=obs, ranking=rk, **NOSLEEP)
    assert "172.18.40.1" not in env["tested"] and "172.18.40.2" not in env["tested"]
    assert any("Skipping 2 recently failed" in e[1] for e in obs.events if e[0] == "note")


def test_skipped_ips_are_used_when_nothing_else_is_left(env):
    from dorm_ip.db import Ranking

    env["set_tests"](lambda ip: result(ip))
    cfg = replace(env["cfg"], hunt=replace(env["cfg"].hunt, max_candidates=30))
    rk = Ranking(skip={ip: 10.0 for ip in cfg.ips})
    obs = Rec()
    hunter.hunt(cfg, observer=obs, ranking=rk, **NOSLEEP)
    assert len(env["tested"]) == 20 and any("Not enough other candidates" in e[1] for e in obs.events if e[0] == "note")


def test_scans_are_reported_to_the_history_hook(env, monkeypatch):
    monkeypatch.setattr(scanner, "scan_used", lambda cfg, iface=None, dry_run=False: {"172.18.40.9"})
    env["set_tests"](lambda ip: result(ip, passed=True))
    seen = []
    hunter.hunt(env["cfg"], on_scan=seen.append, **NOSLEEP)
    assert seen == [{"172.18.40.9"}]


# ---- finalize (DNS override / portal logic)
def fin(env, mode, tested_with="override", portals=(), login=False, monkeypatch=None):
    cfg = env["cfg"]
    cfg = replace(cfg, dns=replace(cfg.dns, final_mode=mode))
    queue = list(portals)
    monkeypatch.setattr(nt, "check_portal", lambda c: queue.pop(0))
    monkeypatch.setattr(hunter, "try_login", lambda c, ip="", mac="": login)
    r = result("172.18.40.9", passed=True)
    r.dns_mode = tested_with
    return hunter.finalize(cfg, r, applier.Target("Dorm", "wlan0"), sleep=lambda s: None)


def test_final_override_keeps_override(env, monkeypatch):
    f = fin(env, "override", monkeypatch=monkeypatch)
    assert (f.dns_mode, f.portal_state) == ("override", "open") and env["dns"] == []


def test_final_default_switches_and_checks(env, monkeypatch):
    f = fin(env, "default", portals=[("open", 0, None)], monkeypatch=monkeypatch)
    assert f.dns_mode == "default" and f.portal_state == "open"
    assert env["dns"] == [("172.18.32.1",)]


def test_final_default_portal_means_login_required(env, monkeypatch):
    f = fin(env, "default", portals=[("portal", 0, "http://portal.local/login")], monkeypatch=monkeypatch)
    assert f.portal_state == "portal" and f.portal_url == "http://portal.local/login"


def test_final_portal_without_location_falls_back_to_connectivity_url(env, monkeypatch):
    f = fin(env, "default", portals=[("portal", 0, None)], monkeypatch=monkeypatch)
    assert f.portal_url == env["cfg"].tests.connectivity_url


def test_auto_stays_on_override_when_open(env, monkeypatch):
    f = fin(env, "auto", monkeypatch=monkeypatch)
    assert f.dns_mode == "override" and env["dns"] == []


def test_auto_falls_back_to_default_when_override_not_open(env, monkeypatch):
    # tested with default DNS -> auto tries override first, portal shows, so back to default
    f = fin(env, "auto", tested_with="default",
            portals=[("portal", 0, None), ("open", 0, None)], monkeypatch=monkeypatch)
    assert f.dns_mode == "default" and f.portal_state == "open"
    assert env["dns"] == [("8.8.8.8",), ("172.18.32.1",)]


def test_auto_reports_login_needed_if_neither_works(env, monkeypatch):
    f = fin(env, "auto", tested_with="default",
            portals=[("portal", 0, None), ("portal", 0, "http://p/")], monkeypatch=monkeypatch)
    assert f.dns_mode == "default" and f.portal_state == "portal"


def test_login_hook_can_resolve_portal(env, monkeypatch):
    f = fin(env, "default", portals=[("portal", 0, None), ("open", 0, None)], login=True, monkeypatch=monkeypatch)
    assert f.portal_state == "open" and f.portal_url is None


# ---- auto-login inside the hunt, and settle_portal (used by `dorm-ip set`)
def portal_cfg(env, **kw):
    cfg = env["cfg"]
    return replace(cfg, portal=replace(cfg.portal, enabled=True, url="http://p/login", login_during_hunt=True, **kw))


def test_hunt_logs_in_on_portal_candidates(env, monkeypatch):
    logins = []
    monkeypatch.setattr(hunter, "_login", lambda c, ip="", mac="": logins.append(ip) or (True, "HTTP 200"))
    hooks = []

    def run_all(c, ip, mode, deep=True, *, on_portal=None, **kw):
        hooks.append(on_portal)
        if on_portal and ip == "172.18.40.1":
            on_portal()
        return result(ip, passed=(ip == "172.18.40.2"))

    monkeypatch.setattr(nt, "run_all", run_all)
    hunter.hunt(portal_cfg(env), **NOSLEEP)
    assert logins == ["172.18.40.1"] and all(h is not None for h in hooks)


def test_login_hook_absent_when_disabled(env, monkeypatch):
    seen = []
    monkeypatch.setattr(nt, "run_all", lambda c, ip, mode, deep=True, *, on_portal=None, **kw: seen.append(on_portal) or result(ip, passed=True))
    hunter.hunt(env["cfg"], **NOSLEEP)  # portal.enabled is false in the fixture config
    assert seen == [None]


def test_login_stops_after_repeated_failures(env, monkeypatch):
    attempts = []
    monkeypatch.setattr(hunter, "_login", lambda c, ip="", mac="": attempts.append(ip) or (False, "portal rejected the login"))

    def run_all(c, ip, mode, deep=True, *, on_portal=None, **kw):
        if on_portal:
            on_portal()
        return result(ip, reason="captive portal: login required")

    monkeypatch.setattr(nt, "run_all", run_all)
    obs = Rec()
    hunter.hunt(portal_cfg(env), observer=obs, **NOSLEEP)
    assert len(attempts) == hunter.MAX_LOGIN_FAILURES  # protects the account from lock-outs
    assert any("not trying again" in e[1] for e in obs.events if e[0] == "note")


def test_login_is_capped_per_hunt(env, monkeypatch):
    attempts = []
    monkeypatch.setattr(hunter, "_login", lambda c, ip="", mac="": attempts.append(ip) or (True, "HTTP 200"))

    def run_all(c, ip, mode, deep=True, *, on_portal=None, **kw):
        if on_portal:
            on_portal()
        return result(ip)

    monkeypatch.setattr(nt, "run_all", run_all)
    hunter.hunt(portal_cfg(env, max_logins_per_hunt=2), **NOSLEEP)
    assert len(attempts) == 2


def test_settle_portal_open_logged_in_and_waiting(env, monkeypatch):
    cfg = portal_cfg(env)
    monkeypatch.setattr(hunter, "_login", lambda c, ip="", mac="": (True, "HTTP 200"))
    states = iter([("dead", 0, None), ("portal", 0, "http://p/"), ("open", 0, None)])
    monkeypatch.setattr(nt, "check_portal", lambda c: next(states))
    st = hunter.settle_portal(cfg, "1.2.3.4", "aa", sleep=lambda s: None)
    assert (st.state, st.logged_in) == ("open", True)


def test_settle_portal_without_login_reports_url(env, monkeypatch):
    monkeypatch.setattr(nt, "check_portal", lambda c: ("portal", 0, None))
    st = hunter.settle_portal(env["cfg"], "1.2.3.4", "aa", sleep=lambda s: None)
    assert st.state == "portal" and not st.logged_in and st.url == env["cfg"].tests.connectivity_url
    assert "not enabled" in st.detail
    st2 = hunter.settle_portal(portal_cfg(env), "1.2.3.4", "aa", login=False, sleep=lambda s: None)
    assert "skipped" in st2.detail
