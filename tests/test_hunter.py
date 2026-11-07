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
    cfg = replace(cfg, hunt=replace(cfg.hunt, max_candidates=5, order="sequential", triage_batch=0))
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
            log.setdefault("deeps", []).append(deep)
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


# ---- parallel triage, --find, standby, failover (phase 2)
from dorm_ip import triage  # noqa: E402
from dorm_ip.models import NetProfile  # noqa: E402

CONTROL = "172.18.40.200"


@pytest.fixture
def tenv(env, monkeypatch):
    env["cfg"] = replace(env["cfg"], hunt=replace(env["cfg"].hunt, max_candidates=8, triage_batch=4))
    env["mode"] = "live"
    env.update(many=[], tri_fail={}, control_ok=True, many_mode="live", batches=[])
    monkeypatch.setattr(
        netinfo, "get_profile",
        lambda i, c: NetProfile("wlan0", "Dorm", "auto", CONTROL, 21, "172.18.47.254", ["172.18.32.1"], "aa:bb"),
    )

    def many(ips, prefix, gw, dns, *, target, sleep=None, clock=None):
        env["many"].append(list(ips))
        return applier.SwitchResult(env["many_mode"], "" if env["many_mode"] == "live" else "extra addresses did not appear")

    def run_triage(cfg, ips, *, control=None, login=None):
        env["batches"].append(list(ips))
        res = {ip: triage.TriageResult(ip, ip not in env["tri_fail"], env["tri_fail"].get(ip), gateway_ok=True) for ip in ips}
        return res, (triage.TriageResult(control, env["control_ok"]) if control else None)

    monkeypatch.setattr(applier, "switch_many", many)
    monkeypatch.setattr(triage, "run_triage", run_triage)
    return env


def ip(n):
    return f"172.18.40.{n}"


def test_triage_filters_and_only_survivors_get_the_full_test(tenv):
    tenv["tri_fail"] = {ip(1): "gateway unreachable", ip(2): "packet loss 40%", ip(3): "no internet: x"}
    tenv["set_tests"](lambda i: result(i, passed=True))
    saved = []
    r = hunter.hunt(tenv["cfg"], save=saved.append, **NOSLEEP)
    assert r.ip == ip(4) and tenv["tested"] == [ip(4)]
    assert tenv["many"] == [[CONTROL, ip(1), ip(2), ip(3), ip(4)]]  # own IP stays on as the control
    assert [(x.ip, x.fail_reason) for x in saved[:3]] == [
        (ip(1), "gateway unreachable"), (ip(2), "packet loss 40%"), (ip(3), "no internet: x")]  # failures reach the history
    assert tenv["persist"] == [ip(4)] and tenv["restore"] == 0


def test_survivors_are_tested_one_at_a_time_and_batches_follow(tenv):
    tenv["tri_fail"] = {ip(i): "x" for i in range(1, 5)}  # the whole first batch dies in triage
    tenv["set_tests"](lambda i: result(i, passed=(i == ip(6))))
    r = hunter.hunt(tenv["cfg"], **NOSLEEP)
    assert r.ip == ip(6) and tenv["batches"] == [[ip(i) for i in range(1, 5)], [ip(i) for i in range(5, 9)]]
    assert tenv["tested"] == [ip(5), ip(6)]


def test_batch_size_comes_from_the_config(tenv):
    tenv["cfg"] = replace(tenv["cfg"], hunt=replace(tenv["cfg"].hunt, triage_batch=3))
    tenv["set_tests"](lambda i: result(i))
    hunter.hunt(tenv["cfg"], **NOSLEEP)
    assert [len(b) for b in tenv["batches"]] == [3, 3, 2]


def test_nothing_passing_restores_the_profile(tenv):
    tenv["set_tests"](lambda i: result(i))
    assert hunter.hunt(tenv["cfg"], **NOSLEEP) is None and tenv["restore"] == 1


def test_control_ip_failing_disables_triage_and_requeues_the_batch(tenv):
    tenv["control_ok"] = False
    tenv["set_tests"](lambda i: result(i, passed=(i == ip(2))))
    obs = Rec()
    r = hunter.hunt(tenv["cfg"], observer=obs, **NOSLEEP)
    assert r.ip == ip(2) and tenv["tested"] == [ip(1), ip(2)]  # tested one by one, nothing was lost
    assert len(tenv["batches"]) == 1  # no second batch after giving up
    assert any("does not work here" in e[1] and "secondary address" in e[1] for e in obs.events if e[0] == "note")


def test_all_extra_addresses_dead_without_a_control_disables_triage(tenv, monkeypatch):
    monkeypatch.setattr(netinfo, "get_profile", lambda i, c: (_ for _ in ()).throw(netinfo.NetError("no wifi")))
    tenv["tri_fail"] = {ip(i): "gateway unreachable" for i in range(1, 5)}
    tenv["set_tests"](lambda i: result(i, passed=True))
    obs = Rec()
    r = hunter.hunt(tenv["cfg"], observer=obs, **NOSLEEP)
    assert r.ip == ip(1) and tenv["tested"] == [ip(1)]
    assert tenv["many"][0][0] == ip(1)  # no control: the first candidate is the primary address
    assert any("not one of the extra addresses" in e[1] for e in obs.events if e[0] == "note")


def test_unsupported_multi_address_falls_back_to_serial(tenv):
    tenv["many_mode"] = "unsupported"
    tenv["set_tests"](lambda i: result(i, passed=(i == ip(3))))
    obs = Rec()
    r = hunter.hunt(tenv["cfg"], observer=obs, **NOSLEEP)
    assert r.ip == ip(3) and tenv["tested"] == [ip(1), ip(2), ip(3)] and len(tenv["many"]) == 1
    assert any("testing one by one" in e[1] for e in obs.events if e[0] == "note")


def test_triage_is_off_without_live_switching(tenv):
    tenv["cfg"] = replace(tenv["cfg"], hunt=replace(tenv["cfg"].hunt, live_change="off"))
    tenv["set_tests"](lambda i: result(i, passed=True))
    hunter.hunt(tenv["cfg"], **NOSLEEP)
    assert tenv["many"] == [] and tenv["tested"] == [ip(1)]


def test_triage_is_off_with_batch_0_or_1_and_in_dry_run(tenv):
    for batch in (0, 1):
        tenv["many"].clear()
        tenv["set_tests"](lambda i: result(i, passed=True))
        hunter.hunt(replace(tenv["cfg"], hunt=replace(tenv["cfg"].hunt, triage_batch=batch)), **NOSLEEP)
        assert tenv["many"] == []
    hunter.hunt(tenv["cfg"], dry_run=True, **NOSLEEP)
    assert tenv["many"] == []


def scored(scores):
    def fn(i):
        r = result(i, passed=i in scores)
        if i in scores:
            r.score = scores[i]
        return r
    return fn


def test_find_collects_n_keeps_the_best_and_sends_the_rest_to_standby(tenv):
    tenv["set_tests"](scored({ip(1): 90.0, ip(2): 70.0, ip(3): 80.0}))
    standby = []
    obs = Rec()
    r = hunter.hunt(tenv["cfg"], find=2, on_standby=standby.extend, observer=obs, **NOSLEEP)
    assert r.ip == ip(1) and tenv["tested"] == [ip(1), ip(2)]  # stops after 2 passing IPs
    assert [w.ip for w in standby] == [ip(2)]
    assert tenv["persist"] == [ip(1)] and tenv["apply"][-1][0] == ip(1)  # switched back to the best
    assert any("2 of 2 requested" in e[1] for e in obs.events if e[0] == "note")


def test_find_switches_back_to_an_earlier_better_ip(tenv):
    tenv["set_tests"](scored({ip(1): 95.0, ip(2): 60.0}))
    r = hunter.hunt(tenv["cfg"], find=2, **NOSLEEP)
    assert r.ip == ip(1) and tenv["apply"][-1][0] == ip(1) and tenv["persist"] == [ip(1)]


def test_find_keeps_the_last_ip_without_switching_when_it_is_the_best(tenv):
    tenv["set_tests"](scored({ip(1): 60.0, ip(2): 95.0}))
    r = hunter.hunt(tenv["cfg"], find=2, **NOSLEEP)
    assert r.ip == ip(2) and tenv["persist"] == [ip(2)]
    assert [a[0] for a in tenv["apply"]].count(ip(2)) == 1  # no needless switch


def test_find_returns_what_it_has_when_fewer_pass(tenv):
    tenv["set_tests"](scored({ip(5): 75.0}))
    standby = []
    r = hunter.hunt(tenv["cfg"], find=3, on_standby=standby.extend, **NOSLEEP)
    assert r.ip == ip(5) and standby == [] and len(tenv["tested"]) == 8  # it looked at every candidate


def test_find_comes_from_the_config_by_default(tenv):
    tenv["cfg"] = replace(tenv["cfg"], hunt=replace(tenv["cfg"].hunt, find=2))
    tenv["set_tests"](scored({ip(1): 80.0, ip(2): 85.0}))
    r = hunter.hunt(tenv["cfg"], **NOSLEEP)
    assert r.ip == ip(2) and tenv["tested"] == [ip(1), ip(2)]


def test_login_in_triage_uses_each_ips_own_address(tenv, monkeypatch):
    seen = {}
    monkeypatch.setattr(hunter, "_login", lambda c, i, mac="": seen.setdefault("ips", []).append(i) or (True, "ok"))
    monkeypatch.setattr(triage, "run_triage", lambda cfg, ips, *, control=None, login=None: (
        {i: triage.TriageResult(i, bool(login(i)), gateway_ok=True) for i in ips}, None))
    tenv["set_tests"](lambda i: result(i, passed=True))
    cfg = portal_cfg(tenv)
    cfg = replace(cfg, hunt=replace(cfg.hunt, triage_batch=2, max_candidates=2))
    hunter.hunt(cfg, **NOSLEEP)
    assert seen["ips"][:2] == [ip(1), ip(2)]


# ---- failover to a standby IP
def test_failover_uses_the_first_standby_that_still_passes(env):
    env["mode"] = "live"
    env["set_tests"](lambda i: result(i, passed=(i == ip(8))))
    saved, dropped = [], []
    r = hunter.failover(env["cfg"], [ip(7), ip(8), ip(9)], save=saved.append, drop=dropped.append, **NOSLEEP)
    assert r.ip == ip(8) and dropped == [ip(7)] and [x.ip for x in saved] == [ip(7), ip(8)]
    assert env["deeps"] == [False, False]  # a quick re-check, not a full hunt
    assert env["persist"] == [ip(8)]


def test_failover_gives_up_after_three_tries(env):
    env["set_tests"](lambda i: result(i))
    dropped = []
    assert hunter.failover(env["cfg"], [ip(i) for i in range(1, 8)], drop=dropped.append, **NOSLEEP) is None
    assert dropped == [ip(1), ip(2), ip(3)]


def test_failover_with_nothing_to_try(env):
    env["set_tests"](lambda i: result(i, passed=True))
    assert hunter.failover(env["cfg"], [], **NOSLEEP) is None
