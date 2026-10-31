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


@pytest.fixture
def env(cfg, monkeypatch):
    """Stub every side effect; record applier calls."""
    log = {"apply": [], "dns": [], "restore": 0, "tested": [], "saved": []}
    cfg = replace(cfg, hunt=replace(cfg.hunt, max_candidates=5, order="sequential"))
    monkeypatch.setattr(applier, "begin_change", lambda i, c, dry_run=False, notify=None: applier.Target("Dorm", "wlan0"))
    monkeypatch.setattr(applier, "apply_static", lambda ip, prefix, gw, dns, *, connection, dry_run=False: log["apply"].append((ip, tuple(dns))))
    monkeypatch.setattr(applier, "set_dns", lambda dns, *, connection, dry_run=False: log["dns"].append(tuple(dns)))
    monkeypatch.setattr(applier, "restore", lambda dry_run=False: log.__setitem__("restore", log["restore"] + 1) or "Dorm")
    monkeypatch.setattr(scanner, "scan_used", lambda cfg, iface=None, dry_run=False: set())
    monkeypatch.setattr(netinfo, "read_mac", lambda d: "aa:bb")
    monkeypatch.setattr(nt, "check_portal", lambda c: ("open", 0, None))
    log["cfg"] = cfg

    def set_tests(fn):
        def run_all(c, ip, mode, deep=True, **kw):
            log["tested"].append(ip)
            return fn(ip)
        monkeypatch.setattr(nt, "run_all", run_all)

    log["set_tests"] = set_tests
    return log


NOSLEEP = dict(sleep=lambda s: None)


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
    def bad(ip, prefix, gw, dns, *, connection, dry_run=False):
        raise NetError("activation failed")

    monkeypatch.setattr(applier, "apply_static", bad)
    env["set_tests"](lambda ip: result(ip))
    obs = Rec()
    with pytest.raises(NetError, match="consecutive"):
        hunter.hunt(env["cfg"], observer=obs, **NOSLEEP)
    assert env["restore"] == 1 and env["tested"] == []
    assert [e for e in obs.events if e[0] == "skipped"].__len__() == 3


def test_gateway_unreachable_gets_one_retry(env):
    calls = {}

    def fn(ip):
        calls[ip] = calls.get(ip, 0) + 1
        if calls[ip] == 1:
            return result(ip, reason="gateway unreachable")
        return result(ip, passed=True)

    env["set_tests"](fn)
    r = hunter.hunt(env["cfg"], **NOSLEEP)
    assert r.ip == "172.18.40.1" and calls["172.18.40.1"] == 2


def test_dry_run_changes_nothing(env, monkeypatch, capsys):
    env["set_tests"](lambda ip: result(ip, passed=True))
    assert hunter.hunt(env["cfg"], dry_run=True, **NOSLEEP) is None
    assert env["tested"] == [] and env["restore"] == 0
    assert len(env["apply"]) == hunter.DRY_RUN_CANDIDATES


def test_settle_sleep_used(env):
    slept = []
    env["set_tests"](lambda ip: result(ip, passed=True))
    hunter.hunt(env["cfg"], sleep=slept.append)
    assert slept[0] == env["cfg"].hunt.settle_seconds


# ---- finalize (DNS override / portal logic)
def fin(env, mode, tested_with="override", portals=(), login=False, monkeypatch=None):
    cfg = env["cfg"]
    cfg = replace(cfg, dns=replace(cfg.dns, final_mode=mode))
    queue = list(portals)
    monkeypatch.setattr(nt, "check_portal", lambda c: queue.pop(0))
    monkeypatch.setattr(hunter, "try_login", lambda c: login)
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