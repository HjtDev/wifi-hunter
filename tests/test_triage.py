import time
from dataclasses import replace

import pytest

from dorm_ip import triage
from dorm_ip import tests as nt

SRC = "172.18.40.9"


@pytest.fixture
def probes(monkeypatch):
    """Scriptable probes; records the source address each one was sent from."""
    st = {"gw_loss": 0.0, "portal": ("open", 100, None), "ping": (30.0, 0.0, 2.0), "dl": (True, 300_000, 5.0), "sources": []}

    def ping(target, count, wait=2, source=None):
        st["sources"].append(("ping", target, source))
        return (None, st["gw_loss"], None) if target == "172.18.47.254" else st["ping"]

    monkeypatch.setattr(nt, "ping", ping)
    monkeypatch.setattr(nt, "check_portal", lambda cfg, source=None: st["sources"].append(("portal", None, source)) or st["portal"])
    monkeypatch.setattr(nt, "small_download", lambda cfg, nbytes, source=None, max_seconds=12.0: st["sources"].append(("dl", None, source)) or st["dl"])
    return st


def test_a_good_ip_passes_and_everything_is_sent_from_its_own_address(cfg, probes):
    t = triage.triage_one(cfg, SRC)
    assert t.passed and t.reason is None and t.gateway_ok and t.portal_state == "open"
    assert {src for _k, _t, src in probes["sources"]} == {SRC}
    assert [k for k, *_ in probes["sources"]] == ["ping", "portal", "ping", "dl"]
    assert t.bytes_used == 100 + 300_000


def test_dead_gateway_stops_at_once(cfg, probes):
    probes["gw_loss"] = 100.0
    t = triage.triage_one(cfg, SRC)
    assert not t.passed and t.reason == "gateway unreachable" and [k for k, *_ in probes["sources"]] == ["ping"]


def test_light_mode_only_checks_the_gateway(cfg, probes):
    assert triage.triage_one(cfg, SRC, light=True).passed
    assert [k for k, *_ in probes["sources"]] == ["ping"]


def test_portal_with_login_hook(cfg, probes):
    states = iter([("portal", 10, "http://p/"), ("open", 10, None)])
    probes["portal"] = None
    nt.check_portal = lambda cfg, source=None: next(states)
    logged = []
    t = triage.triage_one(cfg, SRC, login=lambda ip: logged.append(ip) or True)
    assert t.passed and logged == [SRC]


def test_portal_without_login_is_reported_as_login_required(cfg, probes):
    probes["portal"] = ("portal", 10, "http://p/")
    t = triage.triage_one(cfg, SRC)
    assert not t.passed and t.reason == "captive portal: login required"  # neutral for the cooldown


def test_dead_connectivity_keeps_the_cause(cfg, probes):
    probes["portal"] = ("dead", 0, "DNS lookup failed")
    assert triage.triage_one(cfg, SRC).reason == "no internet: DNS lookup failed"


def test_loss_ping_and_download_filters(cfg, probes):
    probes["ping"] = (30.0, 60.0, 2.0)
    assert triage.triage_one(cfg, SRC).reason == "packet loss 60%"
    probes["ping"] = (30.0, 20.0, 2.0)  # parallel flows add loss: 20% is still fine here
    assert triage.triage_one(cfg, SRC).passed
    probes["ping"] = (cfg.thresholds.max_ping_ms * 2 + 1, 0.0, 2.0)
    assert triage.triage_one(cfg, SRC).reason.startswith("ping ")
    probes["ping"] = (30.0, 0.0, 2.0)
    probes["dl"] = (False, 40_000, 0.1)
    assert triage.triage_one(cfg, SRC).reason == "download stalled"
    probes["dl"] = (False, 0, None)
    assert triage.triage_one(cfg, SRC).reason == "download failed"
    probes["dl"] = (True, 300_000, 0.1)  # complete but crawling
    assert triage.triage_one(cfg, SRC).reason == "download stalled"


def test_triage_thresholds_are_lenient_on_purpose(cfg):
    assert triage.TRIAGE_MAX_LOSS > cfg.thresholds.max_loss_pct * 5
    assert triage.TRIAGE_PING_FACTOR >= 2


def test_run_triage_is_parallel_ordered_and_separates_the_control(cfg, monkeypatch):
    active = {"now": 0, "max": 0}

    def slow(cfg, ip, *, login=None, light=False):
        active["now"] += 1
        active["max"] = max(active["max"], active["now"])
        time.sleep(0.05)
        active["now"] -= 1
        return triage.TriageResult(ip, ip != "172.18.40.3", None if ip != "172.18.40.3" else "x", gateway_ok=True)

    monkeypatch.setattr(triage, "triage_one", slow)
    ips = [f"172.18.40.{i}" for i in range(1, 9)]
    res, ctrl = triage.run_triage(cfg, ips, control="172.18.40.200")
    assert list(res) == ips and not res["172.18.40.3"].passed and ctrl.ip == "172.18.40.200" and ctrl.passed
    assert active["max"] > 1  # really concurrent


def test_a_crashing_probe_only_fails_that_ip(cfg, monkeypatch):
    def boom(cfg, ip, *, login=None, light=False):
        if ip.endswith(".2"):
            raise RuntimeError("x")
        return triage.TriageResult(ip, True, gateway_ok=True)

    monkeypatch.setattr(triage, "triage_one", boom)
    res, ctrl = triage.run_triage(cfg, ["172.18.40.1", "172.18.40.2"])
    assert res["172.18.40.1"].passed and res["172.18.40.2"].reason == "triage error (RuntimeError)" and ctrl is None


def test_to_result_lands_in_the_history_as_a_failure(cfg):
    t = triage.TriageResult(SRC, False, "gateway unreachable", gateway_ok=False, bytes_used=5)
    r = triage.to_result(cfg, t, mac="aa", dns_mode="override", seen_in_use=True)
    assert (r.ip, r.passed, r.score, r.fail_reason, r.bytes_used, r.seen_in_use) == (SRC, False, 0.0, "gateway unreachable", 5, True)
    assert r.sustained_avg_mbps is None and r.dns_mode == "override"