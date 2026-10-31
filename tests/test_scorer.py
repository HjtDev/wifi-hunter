import time

from dorm_ip import scorer
from dorm_ip.models import TestResult


def make(**kw):
    base = dict(
        ts=time.time(), ip="172.18.40.9", mac="aa", dns_mode="override", seen_in_use=False,
        gateway_ok=True, portal_state="open", ping_avg_ms=20.0, ping_loss_pct=0.0,
        ping_jitter_ms=2.0, dns_ms=15.0, quick_mbps=30.0, sustained_avg_mbps=25.0,
        sustained_min_mbps=20.0, collapse_after_mb=None, bytes_used=1, score=0.0,
        passed=False, fail_reason=None,
    )
    base.update(kw)
    return TestResult(**base)


def test_good_result_passes(cfg):
    s, ok, why = scorer.score(make(), cfg)
    assert ok and why is None and 0 < s <= 100


def test_faster_scores_higher(cfg):
    slow = scorer.score(make(quick_mbps=6, sustained_avg_mbps=5, sustained_min_mbps=5), cfg)[0]
    fast = scorer.score(make(), cfg)[0]
    assert fast > slow > 0


def test_collapse_is_hard_fail(cfg):
    s, ok, why = scorer.score(make(collapse_after_mb=2.1), cfg)
    assert (s, ok) == (0.0, False) and "collapsed after 2.1 MB" in why


def test_loss_hard_fail(cfg):
    s, ok, why = scorer.score(make(ping_loss_pct=10.0), cfg)
    assert s == 0.0 and not ok and "loss" in why


def test_portal_and_dead_and_gateway(cfg):
    assert "login required" in scorer.score(make(portal_state="portal"), cfg)[2]
    assert "no internet" in scorer.score(make(portal_state="dead"), cfg)[2]
    assert "gateway" in scorer.score(make(gateway_ok=False), cfg)[2]


def test_threshold_failures_are_soft(cfg):
    s, ok, why = scorer.score(make(ping_avg_ms=120.0), cfg)
    assert not ok and s > 0 and "ping" in why
    s, ok, why = scorer.score(make(quick_mbps=2.0), cfg)
    assert not ok and "quick speed" in why
    s, ok, why = scorer.score(make(sustained_avg_mbps=2.0, sustained_min_mbps=1.5), cfg)
    assert not ok and "sustained" in why


def test_no_deep_renormalises_and_passes(cfg):
    r = make(sustained_avg_mbps=None, sustained_min_mbps=None)
    s, ok, why = scorer.score(r, cfg)
    assert ok and why is None and s > 0


def test_partial_result_has_no_reason(cfg):
    r = make(ping_avg_ms=None, ping_loss_pct=None, quick_mbps=None,
             sustained_avg_mbps=None, sustained_min_mbps=None)
    assert scorer.failure(r, cfg) == (None, False)