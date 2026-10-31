import struct

import httpx
import pytest

from dorm_ip import tests as nt
from dorm_ip.models import NetProfile

PING_OK = """PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.

--- 1.1.1.1 ping statistics ---
5 packets transmitted, 5 received, 0% packet loss, time 1204ms
rtt min/avg/max/mdev = 18.512/21.300/30.001/4.250 ms
"""
PING_LOSSY = """--- 1.1.1.1 ping statistics ---
5 packets transmitted, 3 received, 40% packet loss, time 1500ms
rtt min/avg/max/mdev = 20.0/25.0/40.0/8.0 ms
"""
PING_DEAD = """--- 1.1.1.1 ping statistics ---
5 packets transmitted, 0 received, 100% packet loss, time 4090ms
"""


def test_parse_ping():
    assert nt.parse_ping(PING_OK) == (21.3, 0.0, 4.25)
    assert nt.parse_ping(PING_LOSSY) == (25.0, 40.0, 8.0)
    assert nt.parse_ping(PING_DEAD) == (None, 100.0, None)
    assert nt.parse_ping("garbage") == (None, None, None)


# ---- portal
def mock_client(handler):
    return lambda timeout=None: httpx.Client(transport=httpx.MockTransport(handler))


def test_classify_portal():
    assert nt.classify_portal(204, "", b"") == "open"
    assert nt.classify_portal(302, "", b"") == "portal"
    assert nt.classify_portal(200, "text/html", b"<html>login</html>") == "portal"
    assert nt.classify_portal(200, "", b"<html>") == "portal"
    assert nt.classify_portal(503, "text/plain", b"x") == "dead"


def test_check_portal_states(cfg, monkeypatch):
    monkeypatch.setattr(nt, "_client", mock_client(lambda req: httpx.Response(204)))
    assert nt.check_portal(cfg)[0] == "open"
    monkeypatch.setattr(
        nt, "_client",
        mock_client(lambda req: httpx.Response(302, headers={"location": "http://portal.local/login"})),
    )
    assert nt.check_portal(cfg) == ("portal", 0, "http://portal.local/login")

    def boom(req):
        raise httpx.ConnectTimeout("t")

    monkeypatch.setattr(nt, "_client", mock_client(boom))
    assert nt.check_portal(cfg)[0] == "dead"


# ---- dns
def test_dns_query_roundtrip_helpers():
    q = nt.build_dns_query("google.com", 0x1234)
    assert q[:2] == b"\x12\x34" and b"\x06google\x03com\x00" in q
    resp = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    assert nt.dns_response_ok(resp, 0x1234)
    assert not nt.dns_response_ok(resp, 0x9999)
    nxdomain = struct.pack("!HHHHHH", 0x1234, 0x8183, 1, 0, 0, 0)
    assert not nt.dns_response_ok(nxdomain, 0x1234)
    assert not nt.dns_response_ok(b"\x00", 1)


def test_dns_time_average_and_failure(monkeypatch):
    answers = {"a.com": 10.0, "b.com": 30.0, "c.com": None}
    monkeypatch.setattr(nt, "dns_query_ms", lambda s, d, timeout=2.0: answers[d])
    assert nt.dns_time(["1.1.1.1"], ["a.com", "b.com", "c.com"]) == 20.0
    assert nt.dns_time(["1.1.1.1"], ["c.com"]) is None
    assert nt.dns_time([], ["a.com"]) is None
    assert nt.dns_time(["::1"], ["a.com"]) is None


# ---- sustained analysis
def series(rates_mbps, step=0.5):
    """Build samples from per-interval rates in Mbps."""
    t, b, out = 0.0, 0, [(0.0, 0)]
    for r in rates_mbps:
        t += step
        b += int(r * 1e6 / 8 * step)
        out.append((t, b))
    return out


def test_analyze_steady():
    r = nt.analyze_samples(series([20] * 16), 1.0)
    assert r.collapse_after_mb is None
    assert r.avg_mbps == pytest.approx(20, rel=0.01) and r.min_mbps == pytest.approx(20, rel=0.01)


def test_analyze_collapse_point():
    # 4 s at 20 Mbps (10 MB), then dead
    r = nt.analyze_samples(series([20] * 8 + [0] * 8), 1.0)
    assert r.collapse_after_mb == pytest.approx(10.0, abs=0.01)
    assert r.min_mbps == 0


def test_short_dip_is_not_collapse():
    r = nt.analyze_samples(series([20] * 4 + [0, 0, 0] + [20] * 8), 1.0)  # 1.5 s dip
    assert r.collapse_after_mb is None and r.min_mbps == 0


def test_exactly_two_seconds_is_collapse():
    r = nt.analyze_samples(series([20] * 4 + [0, 0, 0, 0] + [20] * 4), 1.0)
    assert r.collapse_after_mb == pytest.approx(5.0, abs=0.01)


def test_slow_start_ignored_for_min_but_not_avg():
    r = nt.analyze_samples(series([0.5] + [20] * 9), 1.0)
    assert r.min_mbps == pytest.approx(20, rel=0.01)
    assert r.collapse_after_mb is None


def test_analyze_empty():
    assert nt.analyze_samples([(0.0, 0)], 1.0).avg_mbps == 0.0


# ---- sustained / quick with a mocked server
def test_sustained_streams_and_stops(cfg, monkeypatch):
    chunk = b"x" * 65536

    def handler(req):
        return httpx.Response(200, content=chunk * 20)

    monkeypatch.setattr(nt, "_client", mock_client(handler))
    s = nt.sustained(cfg)
    assert s.bytes_used > 0 and s.avg_mbps > 0 and s.collapse_after_mb is None
    assert s.duration <= 2.0


def test_sustained_http_error_is_collapse(cfg, monkeypatch):
    from dataclasses import replace

    cfg = replace(cfg, tests=replace(cfg.tests, sustained_seconds=8))
    monkeypatch.setattr(nt, "_client", mock_client(lambda req: httpx.Response(503)))
    s = nt.sustained(cfg)
    assert s.collapse_after_mb == 0.0 and s.avg_mbps == 0.0


def test_quick_speed(cfg, monkeypatch):
    monkeypatch.setattr(nt, "_client", mock_client(lambda req: httpx.Response(200, content=b"x" * 500_000)))
    mbps, n = nt.quick_speed(cfg)
    assert mbps is None or mbps > 0
    monkeypatch.setattr(nt, "_client", mock_client(lambda req: httpx.Response(404)))
    assert nt.quick_speed(cfg) == (None, 0)


# ---- orchestration
PROFILE = NetProfile("wlan0", "Dorm", "manual", "172.18.40.9", 21, "172.18.47.254", ["8.8.8.8"], "aa:bb")


def stub(monkeypatch, *, gw=True, portal=("open", 0, None), png=(20.0, 0.0, 2.0), dns=15.0,
         quick=(30.0, 5_000_000), sus=None):
    calls = []
    monkeypatch.setattr(nt, "gateway_reachable", lambda g: calls.append("gw") or gw)
    monkeypatch.setattr(nt, "check_portal", lambda c: calls.append("portal") or portal)
    monkeypatch.setattr(nt, "ping", lambda t, n, wait=2: calls.append("ping") or png)
    monkeypatch.setattr(nt, "dns_time", lambda s, d: calls.append("dns") or dns)
    monkeypatch.setattr(nt, "quick_speed", lambda c, max_seconds=20.0: calls.append("quick") or quick)
    from dorm_ip.models import SustainedResult
    monkeypatch.setattr(nt, "sustained", lambda c: calls.append("sus") or (sus or SustainedResult(25, 20, None, 25_000_000, 8)))
    return calls


def test_run_all_pass(cfg, monkeypatch):
    calls = stub(monkeypatch)
    r = nt.run_all(cfg, "172.18.40.9", "override", profile=PROFILE)
    assert r.passed and calls == ["gw", "portal", "ping", "dns", "quick", "sus"]
    assert r.mac == "aa:bb" and r.bytes_used == 30_000_000


def test_run_all_no_deep(cfg, monkeypatch):
    calls = stub(monkeypatch)
    r = nt.run_all(cfg, "172.18.40.9", "override", deep=False, profile=PROFILE)
    assert r.passed and "sus" not in calls and r.sustained_avg_mbps is None


def test_fail_fast_gateway(cfg, monkeypatch):
    calls = stub(monkeypatch, gw=False)
    r = nt.run_all(cfg, "x", "default", profile=PROFILE)
    assert calls == ["gw"] and not r.passed and "gateway" in r.fail_reason


def test_fail_fast_portal(cfg, monkeypatch):
    calls = stub(monkeypatch, portal=("portal", 800, "http://p/"))
    r = nt.run_all(cfg, "x", "default", profile=PROFILE)
    assert calls == ["gw", "portal"] and "login required" in r.fail_reason and r.bytes_used == 800


def test_fail_fast_slow_ping_skips_downloads(cfg, monkeypatch):
    calls = stub(monkeypatch, png=(200.0, 0.0, 1.0))
    r = nt.run_all(cfg, "x", "default", profile=PROFILE)
    assert calls[-1] == "ping" and not r.passed and r.bytes_used == 0


def test_dns_failure(cfg, monkeypatch):
    calls = stub(monkeypatch, dns=None)
    r = nt.run_all(cfg, "x", "default", profile=PROFILE)
    assert calls[-1] == "dns" and "DNS lookups failed" in r.fail_reason and r.score == 0


def test_slow_quick_skips_sustained(cfg, monkeypatch):
    calls = stub(monkeypatch, quick=(1.0, 500_000))
    r = nt.run_all(cfg, "x", "default", profile=PROFILE)
    assert "sus" not in calls and "quick speed" in r.fail_reason


def test_download_failed(cfg, monkeypatch):
    stub(monkeypatch, quick=(None, 0))
    r = nt.run_all(cfg, "x", "default", profile=PROFILE)
    assert r.fail_reason == "download failed" and not r.passed


def test_collapse_detected(cfg, monkeypatch):
    from dorm_ip.models import SustainedResult
    stub(monkeypatch, sus=SustainedResult(10, 0, 2.0, 10_000_000, 8))
    r = nt.run_all(cfg, "x", "default", profile=PROFILE)
    assert r.score == 0 and "collapsed after 2.0 MB" in r.fail_reason


def test_detect_dns_mode(cfg):
    p = PROFILE
    assert nt.detect_dns_mode(p, cfg) == "override"
    p2 = NetProfile("w", "c", "auto", "1.1.1.1", 21, "g", ["172.18.32.1"], "m")
    assert nt.detect_dns_mode(p2, cfg) == "default"
    p3 = NetProfile("w", "c", "auto", "1.1.1.1", 21, "g", ["9.9.9.9"], "m")
    assert nt.detect_dns_mode(p3, cfg) == "custom"


def test_run_all_logs_in_when_portal_blocks(cfg, monkeypatch):
    states = iter([("portal", 800, "http://p/"), ("open", 0, None)])
    calls = stub(monkeypatch)
    monkeypatch.setattr(nt, "check_portal", lambda c: next(states))
    logged = []
    r = nt.run_all(cfg, "x", "override", profile=PROFILE, on_portal=lambda: logged.append(1) or True)
    assert logged == [1] and r.passed and r.portal_state == "open"
    assert calls[-1] == "sus"


def test_run_all_portal_login_failure_still_fails(cfg, monkeypatch):
    stub(monkeypatch)
    monkeypatch.setattr(nt, "check_portal", lambda c: ("portal", 800, "http://p/"))
    r = nt.run_all(cfg, "x", "override", profile=PROFILE, on_portal=lambda: False)
    assert not r.passed and "login required" in r.fail_reason
