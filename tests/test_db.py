import time
from datetime import datetime

import pytest

from dorm_ip.db import DB, db_path
from dorm_ip.models import CheckResult, TestResult


def res(ip="172.18.40.9", passed=True, score=80.0, ts=None, bytes_used=1_000_000, seen=False, sus=20.0):
    return TestResult(
        ts=ts or time.time(), ip=ip, mac="aa", dns_mode="override", seen_in_use=seen, gateway_ok=True,
        portal_state="open", ping_avg_ms=20.0, ping_loss_pct=0.0, ping_jitter_ms=1.0, dns_ms=10.0,
        quick_mbps=30.0, sustained_avg_mbps=sus, sustained_min_mbps=10.0, collapse_after_mb=None,
        bytes_used=bytes_used, score=score if passed else 0.0, passed=passed,
        fail_reason=None if passed else "quick speed 1.0 Mbps < 5 Mbps",
    )


@pytest.fixture
def d():
    with DB(":memory:") as db:
        yield db


def at(hour, day=10):
    return datetime(2026, 10, day, hour, 30).timestamp()


def test_save_roundtrip_and_daily_usage(d):
    d.save(res(bytes_used=2_000_000))
    d.save(res(ip="172.18.40.10", bytes_used=3_000_000))
    row = d.conn.execute("SELECT * FROM results WHERE ip='172.18.40.9'").fetchone()
    assert row["passed"] == 1 and row["mac"] == "aa" and row["dns_mode"] == "override"
    assert d.daily_bytes() == 5_000_000


def test_daily_usage_is_per_day(d):
    d.save(res(ts=at(10, day=1), bytes_used=7))
    d.save(res(ts=at(10, day=2), bytes_used=5))
    assert d.daily_bytes("2026-10-01") == 7 and d.daily_bytes("2026-10-02") == 5
    assert d.daily_bytes("2026-10-03") == 0


def test_check_bytes_count_toward_budget(d):
    d.save_check(CheckResult(time.time(), "1.2.3.4", "aa", True, 0.0, 20.0, 5.0, 200_000, True, ""))
    assert d.daily_bytes() == 200_000
    assert d.conn.execute("SELECT COUNT(*) FROM checks").fetchone()[0] == 1


def test_scores_use_last_five_and_count_failures_as_zero(d):
    for i in range(3):
        d.save(res("172.18.40.1", passed=False, ts=1000 + i))
    for i in range(5):
        d.save(res("172.18.40.1", passed=True, score=60.0, ts=2000 + i))
    d.save(res("172.18.40.2", passed=True, score=90.0))
    d.save(res("172.18.40.2", passed=False))
    s = d.scores()
    assert s["172.18.40.1"] == 60.0  # old failures fell out of the window
    assert s["172.18.40.2"] == 45.0


def test_ip_stats_flags_and_ranking(d):
    for _ in range(4):
        d.save(res("172.18.40.5", passed=False))
    d.save(res("172.18.40.6", passed=True))
    for p in (True, False, False):
        d.save(res("172.18.40.7", passed=p))
    d.save(res("172.18.40.8", passed=False))  # only 1 test: no flag
    by = {s.ip: s for s in d.ip_stats()}
    assert by["172.18.40.5"].flag == "bad"
    assert by["172.18.40.6"].flag == ""
    assert by["172.18.40.7"].flag == "flaky"
    assert by["172.18.40.8"].flag == ""
    assert by["172.18.40.6"].eff_score == 80.0 and by["172.18.40.7"].eff_score == pytest.approx(80 / 3)
    assert by["172.18.40.7"].avg_score == 80.0


def test_good_hours(d):
    for h in (20, 21):
        d.save(res("172.18.40.9", passed=True, ts=at(h)))
    d.save(res("172.18.40.9", passed=False, ts=at(3)))
    d.save(res("172.18.40.9", passed=True, ts=at(9)))
    d.save(res("172.18.40.9", passed=False, ts=at(9, day=11)))
    s = d.ip_stats()[0]
    assert s.good_hours == [9, 20, 21]  # hour 9 passed 1 of 2 (>= 50%); hour 3 never passed


def test_hour_and_seen_stats(d):
    d.save(res(ts=at(10), seen=True))
    d.save(res(ts=at(10), seen=True, passed=False))
    d.save(res(ts=at(11), seen=False))
    assert d.hour_stats() == {10: (2, 1), 11: (1, 1)}
    assert d.seen_stats() == {True: (2, 1), False: (1, 1)}


def test_db_path_uses_xdg(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    assert db_path() == tmp_path / "dorm-ip" / "history.db"
    with DB() as db:
        db.save(res())
    assert (tmp_path / "dorm-ip" / "history.db").exists()


# ---- smart ordering (phase 1)
NOW = datetime(2026, 10, 20, 15, 0).timestamp()



def _fail(ip, ago_min, reason):
    r = res(ip, passed=False, ts=NOW - ago_min * 60)
    r.fail_reason = reason
    return r


def ok(ip, ago_min):
    return res(ip, passed=True, ts=NOW - ago_min * 60)


def test_recently_failed_ip_is_skipped_until_the_cooldown_ends(d):
    d.save(_fail("172.18.40.7", 10, "gateway unreachable"))
    rk = d.ranking(30, now=NOW)
    assert rk.skip == {"172.18.40.7": pytest.approx(20.0)}
    assert d.ranking(30, now=NOW + 3600).skip == {}  # an hour later it may be tried again


def test_cooldown_doubles_per_consecutive_failure_with_a_cap(d):
    for i, ago in enumerate((200, 100, 10)):
        d.save(_fail("172.18.40.7", ago, "speed collapsed after 1.0 MB"))
    assert d.ranking(30, now=NOW).skip["172.18.40.7"] == pytest.approx(120 - 10)  # 30 * 2^2
    d2 = DB(":memory:")
    for ago in range(10, 70, 10):
        d2.save(_fail("172.18.40.8", ago, "x"))
    assert d2.ranking(30, now=NOW).skip["172.18.40.8"] <= 720  # capped at 12 h
    d2.close()


def test_a_pass_resets_the_streak_and_good_ips_only_get_the_base_cooldown(d):
    d.save(_fail("172.18.40.7", 300, "x"))
    d.save(ok("172.18.40.7", 200))
    assert d.ranking(30, now=NOW).skip == {}  # newest result is a pass... wait for failures after it
    d.save(_fail("172.18.40.7", 100, "x"))
    d.save(_fail("172.18.40.7", 10, "x"))
    # two failures since the pass, but it passed within 24 h: base cooldown only (30 min, 10 min ago)
    assert d.ranking(30, now=NOW).skip["172.18.40.7"] == pytest.approx(20.0)


def test_portal_login_failures_never_count(d):
    d.save(_fail("172.18.40.7", 5, "captive portal: login required"))
    assert d.ranking(30, now=NOW).skip == {}
    d.save(_fail("172.18.40.7", 4, "gateway unreachable"))
    d.save(_fail("172.18.40.7", 3, "captive portal: login required"))
    assert d.recent_failures(NOW)["172.18.40.7"].streak == 1


def test_skipping_can_be_turned_off(d):
    d.save(_fail("172.18.40.7", 1, "x"))
    assert d.ranking(0, now=NOW).skip == {}


def test_old_failures_are_forgotten(d):
    d.save(_fail("172.18.40.7", 60 * 24 * 8, "x"))
    assert d.recent_failures(NOW) == {}


def test_hour_of_day_weighting(d):
    morning, evening = datetime(2026, 10, 19, 9, 0).timestamp(), datetime(2026, 10, 19, 21, 0).timestamp()
    d.save(res("172.18.40.1", passed=True, score=100.0, ts=evening))
    d.save(res("172.18.40.1", passed=False, ts=morning))
    assert d.scores()["172.18.40.1"] == 50.0
    assert d.scores(hour=21)["172.18.40.1"] == pytest.approx(200 / 3)  # the evening pass counts double
    assert d.scores(hour=9)["172.18.40.1"] == pytest.approx(100 / 3)
    assert d.scores(hour=23)["172.18.40.1"] == pytest.approx(200 / 3)  # circular +-2 h
    assert d.scores(hour=3)["172.18.40.1"] == 50.0


def test_scan_history_and_busy_ratio(d):
    d.save_scan({"172.18.40.1", "172.18.40.2"}, ts=1)
    d.save_scan({"172.18.40.1"}, ts=2)
    d.save_scan(set(), ts=3)  # empty scans carry no information and are not stored
    assert d.busy_ratio() == {"172.18.40.1": 1.0, "172.18.40.2": 0.5}
    for i in range(10):
        d.save_scan({"172.18.40.3"}, ts=10 + i)
    assert d.busy_ratio() == {"172.18.40.3": 1.0}  # only the last 10 scans count


def test_ranking_bundles_everything(d):
    d.save(res("172.18.40.1", passed=True, score=80.0, ts=NOW - 60))
    d.save(_fail("172.18.40.2", 5, "x"))
    d.save_scan({"172.18.40.3"}, ts=NOW)
    rk = d.ranking(30, now=NOW)
    assert rk.scores["172.18.40.1"] == 80.0 and "172.18.40.2" in rk.skip and rk.busy == {"172.18.40.3": 1.0}


# ---- standby list (phase 2)
def test_standby_roundtrip_ordering_and_upsert(d):
    a, b = res("172.18.40.1", score=70.0, ts=NOW - 60), res("172.18.40.2", score=90.0, ts=NOW - 120)
    d.save_standby([a, b])
    assert [e.ip for e in d.standby_list(12, now=NOW)] == ["172.18.40.2", "172.18.40.1"]  # best score first
    better = res("172.18.40.1", score=95.0, ts=NOW)
    d.save_standby([better])
    entries = d.standby_list(12, now=NOW)
    assert [(e.ip, e.score) for e in entries] == [("172.18.40.1", 95.0), ("172.18.40.2", 90.0)]
    assert entries[0].mac == "aa" and entries[0].dns_mode == "override"


def test_standby_expires(d):
    d.save_standby([res("172.18.40.1", ts=NOW - 13 * 3600), res("172.18.40.2", ts=NOW - 3600)])
    assert [e.ip for e in d.standby_list(12, now=NOW)] == ["172.18.40.2"]
    assert d.conn.execute("SELECT COUNT(*) FROM standby").fetchone()[0] == 1  # the old one is deleted, not hidden


def test_standby_remove_and_clear(d):
    d.save_standby([res("172.18.40.1", ts=NOW), res("172.18.40.2", ts=NOW)])
    d.remove_standby("172.18.40.1")
    assert [e.ip for e in d.standby_list(12, now=NOW)] == ["172.18.40.2"]
    assert d.clear_standby() == 1 and d.standby_list(12, now=NOW) == []
