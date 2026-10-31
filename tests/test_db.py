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