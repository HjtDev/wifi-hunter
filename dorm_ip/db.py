"""SQLite history: test results, watchdog checks and the daily data budget."""

from __future__ import annotations

import os
import sqlite3
import time
from dataclasses import dataclass, fields
from datetime import date, datetime
from pathlib import Path

from .models import CheckResult, TestResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL, ip TEXT NOT NULL, mac TEXT, dns_mode TEXT,
    seen_in_use INTEGER, gateway_ok INTEGER, portal_state TEXT,
    ping_avg_ms REAL, ping_loss_pct REAL, ping_jitter_ms REAL, dns_ms REAL,
    quick_mbps REAL, sustained_avg_mbps REAL, sustained_min_mbps REAL, collapse_after_mb REAL,
    bytes_used INTEGER, score REAL, passed INTEGER, fail_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_results_ip_ts ON results(ip, ts);
CREATE TABLE IF NOT EXISTS daily_usage (day TEXT PRIMARY KEY, bytes INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL, ip TEXT, mac TEXT, gateway_ok INTEGER, loss_pct REAL, rtt_ms REAL,
    probe_mbps REAL, bytes_used INTEGER, ok INTEGER, note TEXT
);
"""

SCORE_WINDOW = 5  # best-history looks at the last N results per IP
FLAKY_MIN_TESTS = 3


def db_path() -> Path:
    base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / "dorm-ip" / "history.db"


def _day(ts: float | None = None) -> str:
    return (datetime.fromtimestamp(ts) if ts is not None else datetime.now()).strftime("%Y-%m-%d")


@dataclass
class IpStats:
    ip: str
    tests: int
    passes: int
    eff_score: float  # mean score where failures count as 0 (reliability x quality)
    avg_score: float | None  # mean score of passing tests only
    avg_sustained: float | None
    last_ts: float
    good_hours: list[int]  # hours of day (local) where it mostly passed

    @property
    def pass_rate(self) -> float:
        return self.passes / self.tests if self.tests else 0.0

    @property
    def flag(self) -> str:
        if self.tests >= FLAKY_MIN_TESTS and self.passes == 0:
            return "bad"
        if self.tests >= FLAKY_MIN_TESTS and self.pass_rate < 0.5:
            return "flaky"
        return ""


class DB:
    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path else db_path()
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> DB:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------ writes

    def add_bytes(self, n: int, ts: float | None = None) -> None:
        if n <= 0:
            return
        with self.conn:
            self.conn.execute(
                "INSERT INTO daily_usage(day, bytes) VALUES(?, ?) "
                "ON CONFLICT(day) DO UPDATE SET bytes = bytes + excluded.bytes",
                (_day(ts), int(n)),
            )

    def save(self, r: TestResult) -> None:
        """Store a test result and add its traffic to today's total."""
        names = [f.name for f in fields(TestResult)]
        values = [int(v) if isinstance(v, bool) else v for v in (getattr(r, n) for n in names)]
        with self.conn:
            self.conn.execute(
                f"INSERT INTO results({','.join(names)}) VALUES({','.join('?' * len(names))})", values
            )
        self.add_bytes(r.bytes_used, r.ts)

    def save_check(self, c: CheckResult) -> None:
        names = [f.name for f in fields(CheckResult)]
        values = [int(v) if isinstance(v, bool) else v for v in (getattr(c, n) for n in names)]
        with self.conn:
            self.conn.execute(
                f"INSERT INTO checks({','.join(names)}) VALUES({','.join('?' * len(names))})", values
            )
        self.add_bytes(c.bytes_used, c.ts)

    # ------------------------------------------------------------ budget

    def daily_bytes(self, day: str | None = None) -> int:
        row = self.conn.execute("SELECT bytes FROM daily_usage WHERE day = ?", (day or _day(),)).fetchone()
        return int(row["bytes"]) if row else 0

    # ------------------------------------------------------------ ordering

    def scores(self, window: int = SCORE_WINDOW) -> dict[str, float]:
        """ip -> mean of the last `window` results, where a failed test counts as 0."""
        out: dict[str, list[float]] = {}
        for row in self.conn.execute("SELECT ip, passed, score FROM results ORDER BY ts DESC, id DESC"):
            vals = out.setdefault(row["ip"], [])
            if len(vals) < window:
                vals.append(float(row["score"]) if row["passed"] else 0.0)
        return {ip: sum(v) / len(v) for ip, v in out.items()}

    # ------------------------------------------------------------ history

    def ip_stats(self) -> list[IpStats]:
        hours: dict[str, dict[int, list[int]]] = {}
        for row in self.conn.execute(
            "SELECT ip, CAST(strftime('%H', ts, 'unixepoch', 'localtime') AS INTEGER) AS h, "
            "COUNT(*) AS n, SUM(passed) AS p FROM results GROUP BY ip, h"
        ):
            hours.setdefault(row["ip"], {})[row["h"]] = [row["n"], row["p"] or 0]

        stats = []
        for row in self.conn.execute(
            "SELECT ip, COUNT(*) AS n, SUM(passed) AS p, "
            "SUM(CASE WHEN passed THEN score ELSE 0 END) * 1.0 / COUNT(*) AS eff, "
            "AVG(CASE WHEN passed THEN score END) AS avg_score, "
            "AVG(CASE WHEN passed THEN sustained_avg_mbps END) AS sus, MAX(ts) AS last_ts "
            "FROM results GROUP BY ip"
        ):
            good = sorted(h for h, (n, p) in hours.get(row["ip"], {}).items() if p > 0 and p / n >= 0.5)
            stats.append(
                IpStats(
                    ip=row["ip"], tests=row["n"], passes=row["p"] or 0, eff_score=row["eff"] or 0.0,
                    avg_score=row["avg_score"], avg_sustained=row["sus"], last_ts=row["last_ts"],
                    good_hours=good,
                )
            )
        return stats

    def hour_stats(self) -> dict[int, tuple[int, int]]:
        """hour of day -> (tests, passes) over all IPs."""
        rows = self.conn.execute(
            "SELECT CAST(strftime('%H', ts, 'unixepoch', 'localtime') AS INTEGER) AS h, "
            "COUNT(*) AS n, SUM(passed) AS p FROM results GROUP BY h"
        )
        return {r["h"]: (r["n"], r["p"] or 0) for r in rows}

    def seen_stats(self) -> dict[bool, tuple[int, int]]:
        """seen_in_use -> (tests, passes): do IPs nobody else uses really do better?"""
        rows = self.conn.execute("SELECT seen_in_use AS s, COUNT(*) AS n, SUM(passed) AS p FROM results GROUP BY s")
        return {bool(r["s"]): (r["n"], r["p"] or 0) for r in rows}

    def result_count(self) -> int:
        return int(self.conn.execute("SELECT COUNT(*) FROM results").fetchone()[0])


def open_db(path: Path | str | None = None) -> DB:
    return DB(path)


def today() -> str:
    return date.today().isoformat()


def now() -> float:
    return time.time()