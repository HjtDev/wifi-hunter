"""SQLite history: test results, watchdog checks and the daily data budget."""

from __future__ import annotations

import os
import sqlite3
import time
from dataclasses import dataclass, field, fields
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
         CREATE TABLE IF NOT EXISTS scan_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL);
         CREATE TABLE IF NOT EXISTS scan_hits (run_id INTEGER NOT NULL, ip TEXT NOT NULL, PRIMARY KEY (run_id, ip));
         CREATE TABLE IF NOT EXISTS standby (
                                                ip TEXT PRIMARY KEY, ts REAL NOT NULL, score REAL, mac TEXT, dns_mode TEXT
         );
         CREATE TABLE IF NOT EXISTS checks (
                                               id INTEGER PRIMARY KEY AUTOINCREMENT,
                                               ts REAL NOT NULL, ip TEXT, mac TEXT, gateway_ok INTEGER, loss_pct REAL, rtt_ms REAL,
                                               probe_mbps REAL, bytes_used INTEGER, ok INTEGER, note TEXT
         ); \
         """

SCORE_WINDOW = 5  # best-history looks at the last N results per IP
FLAKY_MIN_TESTS = 3
HOUR_RADIUS = 2  # results from within +-2 h of the current hour of day count double
SKIP_CAP_MINUTES = 720.0  # a failed IP is never skipped for longer than 12 h
BUSY_WINDOW = 10  # last N ARP scans
NEUTRAL_FAILURE_PREFIX = "captive portal"  # "login required" says nothing about the IP's quality


def db_path() -> Path:
    base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / "dorm-ip" / "history.db"


def _day(ts: float | None = None) -> str:
    return (datetime.fromtimestamp(ts) if ts is not None else datetime.now()).strftime("%Y-%m-%d")


@dataclass
class StandbyEntry:
    ip: str
    ts: float  # when it passed the full test
    score: float
    mac: str
    dns_mode: str


@dataclass
class FailInfo:
    streak: int  # consecutive failures, newest first (portal-login results are ignored)
    last_fail_ts: float
    passed_24h: bool


@dataclass
class Ranking:
    """Everything the hunt order needs from history."""

    scores: dict[str, float] = field(default_factory=dict)  # ip -> 0-100, hour-of-day weighted
    skip: dict[str, float] = field(default_factory=dict)  # ip -> minutes of cooldown left
    busy: dict[str, float] = field(default_factory=dict)  # ip -> share of recent scans that saw it in use


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

    def scores(self, window: int = SCORE_WINDOW, hour: int | None = None) -> dict[str, float]:
        """ip -> weighted mean of the last `window` results, a failed test counting as 0.

        With `hour` (0-23), results from within +-2 hours of that hour of day weigh double: an IP
        that is good in the evening is ranked higher in the evening."""
        rows: dict[str, list[tuple[float, float]]] = {}
        for row in self.conn.execute("SELECT ip, ts, passed, score FROM results ORDER BY ts DESC, id DESC"):
            vals = rows.setdefault(row["ip"], [])
            if len(vals) >= window:
                continue
            weight = 1.0
            if hour is not None:
                diff = abs(datetime.fromtimestamp(row["ts"]).hour - hour)
                if min(diff, 24 - diff) <= HOUR_RADIUS:
                    weight = 2.0
            vals.append((float(row["score"]) if row["passed"] else 0.0, weight))
        return {ip: sum(v * w for v, w in vals) / sum(w for _, w in vals) for ip, vals in rows.items()}

    # ------------------------------------------------------------ smart ordering

    def save_scan(self, used: set[str], ts: float | None = None) -> None:
        """Remember which IPs an ARP scan saw in use (empty scans carry no information)."""
        if not used:
            return
        with self.conn:
            cur = self.conn.execute("INSERT INTO scan_runs(ts) VALUES(?)", (ts if ts is not None else time.time(),))
            self.conn.executemany(
                "INSERT OR IGNORE INTO scan_hits(run_id, ip) VALUES(?, ?)", [(cur.lastrowid, ip) for ip in used]
            )

    def busy_ratio(self, window: int = BUSY_WINDOW) -> dict[str, float]:
        runs = [r["id"] for r in self.conn.execute("SELECT id FROM scan_runs ORDER BY id DESC LIMIT ?", (window,))]
        if not runs:
            return {}
        marks = ",".join("?" * len(runs))
        rows = self.conn.execute(
            f"SELECT ip, COUNT(*) AS n FROM scan_hits WHERE run_id IN ({marks}) GROUP BY ip", runs
        )
        return {r["ip"]: r["n"] / len(runs) for r in rows}

    def recent_failures(self, now: float | None = None, days: int = 7) -> dict[str, FailInfo]:
        now = time.time() if now is None else now
        per_ip: dict[str, list[sqlite3.Row]] = {}
        for row in self.conn.execute(
                "SELECT ip, ts, passed, fail_reason FROM results WHERE ts >= ? ORDER BY ts DESC, id DESC",
                (now - days * 86400,),
        ):
            per_ip.setdefault(row["ip"], []).append(row)
        out: dict[str, FailInfo] = {}
        for ip, rows in per_ip.items():
            streak, last_fail, passed_24h, counting = 0, 0.0, False, True
            for row in rows:
                if row["passed"]:
                    passed_24h = passed_24h or row["ts"] >= now - 86400
                    counting = False
                    continue
                if (row["fail_reason"] or "").startswith(NEUTRAL_FAILURE_PREFIX):
                    continue
                if counting:
                    streak += 1
                    last_fail = max(last_fail, row["ts"])
            out[ip] = FailInfo(streak, last_fail, passed_24h)
        return out

    def ranking(self, skip_base_minutes: float, now: float | None = None, hour: int | None = None) -> Ranking:
        """Scores, cooldowns and busy-ness for ordering the next hunt.

        Cooldown after a failure = skip_base_minutes, doubled per consecutive failure (max 12 h);
        an IP that passed in the last 24 h only gets the base cooldown (good IPs flake)."""
        now = time.time() if now is None else now
        hour = datetime.fromtimestamp(now).hour if hour is None else hour
        skip: dict[str, float] = {}
        if skip_base_minutes > 0:
            for ip, fi in self.recent_failures(now).items():
                if fi.streak == 0:
                    continue
                factor = 1 if fi.passed_24h else 2 ** (fi.streak - 1)
                left = min(skip_base_minutes * factor, SKIP_CAP_MINUTES) - (now - fi.last_fail_ts) / 60
                if left > 0:
                    skip[ip] = left
        return Ranking(self.scores(hour=hour), skip, self.busy_ratio())

    # ------------------------------------------------------------ standby

    def save_standby(self, results: list[TestResult]) -> None:
        """Remember IPs that passed the full test but are not the active one."""
        with self.conn:
            for r in results:
                self.conn.execute(
                    "INSERT INTO standby(ip, ts, score, mac, dns_mode) VALUES(?,?,?,?,?) "
                    "ON CONFLICT(ip) DO UPDATE SET ts=excluded.ts, score=excluded.score, mac=excluded.mac, "
                    "dns_mode=excluded.dns_mode",
                    (r.ip, r.ts, r.score, r.mac, r.dns_mode),
                )

    def standby_list(self, max_age_hours: float, now: float | None = None) -> list[StandbyEntry]:
        """Fresh standby IPs, best score first (expired ones are deleted)."""
        now = time.time() if now is None else now
        with self.conn:
            self.conn.execute("DELETE FROM standby WHERE ts < ?", (now - max_age_hours * 3600,))
        rows = self.conn.execute("SELECT * FROM standby ORDER BY score DESC, ts DESC")
        return [StandbyEntry(r["ip"], r["ts"], r["score"] or 0.0, r["mac"] or "", r["dns_mode"] or "") for r in rows]

    def remove_standby(self, ip: str) -> None:
        with self.conn:
            self.conn.execute("DELETE FROM standby WHERE ip = ?", (ip,))

    def clear_standby(self) -> int:
        with self.conn:
            return self.conn.execute("DELETE FROM standby").rowcount

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
