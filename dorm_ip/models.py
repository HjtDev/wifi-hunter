from __future__ import annotations

from dataclasses import dataclass


@dataclass
class NetProfile:
    interface: str
    connection: str
    method: str  # "auto" | "manual" (as reported by NetworkManager)
    ip: str | None
    prefix: int | None
    gateway: str | None
    dns: list[str]
    mac: str


@dataclass
class TestResult:
    __test__ = False  # stop pytest from trying to collect this class

    ts: float
    ip: str
    mac: str
    dns_mode: str  # "default" | "override"
    seen_in_use: bool
    gateway_ok: bool
    portal_state: str  # "open" | "portal" | "dead"
    ping_avg_ms: float | None
    ping_loss_pct: float | None
    ping_jitter_ms: float | None
    dns_ms: float | None
    quick_mbps: float | None
    sustained_avg_mbps: float | None
    sustained_min_mbps: float | None
    collapse_after_mb: float | None  # None = no collapse
    bytes_used: int
    score: float  # 0-100
    passed: bool
    fail_reason: str | None


@dataclass
class SustainedResult:
    avg_mbps: float
    min_mbps: float
    collapse_after_mb: float | None  # None = no collapse
    bytes_used: int
    duration: float  # seconds actually measured


@dataclass
class CheckResult:
    """One watchdog check of the live connection."""

    ts: float
    ip: str
    mac: str
    gateway_ok: bool
    loss_pct: float | None
    rtt_ms: float | None
    probe_mbps: float | None
    bytes_used: int
    ok: bool
    note: str
