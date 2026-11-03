"""Parallel triage: filter many candidate IPs at once, each tested from its own source address.

Several IPs can sit on one wifi interface at the same time. Triage runs the cheap checks for all of them
in parallel (gateway, portal, loss, a small download that must complete). Because parallel flows share
the wifi bandwidth it only *filters*: it never ranks and never accepts an IP. The survivors then go
through the normal full serial test, so the evidence behind an accepted IP is unchanged.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from . import tests as nettests
from .config import Config
from .models import TestResult

SMALL_DOWNLOAD_BYTES = 300_000
TRIAGE_MAX_LOSS = 25.0  # lenient: parallel flows add loss; the full test applies thresholds.max_loss_pct
TRIAGE_PING_FACTOR = 2.0  # ... and max_ping_ms x 2
TRIAGE_MIN_MBPS = 0.3  # only "stalled or dead" fails here
MAX_WORKERS = 16


@dataclass
class TriageResult:
    ip: str
    passed: bool
    reason: str | None = None
    gateway_ok: bool = False
    portal_state: str = "dead"
    ping_avg_ms: float | None = None
    ping_loss_pct: float | None = None
    bytes_used: int = 0


def triage_one(
    cfg: Config, ip: str, *, login: Callable[[str], bool] | None = None, light: bool = False
) -> TriageResult:
    """Cheap checks for one IP, all sent from `ip`. light=True: gateway only (used for the control IP)."""
    t = TriageResult(ip, False)
    _avg, loss, _jit = nettests.ping(cfg.network.gateway, 2, wait=1, source=ip)
    t.gateway_ok = loss is not None and loss < 100
    if not t.gateway_ok:
        t.reason = "gateway unreachable"
        return t
    if light:
        t.passed = True
        return t

    state, nbytes, detail = nettests.check_portal(cfg, source=ip)
    t.bytes_used += nbytes
    if state == "portal" and login is not None and login(ip):
        state, nbytes, detail = nettests.check_portal(cfg, source=ip)
        t.bytes_used += nbytes
    t.portal_state = state
    if state == "portal":
        t.reason = "captive portal: login required"
        return t
    if state == "dead":
        t.reason = f"no internet: {detail}" if detail else "no internet (connectivity check failed)"
        return t

    t.ping_avg_ms, t.ping_loss_pct, _jit = nettests.ping(cfg.tests.ping_target, 4, source=ip)
    if t.ping_loss_pct is None or t.ping_loss_pct > TRIAGE_MAX_LOSS:
        t.reason = f"packet loss {t.ping_loss_pct or 100:.0f}%"
        return t
    if t.ping_avg_ms is not None and t.ping_avg_ms > cfg.thresholds.max_ping_ms * TRIAGE_PING_FACTOR:
        t.reason = f"ping {t.ping_avg_ms:.0f} ms"
        return t

    complete, got, mbps = nettests.small_download(cfg, SMALL_DOWNLOAD_BYTES, source=ip)
    t.bytes_used += got
    if not complete or mbps is None or mbps < TRIAGE_MIN_MBPS:
        t.reason = "download stalled" if got else "download failed"
        return t
    t.passed = True
    return t


def run_triage(
    cfg: Config,
    ips: list[str],
    *,
    control: str | None = None,
    login: Callable[[str], bool] | None = None,
) -> tuple[dict[str, TriageResult], TriageResult | None]:
    """Triage `ips` in parallel. -> ({ip: result}, control_result). The control IP (a known-good
    address kept on the interface) only gets the gateway check: if even that fails, sending from a
    secondary address does not work on this network."""
    jobs: dict[str, Callable[[], TriageResult]] = {
        ip: (lambda ip=ip: triage_one(cfg, ip, login=login)) for ip in ips
    }
    if control:
        jobs[control] = lambda: triage_one(cfg, control, light=True)

    def safe(ip: str) -> TriageResult:
        try:
            return jobs[ip]()
        except Exception as e:  # one broken probe must not take the whole batch down
            return TriageResult(ip, False, f"triage error ({type(e).__name__})")

    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, max(len(jobs), 1))) as pool:
        futures = {ip: pool.submit(safe, ip) for ip in jobs}
        done = {ip: f.result() for ip, f in futures.items()}
    ctrl = done.pop(control) if control else None
    return {ip: done[ip] for ip in ips}, ctrl


def to_result(cfg: Config, t: TriageResult, *, mac: str, dns_mode: str, seen_in_use: bool) -> TestResult:
    """A failed triage as a TestResult, so it lands in the history (and the cooldown) like any failure."""
    return TestResult(
        ts=time.time(), ip=t.ip, mac=mac, dns_mode=dns_mode, seen_in_use=seen_in_use,
        gateway_ok=t.gateway_ok, portal_state=t.portal_state, ping_avg_ms=t.ping_avg_ms,
        ping_loss_pct=t.ping_loss_pct, ping_jitter_ms=None, dns_ms=None, quick_mbps=None,
        sustained_avg_mbps=None, sustained_min_mbps=None, collapse_after_mb=None,
        bytes_used=t.bytes_used, score=0.0, passed=False, fail_reason=t.reason or "triage failed",
    )