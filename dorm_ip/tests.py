"""Connectivity, ping, DNS, speed and sustained-download tests.

Order is cheap -> expensive and the suite fails fast to save the daily data quota.
"""

from __future__ import annotations

import random
import re
import socket
import struct
import subprocess
import time
from collections.abc import Callable
from urllib.parse import urlsplit

import httpx

from . import netinfo, scorer
from .config import Config
from .models import NetProfile, SustainedResult, TestResult
from .netinfo import NetError

Progress = Callable[[str], None]

_RE_LOSS = re.compile(r"(\d+(?:\.\d+)?)% packet loss")
_RE_RTT = re.compile(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms")
COLLAPSE_SECONDS = 2.0


# ---------------------------------------------------------------- ping

def parse_ping(text: str) -> tuple[float | None, float | None, float | None]:
    """iputils ping summary -> (avg_ms, loss_pct, jitter_ms). Loss is None if unparsable."""
    m = _RE_LOSS.search(text)
    if not m:
        return None, None, None
    loss = float(m.group(1))
    r = _RE_RTT.search(text)
    if not r:
        return None, loss, None
    return float(r.group(2)), loss, float(r.group(4))  # avg, loss, mdev as jitter


def ping(target: str, count: int, wait: int = 2) -> tuple[float | None, float | None, float | None]:
    cmd = ["ping", "-n", "-q", "-c", str(count), "-i", "0.3", "-W", str(wait), target]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=count * (wait + 1) + 5)
    except FileNotFoundError:
        raise NetError("'ping' not found; install iputils") from None
    except subprocess.TimeoutExpired:
        return None, 100.0, None
    avg, loss, jitter = parse_ping(p.stdout)
    if loss is None:
        return None, 100.0, None
    return avg, loss, jitter


def gateway_reachable(gateway: str) -> bool:
    _, loss, _ = ping(gateway, 2, wait=1)
    return loss is not None and loss < 100.0


# ---------------------------------------------------------------- http

def _client(timeout: httpx.Timeout | None = None) -> httpx.Client:
    return httpx.Client(
        timeout=timeout or httpx.Timeout(8.0, read=4.0),
        follow_redirects=False,
        trust_env=False,  # ignore proxy env vars so we measure the real link
    )


def classify_portal(status: int, content_type: str, body: bytes) -> str:
    """'open' (204), 'portal' (redirect or HTML page), else 'dead'."""
    if status == 204:
        return "open"
    if 300 <= status < 400:
        return "portal"
    if "html" in content_type.lower() or body.lstrip()[:1] == b"<":
        return "portal"
    return "dead"


def check_portal(cfg: Config) -> tuple[str, int, str | None]:
    """-> (state, bytes_used, portal_url). state: open | portal | dead."""
    try:
        with _client(httpx.Timeout(5.0)) as c:
            r = c.get(cfg.tests.connectivity_url)
            body = r.content[:4096]
            state = classify_portal(r.status_code, r.headers.get("content-type", ""), body)
            return state, len(r.content), r.headers.get("location")
    except (httpx.HTTPError, OSError):
        return "dead", 0, None


def quick_speed(cfg: Config, max_seconds: float = 20.0) -> tuple[float | None, int]:
    """One download of speed_url -> (Mbps measured after the first byte, bytes)."""
    try:
        with _client() as c, c.stream("GET", cfg.tests.speed_url) as r:
            if r.status_code != 200:
                return None, 0
            total = 0
            t0 = None
            deadline = time.monotonic() + max_seconds
            for chunk in r.iter_bytes(65536):
                now = time.monotonic()
                if t0 is None:
                    t0 = now
                    continue  # time starts at the first chunk; don't count its bytes
                total += len(chunk)
                if now >= deadline:
                    break
            if t0 is None:
                return None, 0
            elapsed = time.monotonic() - t0
            if total == 0 or elapsed <= 0:
                return None, total
            return total * 8 / elapsed / 1e6, total
    except (httpx.HTTPError, OSError):
        return None, 0


# ---------------------------------------------------------------- dns

def build_dns_query(domain: str, qid: int) -> bytes:
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in domain.strip(".").split(".")) + b"\x00"
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)


def dns_response_ok(data: bytes, qid: int) -> bool:
    if len(data) < 12:
        return False
    rid, flags, _qd, an = struct.unpack("!HHHH", data[:8])
    return rid == qid and bool(flags & 0x8000) and (flags & 0xF) == 0 and an > 0


def dns_query_ms(server: str, domain: str, timeout: float = 2.0) -> float | None:
    """Ask `server` directly (UDP/53) so we time the active DNS, not a local cache."""
    qid = random.randrange(0x10000)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        t0 = time.perf_counter()
        try:
            s.sendto(build_dns_query(domain, qid), (server, 53))
            while True:
                data, _ = s.recvfrom(2048)
                if dns_response_ok(data, qid):
                    return (time.perf_counter() - t0) * 1000
                if time.perf_counter() - t0 > timeout:
                    return None
        except OSError:
            return None


def dns_time(servers: list[str], domains: list[str]) -> float | None:
    """Average resolve time in ms over the domains that answered; None if none did."""
    v4 = [s for s in servers if ":" not in s]
    if not v4:
        return None
    times = [t for d in domains if (t := dns_query_ms(v4[0], d)) is not None]
    return sum(times) / len(times) if times else None


# ---------------------------------------------------------------- sustained

def analyze_samples(
    samples: list[tuple[float, int]], collapse_below_mbps: float
) -> SustainedResult:
    """samples = [(seconds, cumulative_bytes)], starting at (0, 0).

    avg: total over total time. min: slowest interval, ignoring the first one (TCP slow start)
    when there are at least 3. collapse: speed stayed under the limit for >= 2 s;
    reported as the MB downloaded when that low stretch began.
    """
    if len(samples) < 2:
        return SustainedResult(0.0, 0.0, 0.0, 0, 0.0)
    rates: list[float] = []
    collapse_mb: float | None = None
    streak: tuple[float, int] | None = None
    for (t0, b0), (t1, b1) in zip(samples, samples[1:]):
        dt = t1 - t0
        if dt <= 0:
            continue
        rate = (b1 - b0) * 8 / dt / 1e6
        rates.append(rate)
        if rate < collapse_below_mbps:
            if streak is None:
                streak = (t0, b0)
            if collapse_mb is None and t1 - streak[0] >= COLLAPSE_SECONDS - 1e-6:
                collapse_mb = streak[1] / 1e6
        else:
            streak = None
    t_end, b_end = samples[-1]
    avg = b_end * 8 / t_end / 1e6 if t_end > 0 else 0.0
    pool = rates[1:] if len(rates) >= 3 else rates
    return SustainedResult(avg, min(pool) if pool else 0.0, collapse_mb, b_end, t_end)


def sustained(cfg: Config) -> SustainedResult:
    """Stream downloads for sustained_seconds, sampling throughput every sample_interval.

    Repeats speed_url on one keep-alive connection (or streams tests.sustained_url if set).
    A stalled stream (read timeout) is recorded as zero speed until the end of the window.
    """
    t = cfg.tests
    url = t.sustained_url or t.speed_url
    interval, window = t.sample_interval, float(t.sustained_seconds)
    samples: list[tuple[float, int]] = [(0.0, 0)]
    total = 0
    start = time.monotonic()
    deadline = start + window
    next_sample = start + interval
    stalled = False

    def record(now: float) -> None:
        nonlocal next_sample
        samples.append((now - start, total))
        next_sample = now + interval

    try:
        with _client(httpx.Timeout(5.0, read=2.0)) as c:
            while time.monotonic() < deadline and not stalled:
                with c.stream("GET", url) as r:
                    if r.status_code != 200:
                        stalled = True
                        break
                    for chunk in r.iter_bytes(65536):
                        total += len(chunk)
                        now = time.monotonic()
                        if now >= next_sample:
                            record(now)
                        if now >= deadline:
                            break
                    if time.monotonic() >= deadline:
                        break
    except (httpx.HTTPError, OSError):
        stalled = True

    now = time.monotonic()
    if stalled:
        # Dead stream: fill the rest of the window with zero-speed samples.
        if now - start > samples[-1][0]:
            record(now)
        while samples[-1][0] + interval <= window:
            samples.append((samples[-1][0] + interval, total))
    elif now - start > samples[-1][0]:
        record(now)
    return analyze_samples(samples, cfg.thresholds.collapse_below_mbps)


# ---------------------------------------------------------------- orchestration

def detect_dns_mode(profile: NetProfile, cfg: Config) -> str:
    if profile.dns and profile.dns == cfg.dns.override:
        return "override"
    if profile.dns and profile.dns == cfg.dns.default:
        return "default"
    return "custom"


def run_all(
    cfg: Config,
    ip: str,
    dns_mode: str,
    deep: bool = True,
    *,
    seen_in_use: bool = False,
    profile: NetProfile | None = None,
    progress: Progress | None = None,
) -> TestResult:
    """Run the suite in order and stop at the first failure. bytes_used counts HTTP
    payload only (ping/DNS traffic is negligible)."""
    say = progress or (lambda _m: None)
    if profile is None:
        profile = netinfo.get_profile(cfg.network.interface, cfg.network.connection)

    r = TestResult(
        ts=time.time(), ip=ip, mac=profile.mac, dns_mode=dns_mode, seen_in_use=seen_in_use,
        gateway_ok=False, portal_state="dead", ping_avg_ms=None, ping_loss_pct=None,
        ping_jitter_ms=None, dns_ms=None, quick_mbps=None, sustained_avg_mbps=None,
        sustained_min_mbps=None, collapse_after_mb=None, bytes_used=0, score=0.0,
        passed=False, fail_reason=None,
    )

    def finish(forced: str | None = None) -> TestResult:
        r.score, r.passed, r.fail_reason = scorer.score(r, cfg)
        if forced and r.fail_reason is None:
            r.score, r.passed, r.fail_reason = 0.0, False, forced
        return r

    def failed() -> bool:
        return scorer.failure(r, cfg)[0] is not None

    say("Gateway reachable?")
    r.gateway_ok = gateway_reachable(cfg.network.gateway)
    if not r.gateway_ok:
        return finish()

    say("Portal / connectivity check")
    r.portal_state, nbytes, _loc = check_portal(cfg)
    r.bytes_used += nbytes
    if failed():
        return finish()

    say("Ping")
    r.ping_avg_ms, r.ping_loss_pct, r.ping_jitter_ms = ping(cfg.tests.ping_target, cfg.tests.ping_count)
    if failed():
        return finish()

    say("DNS lookups")
    r.dns_ms = dns_time(profile.dns, cfg.tests.dns_domains)
    if r.dns_ms is None:
        return finish(forced=f"DNS lookups failed (servers: {', '.join(profile.dns) or 'none'})")

    say("Quick speed test")
    r.quick_mbps, nbytes = quick_speed(cfg)
    r.bytes_used += nbytes
    if r.quick_mbps is None:
        return finish(forced="download failed")
    if failed():
        return finish()

    if deep:
        say(f"Sustained test ({cfg.tests.sustained_seconds}s)")
        s = sustained(cfg)
        r.sustained_avg_mbps, r.sustained_min_mbps = s.avg_mbps, s.min_mbps
        r.collapse_after_mb = s.collapse_after_mb
        r.bytes_used += s.bytes_used
    return finish()