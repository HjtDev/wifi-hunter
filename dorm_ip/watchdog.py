"""Watch the live connection and re-hunt when it degrades."""

from __future__ import annotations

import subprocess
import time
from collections.abc import Callable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from . import hunter, netinfo
from . import tests as nettests
from .config import Config
from .models import CheckResult, NetProfile, TestResult
from .netinfo import NetError

MAX_COOLDOWN = 1800.0
RESUME_GRACE = 60.0  # seconds of ignored checks after a suspend/resume
GATEWAY_PINGS = 3


class WatchObserver:
    """UI hooks (no-ops by default); the CLI subclasses this."""

    def check(self, c: CheckResult, bad_streak: int, limit: int) -> None: ...
    def note(self, text: str) -> None: ...


# ---------------------------------------------------------------- probes

def probe_url(cfg: Config) -> str:
    """speed_url with its bytes= parameter set to probe_bytes (else speed_url unchanged)."""
    parts = urlsplit(cfg.tests.speed_url)
    query = parse_qsl(parts.query, keep_blank_values=True)
    if not any(k == "bytes" for k, _ in query):
        return cfg.tests.speed_url
    query = [(k, str(cfg.watchdog.probe_bytes) if k == "bytes" else v) for k, v in query]
    return urlunsplit(parts._replace(query=urlencode(query)))


class Prober:
    """Small download on a persistent connection (so TLS setup is not part of the speed)."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.client: httpx.Client | None = None

    def close(self) -> None:
        if self.client is not None:
            self.client.close()
            self.client = None

    def probe(self) -> tuple[float | None, int]:
        """-> (Mbps measured after the response headers, bytes). Mbps None = failed."""
        limit = self.cfg.watchdog.probe_bytes
        total = 0
        try:
            if self.client is None:
                self.client = nettests._client(httpx.Timeout(5.0, read=3.0))
            with self.client.stream("GET", probe_url(self.cfg)) as r:
                if r.status_code != 200:
                    return None, 0
                t0 = time.monotonic()
                for chunk in r.iter_bytes(32768):
                    total += len(chunk)
                    if total >= limit:
                        break
                elapsed = time.monotonic() - t0
        except (httpx.HTTPError, OSError):
            self.close()
            return None, total
        if total < limit * 0.5:  # e.g. a portal page instead of the payload
            return None, total
        return total * 8 / max(elapsed, 1e-6) / 1e6, total


def evaluate(cfg: Config, loss: float | None, mbps: float | None, probe: bool = True) -> tuple[bool, str]:
    """probe=False (VPN active): only the gateway ping counts."""
    reasons: list[str] = []
    if loss is None or loss >= 100:
        reasons.append("gateway unreachable")
    elif loss > cfg.thresholds.max_loss_pct:
        reasons.append(f"loss {loss:.0f}%")
    if probe:
        if mbps is None:
            reasons.append("probe failed")
        elif mbps < cfg.watchdog.min_probe_mbps:
            reasons.append(f"probe {mbps:.1f} Mbps")
    return not reasons, ", ".join(reasons)


def run_check(cfg: Config, profile: NetProfile, prober: Prober, probe: bool = True) -> CheckResult:
    """Gateway ping, then (only if the gateway answers and no VPN is active) the download probe."""
    rtt, loss, _jit = nettests.ping(cfg.network.gateway, GATEWAY_PINGS, wait=1)
    mbps, nbytes = (None, 0) if not probe or loss is None or loss >= 100 else prober.probe()
    ok, note = evaluate(cfg, loss, mbps, probe)
    return CheckResult(
        ts=time.time(), ip=profile.ip or "", mac=profile.mac, gateway_ok=loss is not None and loss < 100,
        loss_pct=loss, rtt_ms=rtt, probe_mbps=mbps, bytes_used=nbytes, ok=ok, note=note,
    )


def send_notification(message: str) -> None:
    """notify-send; silently ignored if unavailable (e.g. no desktop session under sudo)."""
    try:
        subprocess.run(
            ["notify-send", "-a", "dorm-ip", "dorm-ip", message],
            capture_output=True, timeout=5, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        pass


# ---------------------------------------------------------------- watchdog

class Watchdog:
    """Never judges the link while it cannot be judged: wifi down, another network, a VPN carrying
    the traffic, just resumed from suspend, or the link busy with your own traffic."""

    def __init__(
            self,
            cfg: Config,
            *,
            db,  # dorm_ip.db.DB (save, save_check, daily_bytes)
            hunt: Callable[[], TestResult | None],
            failover: Callable[[], TestResult | None] | None = None,
            observer: WatchObserver | None = None,
            notify: Callable[[str], None] | None = None,
            sleep: Callable[[float], None] = time.sleep,
            clock: Callable[[], float] = time.monotonic,
            wall: Callable[[], float] = time.time,
    ) -> None:
        self.cfg = cfg
        self.db = db
        self.hunt = hunt
        self.failover = failover
        self.obs = observer or WatchObserver()
        self.notify = notify or (send_notification if cfg.watchdog.notify else (lambda _m: None))
        self.sleep = sleep
        self.clock = clock
        self.wall = wall
        self.prober = Prober(cfg)
        self.bad = 0
        self.hunt_failures = 0
        self.hold_until = 0.0  # no confirm/re-hunt before this (monotonic time)
        self.budget_warned = False
        self.steps = 0
        self.checks = 0
        self.rehunts = 0
        self.last_wall: float | None = None
        self.grace_until = 0.0  # wall time
        self.paused: str | None = None  # why checks are paused (wifi down / other network)
        self.tunnel: str | None = None  # VPN device while one carries the traffic
        self.last_bytes: tuple[float, int] | None = None  # (wall, rx+tx) for the busy estimate
        self.busy: float | None = None  # Mbps on the wifi interface since the previous check

    # -- main loop
    def run(self, max_steps: int | None = None, max_checks: int | None = None) -> None:
        limit = max_steps if max_steps is not None else max_checks
        try:
            while True:
                self.step()
                if limit is not None and self.steps >= limit:
                    return
                self.sleep(self.cfg.watchdog.interval_seconds)
        finally:
            self.prober.close()

    def _profile(self) -> NetProfile | None:
        try:
            return netinfo.get_profile(self.cfg.network.interface, self.cfg.network.connection)
        except NetError:
            return None

    def _pause(self, reason: str) -> None:
        self.bad = 0
        self.last_bytes = None
        if self.paused != reason:
            self.paused = reason
            self.obs.note(f"Paused: {reason}")

    def _busy_mbps(self, profile: NetProfile) -> float | None:
        total = netinfo.iface_bytes(profile.interface)
        now = self.wall()
        prev, self.last_bytes = self.last_bytes, (now, total) if total is not None else None
        if prev is None or total is None or now <= prev[0]:
            return None
        return max(0.0, (total - prev[1]) * 8 / (now - prev[0]) / 1e6)

    def _ignore_slow_probe_if_busy(self, c: CheckResult) -> CheckResult:
        """A slow probe while *you* are using the link is not the IP's fault."""
        limit = self.cfg.watchdog.busy_mbps
        only_slow = (
                not c.ok and c.gateway_ok and c.probe_mbps is not None
                and c.loss_pct is not None and c.loss_pct <= self.cfg.thresholds.max_loss_pct
        )
        if limit > 0 and only_slow and self.busy is not None and self.busy >= limit:
            c.ok = True
            c.note = f"slow probe ignored: link busy ({self.busy:.1f} Mbps of your own traffic)"
        return c

    def step(self) -> CheckResult | None:
        self.steps += 1
        interval = self.cfg.watchdog.interval_seconds
        wall = self.wall()
        if self.last_wall is not None and wall - self.last_wall > 3 * interval + 10:
            self.bad = 0
            self.last_bytes = None
            self.grace_until = wall + RESUME_GRACE
            self.obs.note(
                f"Resumed after {wall - self.last_wall:.0f}s without checks (suspend?); "
                f"ignoring checks for {RESUME_GRACE:.0f}s while the wifi reconnects"
            )
        self.last_wall = wall
        if wall < self.grace_until:
            return None

        profile = self._profile()
        if profile is None or not profile.ip:
            self._pause("wifi not connected")
            return None
        other = netinfo.check_dorm_network(profile, self.cfg)
        if other:
            self._pause(other)
            return None
        if self.paused:
            self.obs.note("Resumed: connected to the dorm wifi again")
            self.paused = None

        tun = netinfo.tunnel_device(profile.interface)
        if tun != self.tunnel:
            self.tunnel = tun
            self.bad = 0
            self.obs.note(
                f"VPN/tunnel '{tun}' is carrying your traffic: checking the gateway only, no downloads, no re-hunts"
                if tun else "VPN/tunnel is gone: full checks resumed"
            )

        self.busy = self._busy_mbps(profile)
        c = run_check(self.cfg, profile, self.prober, probe=tun is None)
        if tun is None:
            c = self._ignore_slow_probe_if_busy(c)
        self.checks += 1
        self.db.save_check(c)
        self.bad = 0 if c.ok else self.bad + 1
        limit = self.cfg.watchdog.bad_checks_to_rehunt
        self.obs.check(c, self.bad, limit)
        if self.bad >= limit:
            self._degraded(profile, c)
        return c

    # -- reaction
    def _degraded(self, profile: NetProfile | None, c: CheckResult) -> None:
        now = self.clock()
        if now < self.hold_until:
            return  # recently handled (false alarm or failed re-hunt); keep logging only
        ip = profile.ip if profile and profile.ip else ""
        mac = profile.mac if profile else ""
        if self.tunnel:
            # Tests and a re-hunt would measure (and reconnect) the VPN, not the dorm link.
            self.obs.note(f"Gateway problem ({c.note}) while VPN '{self.tunnel}' is active: not re-hunting")
            self.notify(f"Gateway problem while VPN is active ({c.note}); not re-hunting")
            self.hold_until = now + self.cfg.watchdog.rehunt_cooldown_seconds
            return
        self.notify(f"Connection degraded on {ip or 'wifi'}: {c.note}")
        self.obs.note(f"Degraded for {self.bad} checks ({c.note})")

        # 1. Session expired? A logged-out IP shows the portal; logging in again is cheaper than a new IP.
        state, _b, _loc = nettests.check_portal(self.cfg)
        if state == "portal":
            self.obs.note("Portal is asking for login")
            if hunter.try_login(self.cfg, ip, mac):
                state, _b, _loc = nettests.check_portal(self.cfg)
                if state == "open":
                    self.obs.note("Logged in again; connection restored")
                    self.notify("Logged in to the portal again")
                    self.bad = 0
                    return

        # 2. Confirm with a real (small) speed test: the 200 KB probe can be fooled by slow start.
        if profile is not None and profile.ip and state != "portal":
            r = nettests.run_all(
                self.cfg, profile.ip, nettests.detect_dns_mode(profile, self.cfg),
                deep=False, profile=profile,
            )
            self.db.save(r)
            if r.passed:
                self.obs.note("False alarm: quick test passes; keeping this IP")
                self.bad = 0
                self.hold_until = now + self.cfg.watchdog.rehunt_cooldown_seconds
                return
            self.obs.note(f"Confirmed: {r.fail_reason}")

        # 3. Re-hunt (unless today's data budget is gone).
        budget = self.cfg.tests.budget_bytes()
        if self.db.daily_bytes() >= budget:
            if not self.budget_warned:
                self.notify("Daily data budget reached; not re-hunting")
                self.budget_warned = True
            self.obs.note("Daily data budget reached; not re-hunting")
            self.hold_until = now + self.cfg.watchdog.rehunt_cooldown_seconds
            return

        result = None
        if self.failover is not None:  # a pre-qualified standby IP is much cheaper than a hunt
            self.obs.note("Trying standby IPs first")
            try:
                result = self.failover()
            except NetError as e:
                self.obs.note(f"Standby failover error: {e}")
            if result is not None:
                self.obs.note(f"Switched to standby IP {result.ip}")
        if result is None:
            self.rehunts += 1
            self.obs.note("Re-hunting for a better IP")
            try:
                result = self.hunt()
            except NetError as e:
                result = None
                self.obs.note(f"Re-hunt error: {e}")

        if result is not None:
            self.hunt_failures = 0
            self.bad = 0
            self.hold_until = self.clock()  # no extra hold
            self.notify(f"Switched to {result.ip} (score {result.score:.0f})")
            self.obs.note(f"Switched to {result.ip}")
            state, _b, _loc = nettests.check_portal(self.cfg)
            if state == "portal" and not hunter.try_login(self.cfg, result.ip, result.mac):
                self.notify("Login required on the new IP")
                self.obs.note("Login required on the new IP")
        else:
            self.hunt_failures += 1
            wait = min(self.cfg.watchdog.rehunt_cooldown_seconds * 2 ** (self.hunt_failures - 1), MAX_COOLDOWN)
            self.hold_until = self.clock() + wait
            self.notify(f"No better IP found; retrying in {wait / 60:.0f} min")
            self.obs.note(f"No better IP found; next attempt in {wait / 60:.0f} min")
