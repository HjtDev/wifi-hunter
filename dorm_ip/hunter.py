"""The hunt loop: apply a candidate IP, test it, stop at the first that passes."""

from __future__ import annotations

import random
import signal
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass

from . import applier, netinfo, portal, scanner
from . import tests as nettests
from .config import Config
from .models import NetProfile, TestResult
from .netinfo import NetError

MAX_CONSECUTIVE_APPLY_FAILURES = 3
MAX_LOGIN_FAILURES = 2  # failed auto-logins before the hunt stops trying (avoids locking the account)
DRY_RUN_CANDIDATES = 3


class HuntObserver:
    """UI hooks. The hunter never prints; the CLI subclasses this (no-ops by default)."""

    def note(self, text: str) -> None: ...
    def scanned(self, used: set[str], candidates: list[str]) -> None: ...
    def trying(self, ip: str, index: int, total: int) -> None: ...
    def stage(self, ip: str, text: str) -> None: ...
    def skipped(self, ip: str, why: str) -> None: ...
    def result(self, r: TestResult) -> None: ...
    def finalized(self, f: Finalized) -> None: ...


@dataclass
class Finalized:
    dns_mode: str  # DNS actually left in place: "default" | "override"
    portal_state: str  # "open" | "portal" | "dead"
    portal_url: str | None = None  # where to log in when portal_state == "portal"


@contextmanager
def _sigterm_as_interrupt() -> Iterator[None]:
    """Treat SIGTERM like Ctrl+C so the finally-block can restore the backup."""

    def handler(signum, frame):  # noqa: ARG001
        raise KeyboardInterrupt

    try:
        old = signal.signal(signal.SIGTERM, handler)
    except ValueError:  # not the main thread
        yield
        return
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, old)


def _login(cfg: Config, ip: str = "", mac: str = "") -> tuple[bool, str]:
    """Portal login with the portal host resolved through the dorm DNS (works under override DNS)."""
    return portal.login_detail(cfg.portal, ip=ip, mac=mac, dorm_dns=cfg.dns.default)


def try_login(cfg: Config, ip: str = "", mac: str = "") -> bool:
    """Single plug-in point for portal auto-login (False when [portal] is not enabled)."""
    return _login(cfg, ip, mac)[0]


@dataclass
class PortalStatus:
    state: str  # "open" | "portal" | "dead"
    logged_in: bool
    detail: str = ""
    url: str | None = None  # where to log in by hand when state == "portal"


def settle_portal(
        cfg: Config,
        ip: str,
        mac: str,
        *,
        login: bool = True,
        sleep: Callable[[float], None] = time.sleep,
        attempts: int = 4,
) -> PortalStatus:
    """After changing the IP: wait for the link, check the portal and log in if needed."""
    sleep(cfg.hunt.settle_seconds)
    state, _b, url = nettests.check_portal(cfg)
    for _ in range(attempts - 1):
        if state != "dead":
            break
        sleep(2)
        state, _b, url = nettests.check_portal(cfg)
    logged_in, detail = False, ""
    if state == "portal":
        if not cfg.portal.enabled:
            detail = "auto-login is not enabled"
        elif not login:
            detail = "auto-login skipped"
        else:
            logged_in, detail = _login(cfg, ip, mac)
            if logged_in:
                sleep(1)
                state, _b, url = nettests.check_portal(cfg)
    if state == "portal" and url is None:
        url = cfg.tests.connectivity_url
    return PortalStatus(state, logged_in and state == "open", detail, url if state == "portal" else None)


def finalize(
        cfg: Config,
        r: TestResult,
        target: applier.Target,
        *,
        sleep: Callable[[float], None] = time.sleep,
) -> Finalized:
    """Leave the passing IP on the DNS chosen by dns.final_mode and report the portal state.

    default : dorm DNS, then portal check
    override: override DNS
    auto    : override if the portal check is 'open', otherwise dorm DNS and re-check
    """
    mode = cfg.dns.final_mode
    current = r.dns_mode  # DNS the candidate was tested with
    state, url = r.portal_state, None  # a passed test means 'open' under that DNS

    def switch(to: str) -> None:
        nonlocal current, state, url
        servers = cfg.dns.override if to == "override" else cfg.dns.default
        applier.set_dns(servers, connection=target.connection)
        current = to
        sleep(cfg.hunt.settle_seconds)
        state, _b, url = nettests.check_portal(cfg)

    if mode == "auto":
        if current != "override":
            switch("override")
        if state != "open":
            switch("default")
    elif current != mode:
        switch(mode)

    if state == "portal" and try_login(cfg, r.ip, r.mac):
        state, _b, url = nettests.check_portal(cfg)
    if state == "portal" and url is None:
        url = cfg.tests.connectivity_url
    return Finalized(dns_mode=current, portal_state=state, portal_url=url if state == "portal" else None)


def _restore(obs: HuntObserver) -> None:
    try:
        conn = applier.restore()
        obs.note(f"Restored original profile of '{conn}'")
    except NetError as e:
        obs.note(f"WARNING: could not restore the original profile ({e}). Run: dorm-ip restore")


def _scan(cfg: Config, target: applier.Target, obs: HuntObserver, dry_run: bool) -> set[str]:
    obs.note("Scanning for IPs in use (arp-scan)...")
    try:
        used = scanner.scan_used(cfg, target.device or None, dry_run=dry_run)
    except NetError as e:
        obs.note(f"Scan skipped, treating every IP as unused: {e}")
        return set()
    if not dry_run and not used:
        obs.note("arp-scan saw no hosts (client isolation or wrong interface?); treating every IP as unused")
    return used


def hunt(
        cfg: Config,
        *,
        observer: HuntObserver | None = None,
        dry_run: bool = False,
        spent: Callable[[], int] | None = None,
        save: Callable[[TestResult], None] | None = None,
        history: dict[str, float] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        rng: random.Random | None = None,
) -> TestResult | None:
    """Try candidates until one passes. Returns the passing result, or None.

    The original profile is restored when nothing passes, on any error, on Ctrl+C and on SIGTERM.
    `spent()` returns bytes already used today (phase 4 passes the database total);
    by default only this run's traffic is counted. `save` is called with every result.
    """
    obs = observer or HuntObserver()
    results: list[TestResult] = []
    spent_bytes = spent or (lambda: sum(r.bytes_used for r in results))
    budget = cfg.tests.budget_bytes()
    use_override = cfg.dns.hunt_with_override
    dns = cfg.dns.override if use_override else cfg.dns.default
    dns_mode = "override" if use_override else "default"
    n = cfg.network

    target = applier.begin_change(n.interface, n.connection, dry_run=dry_run, notify=obs.note)
    done = False
    winner: TestResult | None = None
    try:
        with _sigterm_as_interrupt():
            used = _scan(cfg, target, obs, dry_run)
            order = scanner.candidates(cfg, used, scores=history, rng=rng)
            todo = order[: cfg.hunt.max_candidates]
            if dry_run:
                todo = todo[:DRY_RUN_CANDIDATES]
            obs.scanned(used, todo)

            apply_failures = 0
            login_failures = 0
            logins_done = 0

            def login_for(ip: str, mac: str) -> bool:
                """Auto-login hook for a candidate that shows the portal (with safety limits)."""
                nonlocal login_failures, logins_done
                if login_failures >= MAX_LOGIN_FAILURES or logins_done >= cfg.portal.max_logins_per_hunt:
                    return False
                ok, detail = _login(cfg, ip, mac)
                if ok:
                    login_failures = 0
                    logins_done += 1
                    return True
                login_failures += 1
                suffix = "; not trying again during this hunt" if login_failures >= MAX_LOGIN_FAILURES else ""
                obs.note(f"Auto-login failed ({detail}){suffix}")
                return False

            for i, ip in enumerate(todo, 1):
                if not dry_run and spent_bytes() >= budget:
                    obs.note("Daily data budget reached; stopping")
                    break
                obs.trying(ip, i, len(todo))
                try:
                    applier.apply_static(
                        ip, n.prefix, n.gateway, dns, connection=target.connection, dry_run=dry_run
                    )
                except NetError as e:
                    apply_failures += 1
                    obs.skipped(ip, str(e))
                    if apply_failures >= MAX_CONSECUTIVE_APPLY_FAILURES:
                        raise NetError(f"{apply_failures} consecutive failures applying an IP; last: {e}") from None
                    continue
                apply_failures = 0
                if dry_run:
                    continue

                profile = NetProfile(
                    interface=target.device, connection=target.connection, method="manual",
                    ip=ip, prefix=n.prefix, gateway=n.gateway, dns=list(dns),
                    mac=netinfo.read_mac(target.device) if target.device else "",
                )

                def run_tests(ip: str = ip, profile: NetProfile = profile) -> TestResult:
                    login_hook = None
                    if cfg.portal.enabled and cfg.portal.login_during_hunt:
                        login_hook = lambda: login_for(ip, profile.mac)  # noqa: E731
                    return nettests.run_all(
                        cfg, ip, dns_mode, deep=True, seen_in_use=ip in used, profile=profile,
                        progress=lambda m: obs.stage(ip, m), on_portal=login_hook,
                    )

                sleep(cfg.hunt.settle_seconds)
                r = run_tests()
                if r.fail_reason == "gateway unreachable":
                    # Wifi may still be re-associating after `con up`: give it one more settle period.
                    obs.stage(ip, "gateway not reachable yet, retrying")
                    sleep(cfg.hunt.settle_seconds)
                    r = run_tests()

                results.append(r)
                if save:
                    save(r)
                obs.result(r)
                if r.passed:
                    winner = r
                    break
                if spent_bytes() > budget:
                    obs.note("Daily data budget reached; stopping")
                    break

            if winner:
                obs.stage(winner.ip, "finalizing DNS / portal")
                obs.finalized(finalize(cfg, winner, target, sleep=sleep))
            done = winner is not None or dry_run
    finally:
        if not done:
            _restore(obs)
    return winner
