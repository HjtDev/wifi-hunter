"""The hunt loop: apply a candidate IP, test it, stop at the first that passes."""

from __future__ import annotations

import random
import signal
import time
from collections import deque
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass

from . import applier, netinfo, portal, scanner, triage
from . import tests as nettests
from .config import Config
from .db import Ranking
from .models import NetProfile, TestResult
from .netinfo import NetError

MAX_CONSECUTIVE_APPLY_FAILURES = 3
MAX_LOGIN_FAILURES = 2  # failed auto-logins before the hunt stops trying (avoids locking the account)
DRY_RUN_CANDIDATES = 3


class HuntObserver:
    """UI hooks. The hunter never prints; the CLI subclasses this (no-ops by default)."""

    def note(self, text: str) -> None: ...
    def scanned(self, used: set[str], candidates: list[str]) -> None: ...
    def triage_started(self, ips: list[str]) -> None: ...
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
    # sent from `ip` itself: with several addresses on the interface the login must come from the right one
    return portal.login_detail(cfg.portal, ip=ip, mac=mac, dorm_dns=cfg.dns.default, source_ip=ip or None)


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
        live: bool = False,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        attempts: int = 4,
) -> PortalStatus:
    """After changing the IP: wait for the link, check the portal and log in if needed."""
    wait = cfg.hunt.settle_seconds if live else max(cfg.hunt.settle_seconds * 2, 8.0)
    _wait_ready(cfg, wait, sleep, clock)
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


def _wait_ready(
        cfg: Config, timeout: float, sleep: Callable[[float], None], clock: Callable[[], float]
) -> bool:
    """Poll the gateway until it answers (or `timeout` passes) instead of sleeping a fixed time."""
    deadline = clock() + timeout
    while True:
        _avg, loss, _jit = nettests.ping(cfg.network.gateway, 1, wait=1)
        if loss is not None and loss < 100:
            return True
        if clock() >= deadline:
            return False
        sleep(0.2)


def hunt(
        cfg: Config,
        *,
        observer: HuntObserver | None = None,
        dry_run: bool = False,
        spent: Callable[[], int] | None = None,
        save: Callable[[TestResult], None] | None = None,
        ranking: Ranking | None = None,
        on_scan: Callable[[set[str]], None] | None = None,
        on_standby: Callable[[list[TestResult]], None] | None = None,
        find: int | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        rng: random.Random | None = None,
) -> TestResult | None:
    """Try candidates until `find` of them pass the full test (default 1). Returns the best, or None.

    With live switching available, candidates are first filtered in parallel (triage, several IPs on
    the interface at once) and only the survivors get the full serial test. The best passing IP is kept;
    the other passing ones go to `on_standby`. The original profile is restored when nothing passes,
    on any error, on Ctrl+C and on SIGTERM. `spent()` returns bytes already used today; `save` gets
    every result, `on_scan` every non-empty ARP scan, `ranking` decides the order.
    """
    obs = observer or HuntObserver()
    want = find if find is not None else cfg.hunt.find
    results: list[TestResult] = []
    winners: list[TestResult] = []
    spent_bytes = spent or (lambda: sum(r.bytes_used for r in results))
    budget = cfg.tests.budget_bytes()
    use_override = cfg.dns.hunt_with_override
    dns = cfg.dns.override if use_override else cfg.dns.default
    dns_mode = "override" if use_override else "default"
    n = cfg.network
    rk = ranking or Ranking()

    target = applier.begin_change(n.interface, n.connection, dry_run=dry_run, notify=obs.note)
    done = False
    live_on = cfg.hunt.live_change == "auto" and bool(target.device)
    triage_on = live_on and cfg.hunt.triage_batch >= 2 and not dry_run
    last_mode: str | None = None
    active_ip: str | None = None
    used: set[str] = set()
    control_ip: str | None = None
    if triage_on:
        try:  # the IP we start from works: it proves that sending from a secondary address works too
            control_ip = netinfo.get_profile(n.interface, target.connection).ip
        except NetError:
            control_ip = None
    try:
        with _sigterm_as_interrupt():
            used = _scan(cfg, target, obs, dry_run)
            if on_scan and used and not dry_run:
                on_scan(used)
            order = scanner.candidates(cfg, used, scores=rk.scores, skip=rk.skip, busy=rk.busy, rng=rng)
            todo = order[: cfg.hunt.max_candidates]
            if dry_run:
                todo = todo[:DRY_RUN_CANDIDATES]
            position = {ip: i for i, ip in enumerate(todo, 1)}
            retried = sum(1 for ip in todo if ip in rk.skip)
            cooling = sum(1 for ip in order if ip in rk.skip) - retried
            if cooling > 0:
                obs.note(f"Skipping {cooling} recently failed IPs (use --retry-failed to try them anyway)")
            if retried:
                obs.note(f"Not enough other candidates: retrying {retried} recently failed IPs")
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

            def mac_now() -> str:
                return netinfo.read_mac(target.device) if target.device else ""

            def record(r: TestResult) -> None:
                results.append(r)
                if save:
                    save(r)
                obs.result(r)

            def test_one(ip: str) -> TestResult | None:
                """Switch to `ip` alone and run the full test. None if the switch itself failed."""
                nonlocal apply_failures, live_on, last_mode, active_ip
                obs.trying(ip, position[ip], len(todo))
                try:
                    sw = applier.switch_static(
                        ip, n.prefix, n.gateway, dns, target=target, live=live_on,
                        dry_run=dry_run, sleep=sleep, clock=clock,
                    )
                except NetError as e:
                    apply_failures += 1
                    obs.skipped(ip, str(e))
                    if apply_failures >= MAX_CONSECUTIVE_APPLY_FAILURES:
                        raise NetError(f"{apply_failures} consecutive failures applying an IP; last: {e}") from None
                    return None
                apply_failures = 0
                if live_on and sw.mode != "live":
                    live_on = False
                    obs.note(sw.note)
                elif live_on and last_mode is None and not dry_run:
                    obs.note("Live IP switching works: no reconnect between candidates")
                last_mode = sw.mode
                active_ip = ip
                if dry_run:
                    return None
                profile = NetProfile(
                    interface=target.device, connection=target.connection, method="manual",
                    ip=ip, prefix=n.prefix, gateway=n.gateway, dns=list(dns), mac=mac_now(),
                )
                # a live switch is ready in well under a second; a reconnect needs the wifi to come back
                wait = cfg.hunt.settle_seconds if sw.mode == "live" else max(cfg.hunt.settle_seconds * 2, 8.0)
                obs.stage(ip, "waiting for the gateway")
                ready = _wait_ready(cfg, wait, sleep, clock)
                login_hook = None
                if cfg.portal.enabled and cfg.portal.login_during_hunt:
                    login_hook = lambda: login_for(ip, profile.mac)  # noqa: E731
                r = nettests.run_all(
                    cfg, ip, dns_mode, deep=True, seen_in_use=ip in used, profile=profile,
                    progress=lambda m: obs.stage(ip, m), on_portal=login_hook, gateway_ok=ready,
                )
                record(r)
                return r

            def triage_batch(batch: list[str]) -> list[str] | None:
                """Filter `batch` in parallel. -> survivors, or None if triage does not work here
                (the batch is then put back and tested one by one)."""
                nonlocal triage_on
                control = control_ip if control_ip and control_ip not in batch else None
                addresses = ([control] if control else []) + batch
                sw = applier.switch_many(addresses, n.prefix, n.gateway, dns, target=target, sleep=sleep, clock=clock)

                def give_up(why: str) -> None:
                    nonlocal triage_on
                    triage_on = False
                    queue.extendleft(reversed(batch))
                    obs.note(f"Parallel triage does not work here ({why}); testing one by one")

                if sw.mode != "live":
                    give_up(sw.note)
                    return None
                obs.triage_started(batch)
                sleep(0.5)  # let ARP learn the new addresses
                login = (lambda ip: login_for(ip, mac_now())) if cfg.portal.enabled and cfg.portal.login_during_hunt else None
                trs, ctrl = triage.run_triage(cfg, batch, control=control, login=login)
                if ctrl is not None and not ctrl.passed:
                    give_up("your own IP stopped answering when it was sent from a secondary address")
                    return None
                if ctrl is None and len(batch) >= 4 and all(t.reason == "gateway unreachable" for t in trs.values()):
                    give_up("not one of the extra addresses reached the gateway")
                    return None
                survivors = []
                for ip in batch:
                    if trs[ip].passed:
                        survivors.append(ip)
                    else:
                        record(triage.to_result(cfg, trs[ip], mac=mac_now(), dns_mode=dns_mode, seen_in_use=ip in used))
                return survivors

            queue: deque[str] = deque(todo)
            over_budget = False
            while queue and len(winners) < want and not over_budget:
                if not dry_run and spent_bytes() >= budget:
                    obs.note("Daily data budget reached; stopping")
                    break
                if triage_on and len(queue) >= 2:
                    batch = [queue.popleft() for _ in range(min(cfg.hunt.triage_batch, len(queue)))]
                    survivors = triage_batch(batch)
                    if survivors is None:
                        continue
                    candidates_now = survivors
                else:
                    candidates_now = [queue.popleft()]
                for ip in candidates_now:
                    r = test_one(ip)
                    if r is None:
                        continue
                    if r.passed:
                        winners.append(r)
                        if len(winners) >= want:
                            break
                    if spent_bytes() > budget:
                        obs.note("Daily data budget reached; stopping")
                        over_budget = True
                        break

            if winners:
                best = max(winners, key=lambda w: (w.score, w.ts))
                if want > 1:
                    obs.note(f"{len(winners)} of {want} requested IPs passed; keeping the best ({best.ip}, score {best.score:.0f})")
                others = [w for w in winners if w is not best]
                if on_standby and others:
                    on_standby(others)
                if active_ip != best.ip:  # a better IP was found earlier: go back to it
                    obs.stage(best.ip, "switching back to the best IP")
                    sw = applier.switch_static(
                        best.ip, n.prefix, n.gateway, dns, target=target, live=live_on, sleep=sleep, clock=clock
                    )
                    last_mode = sw.mode
                    st = settle_portal(cfg, best.ip, mac_now(), live=sw.mode == "live", sleep=sleep, clock=clock)
                    if st.state != "open":
                        obs.note(f"{best.ip} shows the portal again ({st.detail or 'login needed'})")
                if last_mode == "live":  # only the final IP is written to the saved profile
                    applier.persist_static(best.ip, n.prefix, n.gateway, dns, connection=target.connection)
                obs.stage(best.ip, "finalizing DNS / portal")
                obs.finalized(finalize(cfg, best, target, sleep=sleep))
                done = True
                return best
            done = dry_run
    finally:
        if not done:
            _restore(obs)
    return None


def failover(
        cfg: Config,
        ips: list[str],
        *,
        save: Callable[[TestResult], None] | None = None,
        drop: Callable[[str], None] | None = None,
        observer: HuntObserver | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        max_tries: int = 3,
) -> TestResult | None:
    """Switch to the first standby IP that still passes a quick re-check (instead of a full hunt).

    Standby IPs already passed the full test earlier; this re-verifies them (gateway, portal, ping,
    DNS, quick speed). A failing one is dropped from the standby list."""
    obs = observer or HuntObserver()
    n = cfg.network
    dns = cfg.dns.override if cfg.dns.hunt_with_override else cfg.dns.default
    dns_mode = "override" if cfg.dns.hunt_with_override else "default"
    target = applier.begin_change(n.interface, n.connection, notify=obs.note)
    live = cfg.hunt.live_change == "auto" and bool(target.device)
    for ip in ips[:max_tries]:
        obs.note(f"Trying standby IP {ip}")
        sw = applier.switch_static(ip, n.prefix, n.gateway, dns, target=target, live=live, sleep=sleep, clock=clock)
        mac = netinfo.read_mac(target.device) if target.device else ""
        profile = NetProfile(
            interface=target.device, connection=target.connection, method="manual", ip=ip,
            prefix=n.prefix, gateway=n.gateway, dns=list(dns), mac=mac,
        )
        wait = cfg.hunt.settle_seconds if sw.mode == "live" else max(cfg.hunt.settle_seconds * 2, 8.0)
        ready = _wait_ready(cfg, wait, sleep, clock)
        hook = (lambda ip=ip: try_login(cfg, ip, mac)) if cfg.portal.enabled else None
        r = nettests.run_all(cfg, ip, dns_mode, deep=False, profile=profile, gateway_ok=ready, on_portal=hook)
        if save:
            save(r)
        if r.passed:
            if sw.mode == "live":
                applier.persist_static(ip, n.prefix, n.gateway, dns, connection=target.connection)
            finalize(cfg, r, target, sleep=sleep)
            return r
        obs.note(f"Standby IP {ip} failed: {r.fail_reason}")
        if drop:
            drop(ip)
    return None
