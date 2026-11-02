"""`dorm-ip live-check`: measure on this machine whether switching the IP without a reconnect works,
and how much faster it is than the normal reconnect."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from . import applier, netinfo
from . import tests as nettests
from .config import Config
from .netinfo import NetError


@dataclass
class StepTiming:
    method: str  # "live" | "reconnect"
    applied_s: float | None  # how long the nmcli command took
    visible_s: float | None  # until the new address showed up (None = it never did)
    gateway_s: float | None  # until the gateway answered from the new address (None = never)
    note: str = ""


def _poll(check: Callable[[], bool], timeout: float, t0: float, sleep, clock) -> float | None:
    while True:
        if check():
            return clock() - t0
        if clock() - t0 >= timeout:
            return None
        sleep(0.1)


def _gateway_up(cfg: Config) -> bool:
    _avg, loss, _jit = nettests.ping(cfg.network.gateway, 1, wait=1)
    return loss is not None and loss < 100


def measure(
    cfg: Config, target: applier.Target, ip: str, dns: list[str], method: str,
    *, sleep=time.sleep, clock=time.monotonic,
) -> StepTiming:
    n = cfg.network
    t0 = clock()
    try:
        if method == "live":
            applier.apply_live(ip, n.prefix, n.gateway, dns, device=target.device)
        else:
            applier.apply_static(ip, n.prefix, n.gateway, dns, connection=target.connection)
    except NetError as e:
        return StepTiming(method, None, None, None, str(e))
    applied = clock() - t0
    visible = _poll(lambda: netinfo.live_addresses(target.device) == [ip], 20.0, t0, sleep, clock)
    gateway = _poll(lambda: _gateway_up(cfg), 25.0, t0, sleep, clock)
    return StepTiming(method, applied, visible, gateway)


def run_live_check(
    cfg: Config, target: applier.Target, ip: str, *, compare: bool,
    sleep=time.sleep, clock=time.monotonic,
) -> list[StepTiming]:
    """Switch to `ip` live (and, with compare, by reconnecting), then put the original profile back."""
    dns = cfg.dns.override if cfg.dns.hunt_with_override else cfg.dns.default
    steps = [measure(cfg, target, ip, dns, "live", sleep=sleep, clock=clock)]
    try:
        if compare:
            applier.restore(keep_backup=True)  # back to the original before the second measurement
            _poll(lambda: _gateway_up(cfg), 25.0, clock(), sleep, clock)
            steps.append(measure(cfg, target, ip, dns, "reconnect", sleep=sleep, clock=clock))
    finally:
        applier.restore()
    return steps


def verdict(steps: list[StepTiming]) -> tuple[str, str]:
    """-> (level, message) with level in ok | warn | bad."""
    live = steps[0]
    if live.note:
        return "bad", f"nmcli refused the live change ({live.note}). Set hunt.live_change = \"off\"."
    if live.visible_s is None:
        return "bad", "The new address never appeared on the running connection: live switching does not work here. Set hunt.live_change = \"off\"."
    if live.gateway_s is None:
        return "warn", "The address changed live, but the gateway never answered. Either this IP is dead (retry with a known-good one using --ip) or live switching does not carry traffic here."
    msg = f"Live switching works: the new IP was usable after {live.gateway_s:.1f}s."
    if len(steps) > 1 and steps[1].gateway_s is not None:
        msg += f" A reconnect needed {steps[1].gateway_s:.1f}s ({steps[1].gateway_s / max(live.gateway_s, 0.01):.0f}x slower)."
    return "ok", msg