"""Find IPs in use (arp-scan) and order the candidates to try."""

from __future__ import annotations

import ipaddress
import os
import random
import re
import shlex
import shutil

from . import netinfo
from .config import Config
from .netinfo import NetError

_RE_HOST = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})")
_PRIV_HINTS = ("permission", "root", "not permitted", "insufficient", "privilege")
NEUTRAL_SCORE = 50.0


def parse_arp_scan(text: str) -> set[str]:
    """`arp-scan --plain` lines: 'IP<TAB>MAC<TAB>vendor'."""
    found: set[str] = set()
    for line in text.splitlines():
        m = _RE_HOST.match(line.strip())
        if m:
            found.add(m.group(1))
    return found


def arp_command(cfg: Config, interface: str) -> list[str]:
    """arp-scan over the configured ranges only (never the whole subnet)."""
    cmd = ["arp-scan", "--interface", interface, "--plain", "--quiet", "--retry", "2"]
    return cmd + [r.replace(" ", "") for r in cfg.network.ranges]


def scan_used(cfg: Config, interface: str | None = None, *, dry_run: bool = False) -> set[str]:
    """IPs from the candidate list that answered ARP. Retries with sudo if not privileged."""
    iface = interface or cfg.network.interface
    if not iface:
        raise NetError("no interface to scan on; set network.interface")
    cmd = arp_command(cfg, iface)
    if dry_run:
        print(f"[dry-run] {shlex.join(cmd)}")
        return set()
    if shutil.which("arp-scan") is None:
        raise NetError("arp-scan is not installed (sudo pacman -S arp-scan)")
    try:
        text = netinfo.run(cmd, timeout=120)
    except NetError as e:
        if os.geteuid() != 0 and any(h in str(e).lower() for h in _PRIV_HINTS):
            text = netinfo.run(["sudo", *cmd], timeout=120)
        else:
            raise
    return parse_arp_scan(text) & set(cfg.ips)


def _ip_key(ip: str) -> int:
    return int(ipaddress.IPv4Address(ip))


NEAR_RADIUS = 3  # "next to a known-good IP" = within 3 addresses
NEAR_BONUS = 10.0  # score points for an untested IP near a good one
GOOD_SCORE = 60.0
BUSY_PENALTY = 20.0  # score points lost by an IP that is always in use


def candidates(
        cfg: Config,
        used: set[str],
        *,
        order: str | None = None,
        scores: dict[str, float] | None = None,
        skip: dict[str, float] | None = None,
        busy: dict[str, float] | None = None,
        rng: random.Random | None = None,
) -> list[str]:
    """All candidate IPs in the order to try them.

    prefer_unused: IPs not seen in the ARP scan come first (used ones are kept, just later).
    Within each group: random | sequential | best-history.
    best-history ranks by score (history, hour-of-day weighted; unknown = neutral), minus a penalty
    for IPs that are often seen in use, plus a small bonus for untested IPs next to good ones
    (hunt.explore_near_good). Without any history it is plain random.
    `skip` (recently failed IPs) are moved to the very end, so they are only reached when there
    are not enough other candidates.
    """
    order = order or cfg.hunt.order
    rng = rng or random.Random()
    scores = scores or {}
    busy = busy or {}
    skip = skip or {}

    good = [_ip_key(ip) for ip, sc in scores.items() if sc >= GOOD_SCORE]

    def rank(ip: str) -> float:
        value = scores.get(ip, NEUTRAL_SCORE)
        if cfg.hunt.explore_near_good and ip not in scores and any(abs(_ip_key(ip) - g) <= NEAR_RADIUS for g in good):
            value += NEAR_BONUS
        return value - BUSY_PENALTY * busy.get(ip, 0.0)

    def arrange(group: list[str]) -> list[str]:
        if order == "sequential":
            return sorted(group, key=_ip_key)
        shuffled = group[:]
        rng.shuffle(shuffled)
        if order == "best-history" and (scores or busy):
            return sorted(shuffled, key=lambda ip: -rank(ip))
        return shuffled

    ips = [ip for ip in cfg.ips if ip not in skip]
    cooling = [ip for ip in cfg.ips if ip in skip]
    if cfg.network.prefer_unused:
        ordered = arrange([i for i in ips if i not in used]) + arrange([i for i in ips if i in used])
    else:
        ordered = arrange(ips)
    # the ones with the shortest cooldown left come first among the skipped
    return ordered + sorted(cooling, key=lambda ip: skip[ip])
