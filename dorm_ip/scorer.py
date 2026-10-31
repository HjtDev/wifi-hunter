"""TestResult -> (score 0-100, passed, fail_reason). Pure functions, no I/O."""

from __future__ import annotations

from .config import Config
from .models import TestResult

# A speed at FULL_FACTOR x its threshold earns 100 points; at the threshold it earns 100/FULL_FACTOR.
FULL_FACTOR = 5.0
# Sustained sub-score blends average and minimum speed so unstable IPs rank lower.
SUSTAINED_AVG_WEIGHT = 0.7


def _clamp(x: float) -> float:
    return max(0.0, min(100.0, x))


def speed_score(mbps: float | None, threshold: float) -> float | None:
    if mbps is None:
        return None
    if threshold <= 0:
        return 100.0
    return _clamp(100.0 * mbps / (threshold * FULL_FACTOR))


def ping_score(avg_ms: float | None, max_ms: float) -> float | None:
    """100 at <= 25% of the limit, 0 at the limit."""
    if avg_ms is None:
        return None
    best = max_ms * 0.25
    if max_ms <= best:
        return 100.0
    return _clamp(100.0 * (max_ms - avg_ms) / (max_ms - best))


def loss_score(loss_pct: float | None, max_loss: float) -> float | None:
    if loss_pct is None:
        return None
    if max_loss <= 0:
        return 100.0 if loss_pct == 0 else 0.0
    return _clamp(100.0 * (1.0 - loss_pct / max_loss))


def failure(r: TestResult, cfg: Config) -> tuple[str | None, bool]:
    """First failing check as (reason, is_hard_fail). Metrics that were never measured
    (None) are skipped: the hunt stops at the first failure, so later stages stay empty."""
    th = cfg.thresholds
    if not r.gateway_ok:
        return "gateway unreachable", True
    if r.portal_state == "dead":
        return "no internet (connectivity check failed)", True
    if r.portal_state == "portal":
        return "captive portal: login required", True
    if r.ping_loss_pct is not None and r.ping_loss_pct > th.max_loss_pct:
        return f"packet loss {r.ping_loss_pct:.0f}% > {th.max_loss_pct:g}%", True
    if r.collapse_after_mb is not None:
        return f"speed collapsed after {r.collapse_after_mb:.1f} MB", True
    if r.ping_avg_ms is not None and r.ping_avg_ms > th.max_ping_ms:
        return f"ping {r.ping_avg_ms:.0f} ms > {th.max_ping_ms:g} ms", False
    if r.quick_mbps is not None and r.quick_mbps < th.min_speed_mbps:
        return f"quick speed {r.quick_mbps:.1f} Mbps < {th.min_speed_mbps:g} Mbps", False
    if r.sustained_avg_mbps is not None and r.sustained_avg_mbps < th.min_sustained_mbps:
        return f"sustained {r.sustained_avg_mbps:.1f} Mbps < {th.min_sustained_mbps:g} Mbps", False
    return None, False


def score(r: TestResult, cfg: Config) -> tuple[float, bool, str | None]:
    """score = 0.5*sustained + 0.2*quick + 0.2*ping + 0.1*loss.

    Components that were not measured (e.g. --no-deep) are left out and the
    remaining weights are renormalised. A hard fail gives score 0.
    """
    th = cfg.thresholds
    reason, hard = failure(r, cfg)
    if hard:
        return 0.0, False, reason

    sustained = None
    if r.sustained_avg_mbps is not None:
        low = r.sustained_min_mbps if r.sustained_min_mbps is not None else r.sustained_avg_mbps
        blended = SUSTAINED_AVG_WEIGHT * r.sustained_avg_mbps + (1 - SUSTAINED_AVG_WEIGHT) * low
        sustained = speed_score(blended, th.min_sustained_mbps)

    parts = [
        (0.5, sustained),
        (0.2, speed_score(r.quick_mbps, th.min_speed_mbps)),
        (0.2, ping_score(r.ping_avg_ms, th.max_ping_ms)),
        (0.1, loss_score(r.ping_loss_pct, th.max_loss_pct)),
    ]
    measured = [(w, v) for w, v in parts if v is not None]
    total_w = sum(w for w, _ in measured)
    value = sum(w * v for w, v in measured) / total_w if total_w else 0.0
    value = round(value, 1)
    return value, reason is None and value > 0, reason