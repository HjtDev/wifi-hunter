"""Load and validate config.toml. No network values are hard-coded here."""

from __future__ import annotations

import ipaddress
import os
import tomllib
import typing
from dataclasses import MISSING, dataclass, field, fields, replace
from pathlib import Path


class ConfigError(Exception):
    pass


@dataclass
class NetworkCfg:
    prefix: int
    gateway: str
    ranges: list[str]
    interface: str = ""
    connection: str = ""
    exclude: list[str] = field(default_factory=list)
    prefer_unused: bool = True


@dataclass
class DnsCfg:
    default: list[str]
    override: list[str] = field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"])
    hunt_with_override: bool = True
    final_mode: str = "auto"  # default | override | auto


@dataclass
class TestsCfg:
    __test__ = False

    ping_target: str = "1.1.1.1"
    ping_count: int = 5
    connectivity_url: str = "http://connectivitycheck.gstatic.com/generate_204"
    speed_url: str = "https://speed.cloudflare.com/__down?bytes=5000000"
    sustained_seconds: int = 8
    sample_interval: float = 0.5
    data_budget_mb: int = 6000
    sustained_url: str = ""  # optional: one long download; empty = repeat speed_url
    dns_domains: list[str] = field(
        default_factory=lambda: ["google.com", "cloudflare.com", "wikipedia.org"]
    )


@dataclass
class ThresholdsCfg:
    max_ping_ms: float = 80
    max_loss_pct: float = 2
    min_speed_mbps: float = 5
    min_sustained_mbps: float = 4
    collapse_below_mbps: float = 1


@dataclass
class HuntCfg:
    max_candidates: int = 30
    order: str = "random"  # random | sequential | best-history
    settle_seconds: float = 4


@dataclass
class WatchdogCfg:
    interval_seconds: float = 10
    probe_bytes: int = 200000
    bad_checks_to_rehunt: int = 3
    notify: bool = True


@dataclass
class Config:
    network: NetworkCfg
    dns: DnsCfg
    tests: TestsCfg
    thresholds: ThresholdsCfg
    hunt: HuntCfg
    watchdog: WatchdogCfg
    # computed by finalize():
    ips: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    source: Path | None = None


_VALID_FINAL = {"default", "override", "auto"}
_VALID_ORDER = {"random", "sequential", "best-history"}


def _check(value: object, hint: object, name: str) -> object:
    if hint is bool:
        ok = isinstance(value, bool)
    elif hint is int:
        ok = isinstance(value, int) and not isinstance(value, bool)
    elif hint is float:
        ok = isinstance(value, (int, float)) and not isinstance(value, bool)
        if ok:
            value = float(value)  # type: ignore[arg-type]
    elif hint is str:
        ok = isinstance(value, str)
    elif typing.get_origin(hint) is list:
        ok = isinstance(value, list) and all(isinstance(x, str) for x in value)
    else:  # pragma: no cover - only reachable by adding a new field type
        raise ConfigError(f"internal: unsupported type for {name}")
    if not ok:
        raise ConfigError(f"config: {name} has the wrong type (got {value!r})")
    return value


def _build(cls: type, data: object, section: str):
    if not isinstance(data, dict):
        raise ConfigError(f"config: [{section}] must be a table")
    hints = typing.get_type_hints(cls)
    known = {f.name for f in fields(cls)}
    unknown = set(data) - known
    if unknown:
        raise ConfigError(f"config: unknown key(s) in [{section}]: {', '.join(sorted(unknown))}")
    kwargs = {}
    for f in fields(cls):
        if f.name in data:
            kwargs[f.name] = _check(data[f.name], hints[f.name], f"{section}.{f.name}")
        elif f.default is MISSING and f.default_factory is MISSING:
            raise ConfigError(f"config: missing required setting {section}.{f.name}")
    return cls(**kwargs)


def _ip(value: str, name: str) -> ipaddress.IPv4Address:
    try:
        return ipaddress.IPv4Address(value.strip())
    except ValueError:
        raise ConfigError(f"config: {name}: {value!r} is not a valid IPv4 address") from None


def parse_range(spec: str) -> list[ipaddress.IPv4Address]:
    """'A.B.C.D-E.F.G.H' (inclusive) or a single IP."""
    spec = spec.strip()
    if "-" in spec:
        a, b = (s.strip() for s in spec.split("-", 1))
        start, end = _ip(a, "range"), _ip(b, "range")
        if end < start:
            raise ConfigError(f"config: range {spec!r} ends before it starts")
        if int(end) - int(start) > 65535:
            raise ConfigError(f"config: range {spec!r} is too large")
        return [ipaddress.IPv4Address(i) for i in range(int(start), int(end) + 1)]
    return [_ip(spec, "range")]


def _validate(cfg: Config) -> None:
    n = cfg.network
    if not 1 <= n.prefix <= 30:
        raise ConfigError(f"config: network.prefix must be 1-30 (got {n.prefix})")
    _ip(n.gateway, "network.gateway")
    for ip in n.exclude:
        _ip(ip, "network.exclude")
    for ip in cfg.dns.default + cfg.dns.override:
        _ip(ip, "dns")
    if cfg.dns.final_mode not in _VALID_FINAL:
        raise ConfigError(f"config: dns.final_mode must be one of {sorted(_VALID_FINAL)}")
    if cfg.hunt.order not in _VALID_ORDER:
        raise ConfigError(f"config: hunt.order must be one of {sorted(_VALID_ORDER)}")
    if not n.ranges:
        raise ConfigError("config: network.ranges is empty")


def finalize(cfg: Config) -> Config:
    """Expand ranges, drop excluded IPs, and compute warnings."""
    n = cfg.network
    _validate(cfg)
    net = ipaddress.ip_interface(f"{n.gateway}/{n.prefix}").network
    excluded = {_ip(x, "network.exclude") for x in n.exclude} | {_ip(n.gateway, "gateway")}

    seen: set[ipaddress.IPv4Address] = set()
    ips: list[str] = []
    outside: list[str] = []
    special: list[str] = []
    for spec in n.ranges:
        for ip in parse_range(spec):
            if ip in seen or ip in excluded:
                continue
            seen.add(ip)
            if ip in (net.network_address, net.broadcast_address):
                special.append(str(ip))
                continue
            if ip not in net:
                outside.append(str(ip))
            ips.append(str(ip))

    warnings: list[str] = []
    if outside:
        warnings.append(
            f"{len(outside)} candidate IP(s) are outside {net} (gateway {n.gateway}/{n.prefix}), "
            f"e.g. {outside[0]}. Check network.prefix and network.ranges."
        )
    if special:
        warnings.append(
            f"Dropped network/broadcast address(es) of {net}: {', '.join(special[:4])}"
        )
    return replace(cfg, ips=ips, warnings=warnings)


def find_config(explicit: Path | None = None) -> Path:
    if explicit is not None:
        if not explicit.is_file():
            raise ConfigError(f"config file not found: {explicit}")
        return explicit
    xdg = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    for p in (Path("config.toml"), xdg / "dorm-ip" / "config.toml"):
        if p.is_file():
            return p
    raise ConfigError("no config.toml found (looked in ./ and ~/.config/dorm-ip/); use --config PATH")


def load_config(path: Path | None = None) -> Config:
    p = find_config(path)
    try:
        raw = tomllib.loads(p.read_text())
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{p}: invalid TOML: {e}") from None

    known = {"network", "dns", "tests", "thresholds", "hunt", "watchdog"}
    unknown = set(raw) - known
    if unknown:
        raise ConfigError(f"config: unknown section(s): {', '.join(sorted(unknown))}")
    for required in ("network", "dns"):
        if required not in raw:
            raise ConfigError(f"config: missing required section [{required}]")

    cfg = Config(
        network=_build(NetworkCfg, raw["network"], "network"),
        dns=_build(DnsCfg, raw["dns"], "dns"),
        tests=_build(TestsCfg, raw.get("tests", {}), "tests"),
        thresholds=_build(ThresholdsCfg, raw.get("thresholds", {}), "thresholds"),
        hunt=_build(HuntCfg, raw.get("hunt", {}), "hunt"),
        watchdog=_build(WatchdogCfg, raw.get("watchdog", {}), "watchdog"),
        source=p,
    )
    return finalize(cfg)


def with_overrides(
        cfg: Config,
        *,
        ranges: list[str] | None = None,
        gateway: str | None = None,
        prefix: int | None = None,
) -> Config:
    """Apply per-run CLI overrides and re-expand/validate."""
    net = cfg.network
    if ranges is not None:
        net = replace(net, ranges=ranges)
    if gateway is not None:
        net = replace(net, gateway=gateway)
    if prefix is not None:
        net = replace(net, prefix=prefix)
    return finalize(replace(cfg, network=net))
