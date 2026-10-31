"""Thin typer CLI. Logic lives in the other modules."""

import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from . import applier, netinfo
from . import tests as nettests
from .config import Config, ConfigError, load_config, with_overrides
from .models import TestResult
from .netinfo import NetError

app = typer.Typer(
    help="Find a fast, stable static IP on the dorm network.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)
dns_app = typer.Typer(help="Change DNS without touching the IP.", no_args_is_help=True)
app.add_typer(dns_app, name="dns")

out = Console()
err = Console(stderr=True)

PLACEHOLDER_CONN = "<active-wifi-connection>"


@dataclass
class State:
    config_path: Path | None
    dry_run: bool

    def load(self, **overrides) -> Config:
        cfg = load_config(self.config_path)
        if any(v is not None for v in overrides.values()):
            cfg = with_overrides(cfg, **overrides)
        for w in cfg.warnings:
            err.print(f"[yellow]warning:[/yellow] {escape(w)}")
        return cfg


@app.callback()
def _root(
        ctx: typer.Context,
        config: Annotated[Path | None, typer.Option("--config", help="Path to config.toml.")] = None,
        dry_run: Annotated[
            bool, typer.Option("--dry-run", help="Print the exact nmcli commands instead of running them.")
        ] = False,
) -> None:
    ctx.obj = State(config, dry_run)


# ---------------------------------------------------------------- helpers

def _parse_ip(value: str, what: str = "IP") -> ipaddress.IPv4Address:
    try:
        return ipaddress.IPv4Address(value.strip())
    except ValueError:
        raise ConfigError(f"{what} {value!r} is not a valid IPv4 address") from None


def _parse_dns(value: str) -> list[str]:
    servers = netinfo.split_list(value)
    if not servers:
        raise ConfigError("no DNS servers given")
    return [str(_parse_ip(s, "DNS server")) for s in servers]


def _resolve(st: State, cfg: Config) -> str:
    """Connection name to modify (only the configured/active wifi one)."""
    try:
        conn, _dev, notes = netinfo.resolve_connection(cfg.network.interface, cfg.network.connection)
    except NetError as e:
        if not st.dry_run:
            raise
        err.print(f"[yellow]note:[/yellow] {escape(str(e))}; using a placeholder for --dry-run")
        return PLACEHOLDER_CONN
    for n in notes:
        err.print(f"[yellow]note:[/yellow] {escape(n)}")
    return conn


def _begin_change(st: State, cfg: Config) -> str:
    """Resolve the connection and back up the original profile before changing anything."""
    conn = _resolve(st, cfg)
    try:
        profile = netinfo.get_profile(cfg.network.interface, conn)
    except NetError as e:
        if not st.dry_run:
            raise
        err.print(f"[yellow]note:[/yellow] cannot read profile ({escape(str(e))}); skipping backup in --dry-run")
        return conn
    applier.backup_profile(profile, dry_run=st.dry_run)
    return conn


def _done(st: State, msg: str) -> None:
    out.print(("[dry-run] " if st.dry_run else "") + msg, markup=False, highlight=False)


# ---------------------------------------------------------------- commands

@app.command()
def info(ctx: typer.Context) -> None:
    """Show the current network profile and warn on config mismatches."""
    st: State = ctx.obj
    cfg = st.load()
    p = netinfo.get_profile(cfg.network.interface, cfg.network.connection)

    t = Table(show_header=False, box=None, pad_edge=False)
    t.add_column(style="bold")
    t.add_column()
    t.add_row("Connection", p.connection)
    t.add_row("Interface", p.interface or "-")
    t.add_row("Method", "DHCP (auto)" if p.method == "auto" else p.method)
    t.add_row("IP", f"{p.ip}/{p.prefix}" if p.ip else "-")
    t.add_row("Gateway", p.gateway or "-")
    t.add_row("DNS", ", ".join(p.dns) or "-")
    t.add_row("MAC", p.mac or "-")
    t.add_row("Config", str(cfg.source))
    t.add_row("Candidates", f"{len(cfg.ips)} IPs from config")
    out.print(t)

    for w in netinfo.check_profile(p, cfg):
        err.print(f"[yellow]warning:[/yellow] {escape(w)}")


@app.command("set")
def set_ip(
        ctx: typer.Context,
        ip: Annotated[str, typer.Argument(help="Static IPv4 address to apply.")],
        gw: Annotated[str | None, typer.Option("--gw", help="Gateway (overrides config).")] = None,
        dns: Annotated[str | None, typer.Option("--dns", help="DNS servers, comma separated.")] = None,
        prefix: Annotated[int | None, typer.Option("--prefix", help="Prefix length (overrides config).")] = None,
) -> None:
    """Apply a static IP to the configured connection."""
    st: State = ctx.obj
    if gw is not None:
        _parse_ip(gw, "gateway")
    cfg = st.load(gateway=gw, prefix=prefix)
    addr = _parse_ip(ip)
    gateway, plen = cfg.network.gateway, cfg.network.prefix
    dns_list = _parse_dns(dns) if dns else cfg.dns.default

    net = ipaddress.ip_interface(f"{gateway}/{plen}").network
    if str(addr) == gateway:
        raise ConfigError("that IP is the gateway")
    if addr not in net:
        err.print(f"[yellow]warning:[/yellow] {addr} is outside {net}; the gateway will be unreachable")

    conn = _begin_change(st, cfg)
    applier.apply_static(str(addr), plen, gateway, dns_list, connection=conn, dry_run=st.dry_run)
    _done(st, f"Applied {addr}/{plen} gw {gateway} dns {','.join(dns_list)} on '{conn}'")


@app.command()
def dhcp(ctx: typer.Context) -> None:
    """Switch the connection back to automatic (DHCP)."""
    st: State = ctx.obj
    cfg = st.load()
    conn = _begin_change(st, cfg)
    applier.apply_dhcp(connection=conn, dry_run=st.dry_run)
    _done(st, f"'{conn}' is back on DHCP")


@dns_app.command("override")
def dns_override(ctx: typer.Context) -> None:
    """Use the override DNS servers from config (portal bypass)."""
    _change_dns(ctx.obj, None, "override")


@dns_app.command("default")
def dns_default(ctx: typer.Context) -> None:
    """Use the dorm DNS servers from config."""
    _change_dns(ctx.obj, None, "default")


@dns_app.command("set")
def dns_set(
        ctx: typer.Context,
        servers: Annotated[str, typer.Argument(help="Comma separated, e.g. 1.1.1.1,8.8.8.8")],
) -> None:
    """Use specific DNS servers."""
    _change_dns(ctx.obj, _parse_dns(servers), "custom")


def _change_dns(st: State, servers: list[str] | None, mode: str) -> None:
    cfg = st.load()
    if servers is None:
        servers = cfg.dns.override if mode == "override" else cfg.dns.default
    conn = _begin_change(st, cfg)
    applier.set_dns(servers, connection=conn, dry_run=st.dry_run)
    _done(st, f"DNS ({mode}) set to {','.join(servers)} on '{conn}'")


@app.command()
def restore(ctx: typer.Context) -> None:
    """Restore the backed-up original profile."""
    st: State = ctx.obj
    conn = applier.restore(dry_run=st.dry_run)
    _done(st, f"Restored original settings of '{conn}'")


def _fmt(v: float | None, unit: str, digits: int = 1) -> str:
    return "-" if v is None else f"{v:.{digits}f} {unit}"


def _print_result(r: TestResult, deep: bool) -> None:
    portal_style = {"open": "green", "portal": "yellow", "dead": "red"}[r.portal_state]
    t = Table(show_header=False, box=None, pad_edge=False)
    t.add_column(style="bold")
    t.add_column()
    t.add_row("IP", f"{r.ip}  (DNS: {r.dns_mode})")
    t.add_row("MAC", r.mac or "-")
    t.add_row("Gateway", "[green]reachable[/green]" if r.gateway_ok else "[red]unreachable[/red]")
    t.add_row("Portal", f"[{portal_style}]{r.portal_state}[/{portal_style}]")
    t.add_row("Ping", f"{_fmt(r.ping_avg_ms, 'ms')}  loss {_fmt(r.ping_loss_pct, '%', 0)}  jitter {_fmt(r.ping_jitter_ms, 'ms')}")
    t.add_row("DNS", _fmt(r.dns_ms, "ms", 0))
    t.add_row("Quick speed", _fmt(r.quick_mbps, "Mbps"))
    if deep:
        t.add_row("Sustained", f"avg {_fmt(r.sustained_avg_mbps, 'Mbps')}   min {_fmt(r.sustained_min_mbps, 'Mbps')}")
        collapse = "none" if r.collapse_after_mb is None else f"after {r.collapse_after_mb:.1f} MB"
        if r.sustained_avg_mbps is None:
            collapse = "-"
        t.add_row("Collapse", collapse)
    t.add_row("Data used", f"{r.bytes_used / 1e6:.1f} MB")
    t.add_row("Score", f"{r.score:.1f} / 100")
    out.print(t)
    if r.passed:
        out.print("[bold green]PASS[/bold green]")
    else:
        out.print(f"[bold red]FAIL[/bold red]: {escape(r.fail_reason or 'unknown')}")
    if not deep and r.passed:
        err.print("[yellow]note:[/yellow] sustained test skipped; stability not verified")


@app.command("test")
def test_cmd(
        ctx: typer.Context,
        no_deep: Annotated[bool, typer.Option("--no-deep", help="Skip the sustained download test.")] = False,
) -> None:
    """Run the full test suite on the current IP."""
    st: State = ctx.obj
    cfg = st.load()
    profile = netinfo.get_profile(cfg.network.interface, cfg.network.connection)
    if not profile.ip:
        raise NetError(f"'{profile.connection}' has no IPv4 address yet")
    mode = nettests.detect_dns_mode(profile, cfg)
    with out.status("Starting...") as status:
        result = nettests.run_all(
            cfg, profile.ip, mode, deep=not no_deep, profile=profile,
            progress=lambda m: status.update(m),
        )
    _print_result(result, deep=not no_deep)


def main() -> None:
    try:
        app()
    except (ConfigError, NetError) as e:
        err.print(f"[red]error:[/red] {escape(str(e))}")
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
