"""Thin typer CLI. Logic lives in the other modules."""

import ipaddress
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.live import Live
from rich.markup import escape
from rich.table import Table

from . import applier, hunter, netinfo, scanner
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


def _begin_change(st: State, cfg: Config) -> str:
    """Resolve the connection and back up the original profile before changing anything."""
    target = applier.begin_change(
        cfg.network.interface,
        cfg.network.connection,
        dry_run=st.dry_run,
        notify=lambda m: err.print(f"[yellow]{escape(m)}[/yellow]"),
    )
    return target.connection


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


@app.command()
def scan(ctx: typer.Context) -> None:
    """Show which candidate IPs are seen in use (arp-scan) and the order they would be tried."""
    st: State = ctx.obj
    cfg = st.load()
    _conn, device, notes = _scan_target(st, cfg)
    for n in notes:
        err.print(f"[yellow]note:[/yellow] {escape(n)}")
    used = scanner.scan_used(cfg, device, dry_run=st.dry_run)
    if st.dry_run:
        return
    ordered = scanner.candidates(cfg, used)
    unused = len(cfg.ips) - len(used)
    out.print(f"Candidates: {len(cfg.ips)}   seen in use: {len(used)}   unused: {unused}")
    if not used:
        err.print("[yellow]warning:[/yellow] no hosts answered ARP (client isolation or wrong interface?)")
    else:
        key = lambda ip: tuple(int(x) for x in ip.split("."))  # noqa: E731
        out.print("In use: " + ", ".join(sorted(used, key=key)), markup=False, highlight=False)
    out.print("Would try first: " + ", ".join(ordered[:10]), markup=False, highlight=False)


def _scan_target(st: State, cfg: Config) -> tuple[str, str, list[str]]:
    try:
        return netinfo.resolve_connection(cfg.network.interface, cfg.network.connection)
    except NetError:
        if st.dry_run:
            return applier.PLACEHOLDER_CONN, cfg.network.interface, []
        raise


class LiveHunt(hunter.HuntObserver):
    """Rich live table for `hunt`."""

    def __init__(self) -> None:
        self.rows: list[tuple[str, ...]] = []
        self.current: tuple[str, int, int, str] | None = None  # ip, index, total, stage
        self.live: Live | None = None
        self.final: hunter.Finalized | None = None
        self.tried = 0

    def _table(self) -> Table:
        t = Table(box=None, pad_edge=False)
        for col in ("#", "IP", "Seen", "Ping", "Quick", "Sustained", "Collapse", "Score", "Result"):
            t.add_column(col)
        for row in self.rows:
            t.add_row(*row)
        if self.current:
            ip, i, total, stage = self.current
            t.add_row(f"{i}/{total}", ip, "", "", "", "", "", "", f"[dim]{escape(stage)}[/dim]")
        return t

    def _refresh(self) -> None:
        if self.live:
            self.live.update(self._table())

    def note(self, text: str) -> None:
        (self.live.console if self.live else err).print(f"[yellow]{escape(text)}[/yellow]")

    def scanned(self, used: set[str], candidates: list[str]) -> None:
        out.print(f"{len(used)} IPs seen in use. Trying up to {len(candidates)} candidates, unused first.")
        self.live = Live(self._table(), console=out, refresh_per_second=8)
        self.live.start()

    def trying(self, ip: str, index: int, total: int) -> None:
        self.current = (ip, index, total, "applying")
        self._refresh()

    def stage(self, ip: str, text: str) -> None:
        if self.current:
            self.current = (*self.current[:3], text)
            self._refresh()

    def skipped(self, ip: str, why: str) -> None:
        idx = self.current[1] if self.current else len(self.rows) + 1
        self.rows.append((str(idx), ip, "", "", "", "", "", "", f"[red]skipped[/red] {escape(why[:40])}"))
        self.current = None
        self._refresh()

    def result(self, r: TestResult) -> None:
        self.tried += 1
        idx = self.current[1] if self.current else self.tried
        sus = "-" if r.sustained_avg_mbps is None else f"{r.sustained_avg_mbps:.1f}/{r.sustained_min_mbps:.1f}"
        coll = "-" if r.sustained_avg_mbps is None else ("none" if r.collapse_after_mb is None else f"{r.collapse_after_mb:.1f} MB")
        status = "[green]PASS[/green]" if r.passed else f"[red]{escape((r.fail_reason or 'fail')[:42])}[/red]"
        self.rows.append((
            str(idx), r.ip, "yes" if r.seen_in_use else "", _fmt(r.ping_avg_ms, "", 0).strip(),
            _fmt(r.quick_mbps, "").strip(), sus, coll, f"{r.score:.0f}", status,
        ))
        self.current = None
        self._refresh()

    def finalized(self, f: hunter.Finalized) -> None:
        self.final = f

    def close(self) -> None:
        if self.live:
            self.current = None
            if self.rows:
                self._refresh()
            else:
                self.live.update("")
            self.live.stop()
            self.live = None


def _open_portal(url: str) -> None:
    if shutil.which("xdg-open") is None:
        err.print("[yellow]xdg-open not found; open the login page manually[/yellow]")
        return
    subprocess.Popen(["xdg-open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


@app.command("hunt")
def hunt_cmd(
        ctx: typer.Context,
        range_: Annotated[
            str | None,
            typer.Option("--range", help="IP range(s) to try, e.g. 172.18.40.1-172.18.40.50 (comma separated)."),
        ] = None,
        max_: Annotated[int | None, typer.Option("--max", help="Max candidates to try.")] = None,
        order: Annotated[str | None, typer.Option("--order", help="random | sequential | best-history")] = None,
        open_portal: Annotated[bool, typer.Option("--open-portal", help="Open the login page if login is required.")] = False,
) -> None:
    """Find a fast, stable IP: scan, try candidates, stop at the first that passes."""
    st: State = ctx.obj
    ranges = [r.strip() for r in range_.split(",") if r.strip()] if range_ else None
    cfg = st.load()
    if ranges or max_ is not None or order:
        cfg = with_overrides(cfg, ranges=ranges, max_candidates=max_, order=order)
    if cfg.hunt.order == "best-history":
        err.print("[yellow]note:[/yellow] no history yet (phase 4); best-history falls back to random order")

    obs = LiveHunt()
    try:
        result = hunter.hunt(cfg, observer=obs, dry_run=st.dry_run)
    finally:
        obs.close()

    if st.dry_run:
        out.print("[dry-run] no tests were run and nothing was changed", markup=False)
        return
    if result is None:
        err.print(f"[red]No passing IP found[/red] after {obs.tried} tried. Original profile restored.")
        raise SystemExit(1)

    out.print()
    _print_result(result, deep=True)
    f = obs.final
    if f is None:
        return
    out.print(f"\nKept {result.ip} with {f.dns_mode} DNS.")
    if f.portal_state == "open":
        out.print("[green]Portal open: no login needed.[/green]")
    elif f.portal_state == "portal":
        out.print("[bold yellow]Login required[/bold yellow]" + (f": {escape(f.portal_url)}" if f.portal_url else ""))
        if open_portal and f.portal_url:
            _open_portal(f.portal_url)
    else:
        err.print("[yellow]warning:[/yellow] portal check failed after finalizing DNS")


def main() -> None:
    try:
        app()
    except (ConfigError, NetError) as e:
        err.print(f"[red]error:[/red] {escape(str(e))}")
        raise SystemExit(1) from None
    except KeyboardInterrupt:
        err.print("\n[yellow]Interrupted.[/yellow]")
        raise SystemExit(130) from None


if __name__ == "__main__":
    main()
