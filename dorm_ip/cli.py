"""Thin typer CLI. Logic lives in the other modules."""

import ipaddress
import shutil
import signal
import sqlite3
import subprocess
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.live import Live
from rich.markup import escape
from rich.table import Table

from . import applier, hunter, netinfo, portal, scanner, watchdog
from . import tests as nettests
from .config import Config, ConfigError, load_config, with_overrides
from .db import DB, IpStats, open_db
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
    with open_db() as d:
        d.save(result)
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
    obs = LiveHunt()
    d: DB | None = None if st.dry_run else open_db()
    try:
        history = d.scores() if d is not None and cfg.hunt.order == "best-history" else None
        if cfg.hunt.order == "best-history" and not history:
            err.print("[yellow]note:[/yellow] no history yet; best-history falls back to random order")
        result = hunter.hunt(
            cfg, observer=obs, dry_run=st.dry_run, history=history,
            spent=d.daily_bytes if d else None, save=d.save if d else None,
        )
        used_today = d.daily_bytes() if d else 0
    finally:
        obs.close()
        if d is not None:
            d.close()

    if st.dry_run:
        out.print("[dry-run] no tests were run and nothing was changed", markup=False)
        return
    if result is None:
        err.print(f"[red]No passing IP found[/red] after {obs.tried} tried. Original profile restored.")
        raise SystemExit(1)

    out.print()
    _print_result(result, deep=True)
    out.print(f"Data used today: {used_today / 1e6:.0f} MB of {cfg.tests.data_budget_mb} MB budget")
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


def _hour_ranges(hours: list[int]) -> str:
    """[20, 21, 22, 23, 1] -> '1, 20-23'"""
    if not hours:
        return "-"
    hours = sorted(set(hours))
    groups, start, prev = [], hours[0], hours[0]
    for h in hours[1:]:
        if h == prev + 1:
            prev = h
            continue
        groups.append((start, prev))
        start = prev = h
    groups.append((start, prev))
    return ", ".join(str(a) if a == b else f"{a}-{b}" for a, b in groups)


BARS = "▁▂▃▄▅▆▇█"


def _hour_chart(hours: dict[int, tuple[int, int]]) -> tuple[str, str]:
    ruler = "".join(str(h % 10) for h in range(24))
    bars = ""
    for h in range(24):
        n, p = hours.get(h, (0, 0))
        bars += "·" if n == 0 else BARS[round(p / n * (len(BARS) - 1))]
    return ruler, bars


def _stats_row(rank: int, s: IpStats) -> tuple[str, ...]:
    flag = {"bad": "[red]bad[/red]", "flaky": "[yellow]flaky[/yellow]"}.get(s.flag, "")
    return (
        str(rank), s.ip, str(s.tests), f"{s.pass_rate * 100:.0f}%",
        "-" if s.avg_score is None else f"{s.avg_score:.0f}",
        "-" if s.avg_sustained is None else f"{s.avg_sustained:.1f}",
        _hour_ranges(s.good_hours), datetime.fromtimestamp(s.last_ts).strftime("%m-%d %H:%M"), flag,
    )


@app.command()
def history(
        ctx: typer.Context,
        top: Annotated[int, typer.Option("--top", help="How many best IPs to show.")] = 10,
) -> None:
    """Best IPs from past tests, when they were good (hour of day), and IPs that often fail."""
    st: State = ctx.obj
    cfg = st.load()
    with open_db() as d:
        stats = d.ip_stats()
        if not stats:
            out.print("No results yet. Run `dorm-ip test` or `dorm-ip hunt` first.")
            return
        ranked = sorted(stats, key=lambda s: (-s.eff_score, -s.tests))[:top]
        t = Table(box=None, pad_edge=False)
        for col in ("#", "IP", "Tests", "Pass", "Score", "Sust Mbps", "Good hours", "Last", "Flag"):
            t.add_column(col)
        for i, s in enumerate(ranked, 1):
            t.add_row(*_stats_row(i, s))
        out.print(t)

        bad = sorted((s for s in stats if s.flag), key=lambda s: (s.passes / s.tests, -s.tests))
        if bad:
            shown = ", ".join(f"{s.ip} ({s.passes}/{s.tests})" for s in bad[:15])
            out.print(f"\nOften fail (passes/tests): {shown}" + (" ..." if len(bad) > 15 else ""), markup=False, highlight=False)

        ruler, bars = _hour_chart(d.hour_stats())
        out.print(f"\nHour of day  {ruler}\nPass rate    {bars}", markup=False, highlight=False)

        seen = d.seen_stats()
        parts = []
        for flag, label in ((False, "unused IPs"), (True, "IPs seen in use")):
            if flag in seen and seen[flag][0]:
                n, p = seen[flag]
                parts.append(f"{label}: {p / n * 100:.0f}% pass ({n} tests)")
        if parts:
            out.print("By scan: " + "   ".join(parts), markup=False, highlight=False)
        out.print(
            f"Data used today: {d.daily_bytes() / 1e6:.0f} MB of {cfg.tests.data_budget_mb} MB budget",
            markup=False, highlight=False,
        )


class PrintWatch(watchdog.WatchObserver):
    def check(self, c, bad_streak: int, limit: int) -> None:  # type: ignore[override]
        ts = datetime.fromtimestamp(c.ts).strftime("%H:%M:%S")
        status = "[green]ok[/green]" if c.ok else f"[red]BAD {bad_streak}/{limit}[/red]"
        line = (
            f"{ts}  {escape(c.ip or '-'):<15}  gw {_fmt(c.rtt_ms, 'ms', 0)}  loss {_fmt(c.loss_pct, '%', 0)}"
            f"  probe {_fmt(c.probe_mbps, 'Mbps')}  {status}"
        )
        if c.note:
            line += f"  {escape(c.note)}"
        out.print(line)

    def note(self, text: str) -> None:
        out.print(f"[yellow]{escape(text)}[/yellow]")


@app.command()
def watch(
        ctx: typer.Context,
        notify: Annotated[
            bool | None, typer.Option("--notify/--no-notify", help="Desktop notifications (default: from config).")
        ] = None,
) -> None:
    """Watch the connection and re-hunt automatically when it degrades."""
    st: State = ctx.obj
    cfg = st.load()
    if notify is not None:
        cfg = replace(cfg, watchdog=replace(cfg.watchdog, notify=notify))
    w = cfg.watchdog
    per_day = w.probe_bytes * 86400 / w.interval_seconds / 1e6
    out.print(
        f"Watching every {w.interval_seconds:g}s; re-hunt after {w.bad_checks_to_rehunt} bad checks. "
        f"Probe traffic is about {per_day:.0f} MB/day (budget {cfg.tests.data_budget_mb} MB/day). Ctrl+C to stop.",
        markup=False, highlight=False,
    )

    def on_term(signum, frame):  # noqa: ARG001
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, on_term)
    with open_db() as d:

        def do_hunt():
            obs = LiveHunt()
            try:
                history = d.scores() if cfg.hunt.order == "best-history" else None
                return hunter.hunt(
                    cfg, observer=obs, dry_run=st.dry_run, history=history, spent=d.daily_bytes, save=d.save
                )
            finally:
                obs.close()

        wd = watchdog.Watchdog(cfg, db=d, hunt=do_hunt, observer=PrintWatch())
        try:
            wd.run()
        except KeyboardInterrupt:
            out.print(f"\nStopped after {wd.checks} checks, {wd.rehunts} re-hunt(s). The current IP was left as is.")


@app.command()
def login(
        ctx: typer.Context,
        force: Annotated[bool, typer.Option("--force", help="Log in even if the portal already looks open.")] = False,
) -> None:
    """Replay the portal login request configured in the portal section of config.toml."""
    st: State = ctx.obj
    cfg = st.load()
    if st.dry_run:
        p = cfg.portal
        out.print(
            f"[dry-run] would send {p.method} {p.url} with fields: {', '.join(p.fields) or '(none)'}",
            markup=False, highlight=False,
        )
        return
    profile = netinfo.get_profile(cfg.network.interface, cfg.network.connection)
    state, _b, _loc = nettests.check_portal(cfg)
    out.print(f"Portal state: {state}")
    if state == "open" and not force:
        out.print("Already open; nothing to do (use --force to log in anyway).")
        return
    ok, detail = portal.login_detail(cfg.portal, ip=profile.ip or "", mac=profile.mac)
    out.print(("Login request sent: " if ok else "[red]Login failed:[/red] ") + escape(detail))
    state = nettests.check_portal(cfg)[0]
    out.print(f"Portal state now: {state}")
    if not ok or state != "open":
        raise SystemExit(1)



def main() -> None:
    try:
        app()
    except (ConfigError, NetError) as e:
        err.print(f"[red]error:[/red] {escape(str(e))}")
        raise SystemExit(1) from None
    except sqlite3.Error as e:
        err.print(f"[red]database error:[/red] {escape(str(e))}")
        raise SystemExit(1) from None
    except KeyboardInterrupt:
        err.print("\n[yellow]Interrupted.[/yellow]")
        raise SystemExit(130) from None


if __name__ == "__main__":
    main()
