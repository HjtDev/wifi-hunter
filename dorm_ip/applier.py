"""Change / restore the NetworkManager connection. Every function supports dry_run."""

from __future__ import annotations

import json
import os
import shlex
import sys
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path

from . import netinfo
from .models import NetProfile
from .netinfo import NetError


PLACEHOLDER_CONN = "<active-wifi-connection>"


@dataclass
class Target:
    connection: str
    device: str


def begin_change(
        interface: str,
        connection: str,
        *,
        dry_run: bool = False,
        notify: Callable[[str], None] | None = None,
) -> Target:
    """Resolve the one connection we may modify and back up its original profile.

    In dry-run mode, missing nmcli/wifi falls back to a placeholder so the commands
    can still be previewed.
    """
    say = notify or (lambda m: _say(m))
    try:
        conn, dev, notes = netinfo.resolve_connection(interface, connection)
    except NetError as e:
        if not dry_run:
            raise
        say(f"note: {e}; using a placeholder for --dry-run")
        return Target(PLACEHOLDER_CONN, interface)
    for n in notes:
        say(f"note: {n}")
    try:
        profile = netinfo.get_profile(interface, conn)
    except NetError as e:
        if not dry_run:
            raise
        say(f"note: cannot read profile ({e}); skipping backup in --dry-run")
        return Target(conn, dev)
    backup_profile(profile, dry_run=dry_run)
    return Target(conn, dev)


def backup_path() -> Path:
    base = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state")
    return base / "dorm-ip" / "backup.json"


def _say(msg: str) -> None:
    print(msg, file=sys.stderr)


def _nm(args: list[str], dry_run: bool) -> None:
    cmd = ["nmcli", *args]
    if dry_run:
        print(f"[dry-run] {shlex.join(cmd)}")
        return
    netinfo.run(cmd)


def _list_arg(value: str) -> str:
    return ",".join(netinfo.split_list(value))


# ---------------------------------------------------------------- backup

def backup_profile(p: NetProfile, dry_run: bool = False) -> Path:
    """Save the original profile before the first change.

    An existing backup for the same connection is kept (so a second run can never
    overwrite the true original with an already-modified state). `restore`
    consumes the backup, so the next change takes a fresh one.
    """
    path = backup_path()
    if path.exists():
        try:
            existing = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            existing = {}
        if existing.get("profile", {}).get("connection") == p.connection:
            _say(f"Keeping existing backup of original profile: {path}")
            return path

    data = {"profile": asdict(p), "saved": netinfo.saved_settings(p.connection)}
    if dry_run:
        _say(f"[dry-run] would back up original profile to {path}")
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    tmp.chmod(0o600)
    tmp.replace(path)
    _say(f"Backed up original profile to {path}")
    return path


# ---------------------------------------------------------------- apply

def _static_args(ip: str, prefix: int, gateway: str, dns: list[str]) -> list[str]:
    return [
        "ipv4.method", "manual",
        "ipv4.addresses", f"{ip}/{prefix}",
        "ipv4.gateway", gateway,
        "ipv4.dns", ",".join(dns),
        "ipv4.ignore-auto-dns", "yes" if dns else "no",
    ]


def apply_static(
        ip: str,
        prefix: int,
        gateway: str,
        dns: list[str],
        *,
        connection: str,
        dry_run: bool = False,
) -> None:
    """Change the saved profile and reconnect (the wifi drops and re-associates)."""
    _nm(["con", "mod", connection, *_static_args(ip, prefix, gateway, dns)], dry_run)
    _nm(["con", "up", connection], dry_run)


def apply_live(
        ip: str, prefix: int, gateway: str, dns: list[str], *, device: str, dry_run: bool = False
) -> None:
    """Change the address of the *running* connection only: no reconnect, saved profile untouched."""
    _nm(["device", "modify", device, *_static_args(ip, prefix, gateway, dns)], dry_run)


def persist_static(
        ip: str, prefix: int, gateway: str, dns: list[str], *, connection: str, dry_run: bool = False
) -> None:
    """Save the settings to the profile without reconnecting (after a live switch)."""
    _nm(["con", "mod", connection, *_static_args(ip, prefix, gateway, dns)], dry_run)


def verify_live(
        ip: str,
        device: str,
        *,
        timeout: float = 2.0,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
) -> bool:
    """True once the device has exactly one IPv4 address and it is `ip`."""
    deadline = clock() + timeout
    while True:
        if netinfo.live_addresses(device) == [ip]:
            return True
        if clock() >= deadline:
            return False
        sleep(0.1)


@dataclass
class SwitchResult:
    mode: str  # "live" | "reconnect"
    note: str = ""  # why a live switch was not used


def switch_static(
        ip: str,
        prefix: int,
        gateway: str,
        dns: list[str],
        *,
        target: Target,
        live: bool,
        dry_run: bool = False,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
) -> SwitchResult:
    """Move to `ip`. With live=True try the no-reconnect switch first and *check* that it took
    effect; if it did not (or nmcli refuses), fall back to the normal reconnect."""
    note = ""
    if live and target.device:
        try:
            apply_live(ip, prefix, gateway, dns, device=target.device, dry_run=dry_run)
            if dry_run or verify_live(ip, target.device, sleep=sleep, clock=clock):
                return SwitchResult("live")
            note = "the address did not change on the running connection"
        except NetError as e:
            note = str(e)
        note = f"live IP switching is not working here ({note}); using full reconnects"
    apply_static(ip, prefix, gateway, dns, connection=target.connection, dry_run=dry_run)
    return SwitchResult("reconnect", note)


def apply_dhcp(*, connection: str, dry_run: bool = False) -> None:
    _nm(
        [
            "con", "mod", connection,
            "ipv4.method", "auto",
            "ipv4.addresses", "",
            "ipv4.gateway", "",
            "ipv4.dns", "",
            "ipv4.ignore-auto-dns", "no",
        ],
        dry_run,
    )
    _nm(["con", "up", connection], dry_run)


def set_dns(dns: list[str], *, connection: str, dry_run: bool = False) -> None:
    """Change only the DNS servers, leaving the IP configuration untouched."""
    _nm(
        [
            "con", "mod", connection,
            "ipv4.dns", ",".join(dns),
            "ipv4.ignore-auto-dns", "yes" if dns else "no",
        ],
        dry_run,
    )
    _nm(["con", "up", connection], dry_run)


def restore(dry_run: bool = False, keep_backup: bool = False) -> str:
    """Put the backed-up original settings back. Returns the connection name."""
    path = backup_path()
    if not path.exists():
        raise NetError(f"nothing to restore: no backup at {path}")
    try:
        data = json.loads(path.read_text())
        connection = data["profile"]["connection"]
        saved = data["saved"]
    except (OSError, json.JSONDecodeError, KeyError):
        raise NetError(f"backup file {path} is unreadable or corrupt") from None

    _nm(
        [
            "con", "mod", connection,
            "ipv4.method", saved.get("ipv4.method") or "auto",
            "ipv4.addresses", _list_arg(saved.get("ipv4.addresses", "")),
            "ipv4.gateway", saved.get("ipv4.gateway", ""),
            "ipv4.dns", _list_arg(saved.get("ipv4.dns", "")),
            "ipv4.ignore-auto-dns", saved.get("ipv4.ignore-auto-dns") or "no",
                           ],
        dry_run,
    )
    _nm(["con", "up", connection], dry_run)
    if not dry_run and not keep_backup:
        path.unlink(missing_ok=True)
    return connection
