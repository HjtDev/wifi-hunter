"""Change / restore the NetworkManager connection. Every function supports dry_run."""

from __future__ import annotations

import json
import os
import shlex
import sys
from dataclasses import asdict
from pathlib import Path

from . import netinfo
from .models import NetProfile
from .netinfo import NetError


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

def apply_static(
        ip: str,
        prefix: int,
        gateway: str,
        dns: list[str],
        *,
        connection: str,
        dry_run: bool = False,
) -> None:
    _nm(
        [
            "con", "mod", connection,
            "ipv4.method", "manual",
            "ipv4.addresses", f"{ip}/{prefix}",
            "ipv4.gateway", gateway,
            "ipv4.dns", ",".join(dns),
            "ipv4.ignore-auto-dns", "yes" if dns else "no",
        ],
        dry_run,
    )
    _nm(["con", "up", connection], dry_run)


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


def restore(dry_run: bool = False) -> str:
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
    if not dry_run:
        path.unlink(missing_ok=True)
    return connection
