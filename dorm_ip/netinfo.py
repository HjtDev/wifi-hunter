"""Read the current network state from NetworkManager (nmcli) and sysfs."""

from __future__ import annotations

import ipaddress
import re
import shlex
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from .models import NetProfile

if TYPE_CHECKING:
    from .config import Config

SAVED_FIELDS = [
    "ipv4.method",
    "ipv4.addresses",
    "ipv4.gateway",
    "ipv4.dns",
    "ipv4.ignore-auto-dns",
]
_WIFI_TYPES = {"802-11-wireless", "wifi"}


class NetError(Exception):
    pass


def run(args: list[str], timeout: float = 30) -> str:
    """Run a command, return stdout, raise NetError on any failure."""
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise NetError(f"'{args[0]}' not found; is it installed?") from None
    except subprocess.TimeoutExpired:
        raise NetError(f"timed out: {shlex.join(args)}") from None
    if p.returncode != 0:
        detail = p.stderr.strip() or p.stdout.strip() or f"exit code {p.returncode}"
        raise NetError(f"{shlex.join(args)} failed: {detail}")
    return p.stdout


def nmcli(*args: str) -> str:
    return run(["nmcli", *args])


# ---------------------------------------------------------------- parsing

def split_terse(line: str) -> list[str]:
    """Split an `nmcli -t` line on unescaped ':' and unescape '\\:' and '\\\\'."""
    parts: list[str] = []
    cur: list[str] = []
    i = 0
    while i < len(line):
        c = line[i]
        if c == "\\" and i + 1 < len(line):
            cur.append(line[i + 1])
            i += 2
            continue
        if c == ":":
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    parts.append("".join(cur))
    return parts


def parse_kv(text: str) -> dict[str, str]:
    """Parse `nmcli -t -f a,b con show X` output (key:value per line)."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if not sep:
            continue
        value = value.replace("\\:", ":").strip()
        out[key.strip()] = "" if value == "--" else value
    return out


def split_list(value: str) -> list[str]:
    return [x for x in re.split(r"[,\s]+", value.strip()) if x]


def parse_active(text: str) -> list[tuple[str, str, str]]:
    """Parse `nmcli -t -f NAME,TYPE,DEVICE con show --active` -> (name, type, device)."""
    rows = []
    for line in text.splitlines():
        parts = split_terse(line)
        if len(parts) >= 3:
            rows.append((parts[0], parts[1], parts[2]))
    return rows


def parse_live(text: str) -> tuple[str | None, int | None, str | None, list[str]]:
    """Parse `nmcli -t -f IP4.ADDRESS,IP4.GATEWAY,IP4.DNS dev show X`."""
    kv = parse_kv(text)
    ip = prefix = gateway = None
    dns: list[str] = []
    for key, value in kv.items():
        if key.startswith("IP4.ADDRESS") and ip is None and value:
            addr, _, plen = value.partition("/")
            ip = addr
            prefix = int(plen) if plen.isdigit() else None
        elif key == "IP4.GATEWAY" and value:
            gateway = value
        elif key.startswith("IP4.DNS") and value:
            dns.append(value)
    return ip, prefix, gateway, dns


# ---------------------------------------------------------------- queries

def active_wifi() -> list[tuple[str, str]]:
    text = nmcli("-t", "-f", "NAME,TYPE,DEVICE", "con", "show", "--active")
    return [(n, d) for n, t, d in parse_active(text) if t in _WIFI_TYPES]


def resolve_connection(interface: str = "", connection: str = "") -> tuple[str, str, list[str]]:
    """Decide which NM connection and device to work on.

    Returns (connection, device, notes). Only this one connection is ever modified.
    """
    notes: list[str] = []
    wifis = active_wifi()
    if connection:
        for name, dev in wifis:
            if name == connection:
                return name, dev, notes
        notes.append(f"connection '{connection}' is not active right now")
        return connection, interface, notes

    if not wifis:
        raise NetError("no active wifi connection found (connect to the dorm wifi first)")
    if interface:
        match = [w for w in wifis if w[1] == interface]
        if len(match) == 1:
            return match[0][0], match[0][1], notes
        if len(wifis) == 1:
            name, dev = wifis[0]
            notes.append(f"interface '{interface}' not active; using '{dev}' (set network.interface)")
            return name, dev, notes
        raise NetError(
            f"no active wifi connection on '{interface}'; active: "
            + ", ".join(f"{n} ({d})" for n, d in wifis)
        )
    if len(wifis) == 1:
        return wifis[0][0], wifis[0][1], notes
    raise NetError(
        "several active wifi connections; set network.connection in config.toml: "
        + ", ".join(f"{n} ({d})" for n, d in wifis)
    )


def saved_settings(connection: str) -> dict[str, str]:
    """The *configured* ipv4 settings of a connection (what restore needs)."""
    text = nmcli("-t", "-f", ",".join(SAVED_FIELDS), "con", "show", connection)
    kv = parse_kv(text)
    return {f: kv.get(f, "") for f in SAVED_FIELDS}


def read_mac(device: str) -> str:
    try:
        return Path(f"/sys/class/net/{device}/address").read_text().strip()
    except OSError:
        pass
    text = nmcli("-t", "-f", "GENERAL.HWADDR", "dev", "show", device)
    return parse_kv(text).get("GENERAL.HWADDR", "")


def get_profile(interface: str = "", connection: str = "") -> NetProfile:
    conn, dev, _ = resolve_connection(interface, connection)
    saved = saved_settings(conn)
    ip = prefix = gateway = None
    dns: list[str] = split_list(saved["ipv4.dns"])
    if dev:
        live = nmcli("-t", "-f", "IP4.ADDRESS,IP4.GATEWAY,IP4.DNS", "dev", "show", dev)
        ip, prefix, gateway, live_dns = parse_live(live)
        dns = live_dns or dns
    return NetProfile(
        interface=dev,
        connection=conn,
        method=saved["ipv4.method"] or "auto",
        ip=ip,
        prefix=prefix,
        gateway=gateway,
        dns=dns,
        mac=read_mac(dev) if dev else "",
    )


# ---------------------------------------------------------------- checks

def check_profile(p: NetProfile, cfg: Config) -> list[str]:
    """Compare the live profile with the config; return human-readable warnings."""
    warnings: list[str] = []
    source = "DHCP lease" if p.method == "auto" else "static config (not a DHCP lease)"
    n = cfg.network
    if p.prefix is not None and p.prefix != n.prefix:
        msg = f"live prefix /{p.prefix} ({source}) differs from config /{n.prefix}."
        if p.ip and p.gateway:
            live_net = ipaddress.ip_interface(f"{p.ip}/{p.prefix}").network
            if ipaddress.ip_address(p.gateway) not in live_net:
                msg += f" With /{p.prefix} the gateway {p.gateway} is outside {live_net}."
        warnings.append(msg)
    if p.gateway and p.gateway != n.gateway:
        warnings.append(f"live gateway {p.gateway} differs from config gateway {n.gateway}.")
    return warnings