"""`dorm-ip init`: ask a few questions, write config.toml and the credentials file."""

from __future__ import annotations

import importlib.resources
import ipaddress
import json
import os
import shutil
import sys
import tomllib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from . import netinfo, portal
from .config import ConfigError, default_config_path, find_config, load_config
from .netinfo import NetError

# ---------------------------------------------------------------- config.toml writer

# (section, [(key, comment)]) in file order
SCHEMA: list[tuple[str, list[tuple[str, str]]]] = [
    ("network", [
        ("interface", ""), ("connection", "nmcli connection name; empty = the active wifi connection"),
        ("prefix", ""), ("gateway", ""), ("ranges", ""), ("exclude", "never try these (the gateway)"),
        ("prefer_unused", "try IPs not seen in the ARP scan first (shared IPs are still tried)"),
    ]),
    ("dns", [
        ("default", "the dorm DNS"), ("override", "DNS that skips the portal's DNS redirect"),
        ("hunt_with_override", "test candidates with the override DNS"),
        ("final_mode", "DNS kept after a hunt: override | default | auto"),
    ]),
    ("tests", [
        ("ping_target", ""), ("ping_count", ""), ("connectivity_url", ""), ("speed_url", ""),
        ("sustained_url", "empty = repeat speed_url for the whole sustained test"),
        ("sustained_seconds", ""), ("sample_interval", ""), ("dns_domains", ""),
        ("data_budget_mb", "daily cap for test traffic, 0 = unlimited"),
    ]),
    ("thresholds", [
        ("max_ping_ms", ""), ("max_loss_pct", ""),
        ("min_speed_mbps", "8 Mbps = 1 MB/s"), ("min_sustained_mbps", ""),
        ("collapse_below_mbps", "under this for >= 2 s counts as 'speed collapsed'"),
        ("speed_rule", "either: quick OR sustained is enough | both: both must pass"),
    ]),
    ("hunt", [
        ("max_candidates", ""), ("order", "random | sequential | best-history"),
        ("settle_seconds", "wait after applying an IP"),
    ]),
    ("watchdog", [
        ("interval_seconds", ""), ("probe_bytes", ""), ("bad_checks_to_rehunt", ""), ("notify", ""),
        ("min_probe_mbps", "a 200 KB probe is dominated by TCP slow start"),
        ("rehunt_cooldown_seconds", "doubles after each failed re-hunt, max 30 min"),
        ("busy_mbps", "slow probe + your own traffic above this = ignored (0 = off)"),
    ]),
    ("portal", [
        ("enabled", ""), ("url", ""), ("method", ""), ("content_type", "form | json"),
        ("fields", "{username} {password} {ip} {mac} are filled in at login time"),
        ("query", ""), ("headers", ""), ("success_contains", ""), ("failure_contains", ""),
        ("credentials_file", "username/password live here, never in this file"),
        ("keyring_service", ""), ("login_during_hunt", "log in on candidates that show the portal"),
        ("max_logins_per_hunt", ""),
        ("resolve_via_dorm_dns", "resolve the portal host through dns.default, even on override DNS"),
        ("host_ip", ""), ("verify_tls", ""), ("timeout", ""),
    ]),
]


def toml_str(s: str) -> str:
    return json.dumps(s)  # JSON string escapes are valid TOML basic-string escapes


def toml_value(v: object) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, str):
        return toml_str(v)
    if isinstance(v, list):
        return "[" + ", ".join(toml_value(x) for x in v) + "]"
    if isinstance(v, dict):
        if not v:
            return "{}"
        return "{ " + ", ".join(f"{toml_str(k)} = {toml_value(x)}" for k, x in v.items()) + " }"
    raise TypeError(f"cannot write {type(v).__name__} to TOML")


def render_config(values: dict) -> str:
    out = [
        "# dorm-ip configuration, written by `dorm-ip init`.",
        "# Edit freely (make edit-config); re-running init keeps your values as defaults.",
    ]
    for section, keys in SCHEMA:
        out.append(f"\n[{section}]")
        for key, comment in keys:
            if key not in values.get(section, {}):
                continue
            line = f"{key} = {toml_value(values[section][key])}"
            out.append(f"{line}  # {comment}" if comment else line)
    return "\n".join(out) + "\n"


def example_values() -> dict:
    text = importlib.resources.files("dorm_ip").joinpath("config.example.toml").read_text()
    return tomllib.loads(text)


def merge(base: dict, over: dict) -> dict:
    """Section-level merge: keys from `over` replace those in `base` (dict values replaced whole)."""
    out = {sec: dict(vals) for sec, vals in base.items()}
    for sec, vals in over.items():
        if isinstance(vals, dict):
            out.setdefault(sec, {}).update(vals)
    return out


# ---------------------------------------------------------------- credentials file

def write_credentials(path: Path, username: str, password: str) -> None:
    """Write the credentials file readable by you only (chmod 600)."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(f"username = {toml_str(username)}\npassword = {toml_str(password)}\n")


def read_credentials(path: Path) -> tuple[str, str] | None:
    try:
        data = tomllib.loads(path.read_text())
    except (OSError, tomllib.TOMLDecodeError):
        return None
    u, p = data.get("username"), data.get("password")
    return (u, p) if isinstance(u, str) and isinstance(p, str) and u and p else None


# ---------------------------------------------------------------- prompting

class Prompter:
    """Interface used by the wizard (so tests can script the answers)."""

    def say(self, text: str) -> None: ...
    def ask(self, text: str, default: str = "") -> str: return default
    def confirm(self, text: str, default: bool = True) -> bool: return default
    def secret(self, text: str) -> str: return ""
    def choose(self, text: str, choices: list[str], default: str) -> str: return default
    def paste(self, text: str) -> str: return ""


class AutoPrompter(Prompter):
    """--yes: accept every default, skip secrets and pasted requests."""

    def __init__(self, say: Callable[[str], None] = print) -> None:
        self._say = say

    def say(self, text: str) -> None:
        self._say(text)


class TyperPrompter(Prompter):
    def __init__(self, say: Callable[[str], None] = print) -> None:
        self._say = say

    def say(self, text: str) -> None:
        self._say(text)

    def ask(self, text: str, default: str = "") -> str:
        import typer

        return typer.prompt(text, default=default, show_default=bool(default)).strip()

    def confirm(self, text: str, default: bool = True) -> bool:
        import typer

        return typer.confirm(text, default=default)

    def secret(self, text: str) -> str:
        import typer

        return typer.prompt(text, default="", hide_input=True, show_default=False)

    def choose(self, text: str, choices: list[str], default: str) -> str:
        import typer

        while True:
            answer = typer.prompt(text, default=default).strip().lower()
            if answer in choices:
                return answer
            self.say(f"  ! please type one of: {', '.join(choices)}")

    def paste(self, text: str) -> str:
        self.say(text)
        lines: list[str] = []
        for line in sys.stdin:
            if not line.strip():
                break
            lines.append(line.rstrip("\n"))
        return "\n".join(lines)


# ---------------------------------------------------------------- the wizard

@dataclass
class Detected:
    interface: str
    connection: str
    gateway: str | None
    prefix: int | None
    dns: list[str]
    method: str
    ip: str | None = None
    mac: str = ""


def detect_network() -> Detected | None:
    try:
        p = netinfo.get_profile("", "")
    except NetError:
        return None
    return Detected(p.interface, p.connection, p.gateway, p.prefix, p.dns, p.method, p.ip, p.mac)


@dataclass
class InitResult:
    config_path: Path
    credentials_path: Path | None = None
    portal_enabled: bool = False
    notes: list[str] = field(default_factory=list)


def _ask_parsed(p: Prompter, text: str, default: str, parse: Callable[[str], object], tries: int = 5):
    for _ in range(tries):
        raw = p.ask(text, default)
        try:
            return parse(raw)
        except (ValueError, ConfigError) as e:
            p.say(f"  ! {e}")
    raise ConfigError(f"too many invalid answers for: {text}")


def _ip_list(raw: str) -> list[str]:
    items = [x for x in raw.replace(",", " ").split() if x]
    if not items:
        raise ValueError("enter at least one IP address")
    return [str(ipaddress.IPv4Address(x)) for x in items]


def _range_list(raw: str) -> list[str]:
    items = [x.strip() for x in raw.split(",") if x.strip()]
    if not items:
        raise ValueError("enter at least one range")
    from .config import parse_range

    for it in items:
        parse_range(it)
    return items


def _num(raw: str) -> float:
    v = float(raw)
    if v < 0:
        raise ValueError("must not be negative")
    return v


def run_init(
        p: Prompter,
        *,
        target: Path,
        curl_text: str | None = None,
        detect: Callable[[], Detected | None] = detect_network,
        source: Path | None = None,
) -> InitResult | None:
    """Interactive setup. Returns None if the user declined to overwrite an existing config."""
    values = example_values()
    base_path = target if target.exists() else source
    if base_path is not None and base_path.exists():
        try:
            values = merge(values, tomllib.loads(base_path.read_text()))
            p.say(f"Using the values in {base_path} as defaults.")
        except tomllib.TOMLDecodeError:
            p.say(f"! {base_path} is not valid TOML; starting from the built-in defaults.")
    if target.exists() and not p.confirm(f"{target} exists. Update it? (a backup is kept as {target.name}.bak)", True):
        return None

    v_net, v_dns, v_tests = values["network"], values["dns"], values["tests"]
    v_th, v_hunt, v_wd, v_portal = values["thresholds"], values["hunt"], values["watchdog"], values["portal"]
    notes: list[str] = []

    # ---- 1. network
    p.say("\n== Network ==")
    det = detect()
    if det:
        bits = [f"interface {det.interface}", f"connection '{det.connection}'"]
        if det.gateway:
            bits.append(f"gateway {det.gateway}")
        if det.prefix:
            bits.append(f"/{det.prefix}")
        p.say("Detected from your current wifi: " + ", ".join(bits))
        v_net["interface"] = det.interface or v_net["interface"]
        v_net["gateway"] = det.gateway or v_net["gateway"]
        v_net["prefix"] = det.prefix or v_net["prefix"]
        if det.method == "auto" and det.dns:  # a DHCP lease is the source of truth for the dorm DNS
            v_dns["default"] = det.dns
    else:
        p.say("Not connected to wifi (or nmcli is unavailable): using the values from the config/defaults.")
    p.say(
        f"  interface {v_net['interface']}, gateway {v_net['gateway']}, prefix /{v_net['prefix']}, "
        f"dorm DNS {', '.join(v_dns['default'])}\n  IP ranges: {', '.join(v_net['ranges'])}"
    )
    if not p.confirm("Are these network settings correct?", True):
        v_net["interface"] = p.ask("Wifi interface", v_net["interface"])
        v_net["gateway"] = str(_ask_parsed(p, "Gateway", v_net["gateway"], lambda r: ipaddress.IPv4Address(r.strip())))
        v_net["prefix"] = int(_ask_parsed(p, "Prefix length", str(v_net["prefix"]), lambda r: _in_range(int(r), 1, 30)))
        v_dns["default"] = _ask_parsed(p, "Dorm DNS servers (comma separated)", ", ".join(v_dns["default"]), _ip_list)
        v_net["ranges"] = _ask_parsed(p, "IP ranges to hunt (comma separated A-B)", ", ".join(v_net["ranges"]), _range_list)
    v_net["exclude"] = sorted(set(v_net.get("exclude", [])) | {v_net["gateway"]})

    # ---- 2. what a good IP is
    p.say("\n== What is a good IP? ==")
    v_net["prefer_unused"] = p.confirm("Try IPs nobody else is using first?", bool(v_net["prefer_unused"]))
    v_dns["override"] = _ask_parsed(
        p, "Override DNS servers (skip the portal's DNS redirect)", ", ".join(v_dns["override"]), _ip_list
    )
    v_dns["hunt_with_override"] = True
    v_dns["final_mode"] = p.choose(
        "DNS to keep after a hunt (override / default / auto)", ["override", "default", "auto"], v_dns["final_mode"]
    )
    mbs = _ask_parsed(
        p, "Minimum speed in MB/s (1 MB/s = 8 Mbps)", f"{v_th['min_speed_mbps'] / 8:g}", _num
    )
    v_th["min_speed_mbps"] = v_th["min_sustained_mbps"] = round(float(mbs) * 8, 2)
    v_th["speed_rule"] = "either" if p.confirm(
        "Accept an IP if EITHER the quick or the sustained test reaches that speed? (No = both must)",
        v_th["speed_rule"] == "either",
        ) else "both"
    v_th["max_ping_ms"] = _num_int(_ask_parsed(p, "Maximum ping in ms", str(v_th["max_ping_ms"]), _num))
    v_hunt["max_candidates"] = int(_ask_parsed(p, "Candidates to try per hunt", str(v_hunt["max_candidates"]), _positive_int))
    v_hunt["order"] = p.choose("Order within a group", ["random", "sequential", "best-history"], v_hunt["order"])
    shown = 0 if v_tests["data_budget_mb"] >= 100000 else v_tests["data_budget_mb"]
    v_tests["data_budget_mb"] = int(_ask_parsed(
        p, "Daily data budget for tests in MB (0 = unlimited)", str(shown), lambda r: int(_num(r))
    ))

    # ---- 3. portal auto-login
    p.say("\n== Portal auto-login ==")
    creds_path = Path(v_portal["credentials_file"]).expanduser()
    existing = read_credentials(creds_path)
    saved_creds: Path | None = None
    portal_ok = False
    if p.confirm("Log in to the portal automatically (hunt, set, watchdog)?", True):
        username = p.ask("Portal username", existing[0] if existing else "")
        password = p.secret("Portal password (hidden; Enter keeps the saved one)")
        if not password and existing and existing[0] == username:
            password = existing[1]
        if not username or not password:
            notes.append("No username/password given: auto-login stays off. Re-run `dorm-ip init` to set it up.")
        else:
            section = _portal_request(p, v_portal, curl_text, username, password, det, notes)
            if section is not None:  # {} = keep the existing request
                v_portal.update(section)
                v_portal["success_contains"] = p.ask(
                    "Text that appears in a successful login response (blank = any non-error)",
                    v_portal.get("success_contains", ""),
                )
                v_portal["login_during_hunt"] = p.confirm(
                    "Also log in on candidate IPs that show the portal while hunting? "
                    "(creates a portal session per candidate)", True,
                )
                portal_ok = True
            else:
                notes.append("No login request yet: auto-login stays off. Re-run `dorm-ip init` and paste it.")
            write_credentials(creds_path, username, password)
            saved_creds = creds_path
    v_portal["enabled"] = portal_ok and bool(v_portal.get("url"))

    # ---- 4. watchdog
    p.say("\n== Watchdog ==")
    v_wd["interval_seconds"] = _num_int(_ask_parsed(
        p, "Seconds between watchdog checks (each uses ~200 KB)", str(v_wd["interval_seconds"]), _num
    ))
    v_wd["notify"] = p.confirm("Desktop notifications?", bool(v_wd["notify"]))

    # ---- write
    if target.exists():
        shutil.copy2(target, target.with_name(target.name + ".bak"))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_config(values))
    try:
        load_config(target)
    except ConfigError as e:
        notes.append(f"The written config did not validate: {e}")
    return InitResult(target, saved_creds, bool(v_portal["enabled"]), notes)


def _in_range(v: int, lo: int, hi: int) -> int:
    if not lo <= v <= hi:
        raise ValueError(f"must be between {lo} and {hi}")
    return v


def _positive_int(raw: str) -> int:
    v = int(raw)
    if v < 1:
        raise ValueError("must be at least 1")
    return v


def _num_int(v: float) -> int | float:
    return int(v) if float(v).is_integer() else v


def _portal_request(
        p: Prompter, v_portal: dict, curl_text: str | None, username: str, password: str,
        det: Detected | None, notes: list[str],
) -> dict | None:
    """Get the login request as a [portal] section (from a pasted cURL, or the existing config)."""
    if not curl_text and v_portal.get("url"):
        if p.confirm(f"Keep the existing login request ({_host(v_portal['url'])})?", True):
            return {}
    if not curl_text:
        curl_text = p.paste(
            "\nTo log in automatically You need the browser's login request:\n"
            "  1. Open the portal login page, press F12 and open the Network tab.\n"
            "  2. Log in. Right-click the login request (usually a POST) > Copy > Copy as cURL (bash).\n"
            "  3. Paste it here, then press Enter on an empty line. (Blank = skip for now.)"
        )
    if not curl_text.strip():
        return None
    try:
        req = portal.parse_curl(curl_text)
        section, warnings = portal.curl_to_portal(
            req, username=username, password=password,
            ip=(det.ip or "") if det else "", mac=(det.mac or "") if det else "",
        )
    except portal.PortalError as e:
        p.say(f"! {e}")
        return None
    for w in warnings:
        p.say(f"! {w}")
    p.say(f"Login request saved: {section['method']} {_host(section['url'])} with fields {', '.join(section['fields']) or '(none)'}.")
    return section or None


def _host(url: str) -> str:
    from urllib.parse import urlsplit

    return urlsplit(url).netloc or url


def existing_source() -> Path | None:
    try:
        return find_config(None)
    except ConfigError:
        return None


__all__ = ["run_init", "default_config_path", "existing_source", "TyperPrompter", "AutoPrompter"]
