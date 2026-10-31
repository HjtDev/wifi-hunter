"""Captive-portal auto-login: replay the browser's login request with httpx.

Everything about the request comes from the [portal] section of config.toml.
Credentials are read from a chmod 600 file (or the system keyring) and are never
logged, printed or stored in the config.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import httpx

from .config import PortalCfg

_TOKEN = re.compile(r"\{(username|password|ip|mac)\}")


class PortalError(Exception):
    pass


def load_credentials(cfg: PortalCfg) -> tuple[str, str]:
    path = Path(cfg.credentials_file).expanduser() if cfg.credentials_file else None
    if path is not None and path.is_file():
        if path.stat().st_mode & 0o077:
            raise PortalError(f"{path} is readable by other users; run: chmod 600 {path}")
        try:
            data = tomllib.loads(path.read_text())
        except tomllib.TOMLDecodeError:
            raise PortalError(f"{path} is not valid TOML") from None
        user, pw = data.get("username"), data.get("password")
        if not isinstance(user, str) or not isinstance(pw, str) or not user or not pw:
            raise PortalError(f'{path} must contain: username = "..." and password = "..."')
        return user, pw
    if cfg.keyring_service:
        try:
            import keyring  # optional dependency
        except ImportError:
            raise PortalError("portal.keyring_service is set but the 'keyring' package is not installed") from None
        user = keyring.get_password(cfg.keyring_service, "username")
        pw = keyring.get_password(cfg.keyring_service, "password")
        if user and pw:
            return user, pw
        raise PortalError(f"no username/password stored in the keyring under '{cfg.keyring_service}'")
    where = str(path) if path else "portal.credentials_file"
    raise PortalError(f'no credentials: create {where} (chmod 600) with username = "..." and password = "..."')


def render(value: str, ctx: dict[str, str]) -> str:
    """Replace {username} {password} {ip} {mac} only; other braces are left alone."""
    return _TOKEN.sub(lambda m: ctx[m.group(1)], value)


def build_request(cfg: PortalCfg, creds: tuple[str, str], ip: str = "", mac: str = "") -> dict:
    ctx = {"username": creds[0], "password": creds[1], "ip": ip, "mac": mac}
    fields = {k: render(v, ctx) for k, v in cfg.fields.items()}
    req: dict = {
        "method": cfg.method.upper(),
        "url": render(cfg.url, ctx),
        "headers": {k: render(v, ctx) for k, v in cfg.headers.items()},
    }
    query = {k: render(v, ctx) for k, v in cfg.query.items()}
    if req["method"] == "GET":
        req["params"] = {**query, **fields}
    else:
        if query:
            req["params"] = query
        if cfg.content_type == "json":
            req["json"] = fields
        else:
            req["data"] = fields
    return req


def login_detail(
        cfg: PortalCfg | None, *, ip: str = "", mac: str = "", client: httpx.Client | None = None
) -> tuple[bool, str]:
    """-> (success, short reason). The reason never contains credentials."""
    if cfg is None or not cfg.enabled:
        return False, "auto-login is not enabled (portal.enabled = false)"
    try:
        req = build_request(cfg, load_credentials(cfg), ip, mac)
    except PortalError as e:
        return False, str(e)

    own = client is None
    c = client or httpx.Client(
        follow_redirects=True, timeout=cfg.timeout, verify=cfg.verify_tls, trust_env=False
    )
    try:
        r = c.request(**req)
        body = r.text
    except httpx.HTTPError as e:
        return False, f"request failed: {type(e).__name__}"
    finally:
        if own:
            c.close()

    if r.status_code >= 400:
        return False, f"HTTP {r.status_code}"
    if cfg.failure_contains and cfg.failure_contains in body:
        return False, "portal rejected the login (failure_contains matched)"
    if cfg.success_contains and cfg.success_contains not in body:
        return False, f"HTTP {r.status_code} but success_contains not found in the response"
    return True, f"HTTP {r.status_code}"


def login(
        session_cfg: PortalCfg | None,
        *,
        ip: str = "",
        mac: str = "",
        client: httpx.Client | None = None,
) -> bool:
    """Replay the portal login. Single plug-in point used by hunter.finalize and the watchdog."""
    return login_detail(session_cfg, ip=ip, mac=mac, client=client)[0]
