"""Captive-portal auto-login: replay the browser's login request with httpx.

Everything about the request comes from the [portal] section of config.toml.
Credentials are read from a chmod 600 file (or the system keyring) and are never
logged, printed or stored in the config.
"""

from __future__ import annotations

import codecs
import ipaddress
import json
import re
import shlex
import tomllib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlsplit

import httpx

from . import dnsq
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


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


class ResolvingTransport(httpx.BaseTransport):
    """Connects to the IP a custom resolver returns while keeping the original host name
    for the Host header, TLS SNI and certificate verification. If the resolver has no
    answer the request goes out unchanged (system DNS)."""

    def __init__(self, inner: httpx.BaseTransport, resolver: Callable[[str], str | None]) -> None:
        self.inner = inner
        self.resolver = resolver
        self.cache: dict[str, str | None] = {}

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if not host or _is_ip(host):
            return self.inner.handle_request(request)
        if host not in self.cache:
            self.cache[host] = self.resolver(host)
        ip = self.cache[host]
        if not ip:
            return self.inner.handle_request(request)
        extensions = {**request.extensions, "sni_hostname": host}
        rewritten = httpx.Request(
            request.method,
            request.url.copy_with(host=ip),
            headers=request.headers,  # keeps Host: <original name>
            stream=request.stream,
            extensions=extensions,
        )
        return self.inner.handle_request(rewritten)

    def close(self) -> None:
        self.inner.close()


def make_client(
        cfg: PortalCfg, dorm_dns: list[str] | None = None, source_ip: str | None = None
) -> httpx.Client:
    portal_host = urlsplit(cfg.url).hostname or ""

    def resolver(host: str) -> str | None:
        if cfg.host_ip and host == portal_host:
            return cfg.host_ip
        if cfg.resolve_via_dorm_dns and dorm_dns:
            return dnsq.resolve_via(dorm_dns, host)
        return None

    transport = ResolvingTransport(httpx.HTTPTransport(verify=cfg.verify_tls, local_address=source_ip), resolver)
    return httpx.Client(transport=transport, follow_redirects=True, timeout=cfg.timeout, trust_env=False)


def login_detail(
        cfg: PortalCfg | None,
        *,
        ip: str = "",
        mac: str = "",
        client: httpx.Client | None = None,
        dorm_dns: list[str] | None = None,
        source_ip: str | None = None,
) -> tuple[bool, str]:
    """-> (success, short reason). The reason never contains credentials.

    The portal host is resolved through `dorm_dns` (the dorm DNS servers) when given, so the
    login works while the system DNS is the override DNS."""
    if cfg is None or not cfg.enabled:
        return False, "auto-login is not enabled (portal.enabled = false)"
    try:
        req = build_request(cfg, load_credentials(cfg), ip, mac)
    except PortalError as e:
        return False, str(e)

    own = client is None
    c = client or make_client(cfg, dorm_dns, source_ip)
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
        dorm_dns: list[str] | None = None,
        source_ip: str | None = None,
) -> bool:
    """Replay the portal login. Single plug-in point used by hunter.finalize and the watchdog."""
    return login_detail(session_cfg, ip=ip, mac=mac, client=client, dorm_dns=dorm_dns, source_ip=source_ip)[0]


# ---------------------------------------------------------------- "Copy as cURL" import

_ARG_OPTS = {
    "-X", "--request", "-H", "--header", "-d", "--data", "--data-raw", "--data-binary", "--data-ascii",
    "--data-urlencode", "-b", "--cookie", "-u", "--user", "--url", "-e", "--referer", "-A", "--user-agent",
    "-o", "--output", "-m", "--max-time", "--connect-timeout", "-x", "--proxy", "--json",
}
_DATA_OPTS = {"-d", "--data", "--data-raw", "--data-binary", "--data-ascii", "--data-urlencode"}
_DROP_HEADERS = {"host", "content-length", "accept-encoding", "connection", "cookie", "content-type"}
_ANSI_C = re.compile(r"\$'((?:[^'\\]|\\.)*)'")


@dataclass
class CurlRequest:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str | None = None
    insecure: bool = False
    json_body: bool = False


def _decode_ansi_c(m: re.Match) -> str:
    raw = m.group(1).encode("latin-1", "backslashreplace").decode("unicode_escape")
    return shlex.quote(raw)


def parse_curl(text: str) -> CurlRequest:
    """Parse a browser "Copy as cURL (bash)" command."""
    text = text.replace("\\\r\n", " ").replace("\\\n", " ").strip()
    text = _ANSI_C.sub(_decode_ansi_c, text)
    try:
        tokens = shlex.split(text)
    except ValueError as e:
        raise PortalError(f"could not parse the cURL command: {e}") from None
    if not tokens or tokens[0] != "curl":
        raise PortalError("that does not look like a cURL command (it must start with 'curl')")

    method = ""
    url = ""
    headers: dict[str, str] = {}
    data: list[str] = []
    insecure = json_body = False
    i = 1
    while i < len(tokens):
        t = tokens[i]
        if t in _ARG_OPTS:
            if i + 1 >= len(tokens):
                raise PortalError(f"cURL option {t} is missing its value")
            val = tokens[i + 1]
            i += 2
            if t in ("-X", "--request"):
                method = val.upper()
            elif t in ("-H", "--header"):
                k, _, v = val.partition(":")
                headers[k.strip()] = v.strip()
            elif t in _DATA_OPTS:
                data.append(val)
            elif t == "--json":
                data.append(val)
                json_body = True
            elif t == "--url":
                url = val
            elif t in ("-e", "--referer"):
                headers["Referer"] = val
            elif t in ("-A", "--user-agent"):
                headers["User-Agent"] = val
            continue
        if t in ("-k", "--insecure"):
            insecure = True
        elif not t.startswith("-") and not url:
            url = t
        i += 1

    if not url:
        raise PortalError("no URL found in the cURL command")
    body = "&".join(data) if data else None
    if headers and any(k.lower() == "content-type" and "json" in v.lower() for k, v in headers.items()):
        json_body = True
    return CurlRequest(method or ("POST" if body is not None else "GET"), url, headers, body, insecure, json_body)


def _tokenize(value: str, subs: list[tuple[str, str]]) -> str:
    for secret, token in subs:
        if not secret:
            continue
        if value == secret:
            value = token
        elif len(secret) >= 4 and secret in value:
            value = value.replace(secret, token)
    return value


def curl_to_portal(
        req: CurlRequest, *, username: str, password: str, ip: str = "", mac: str = ""
) -> tuple[dict, list[str]]:
    """Turn a parsed cURL request into a [portal] config section.

    Occurrences of the username/password (and the current IP/MAC) are replaced by the
    {username}/{password}/{ip}/{mac} tokens, so no secret ends up in the config file.
    """
    warnings: list[str] = []
    pairs = [(password, "{password}"), (username, "{username}"), (mac, "{mac}"), (ip, "{ip}")]
    subs = sorted((p for p in pairs if p[0]), key=lambda p: -len(p[0]))
    # URLs may carry URL-encoded secrets
    url_subs = subs + [(quote(sec, safe=""), tok) for sec, tok in subs if quote(sec, safe="") != sec]

    fields: dict[str, str] = {}
    if req.body is not None:
        if req.json_body:
            try:
                parsed = json.loads(req.body)
            except json.JSONDecodeError:
                raise PortalError("the request body is declared JSON but is not valid JSON") from None
            if not isinstance(parsed, dict):
                raise PortalError("only JSON object bodies are supported")
            for k, v in parsed.items():
                if not isinstance(v, str):
                    warnings.append(f"JSON field '{k}' is not a string; it will be sent as text")
                fields[k] = _tokenize(str(v), subs)
        else:
            for k, v in parse_qsl(req.body, keep_blank_values=True):
                fields[k] = _tokenize(v, subs)

    headers = {
        k: _tokenize(v, url_subs)
        for k, v in req.headers.items()
        if k.lower() not in _DROP_HEADERS and not k.startswith(":") and not k.lower().startswith("sec-")
    }
    url = _tokenize(req.url, url_subs)
    method = req.method if req.method in ("GET", "POST") else "POST"
    if method != req.method:
        warnings.append(f"method {req.method} is not supported; using POST")

    blob = url + "".join(fields.values()) + "".join(headers.values())
    if "{username}" not in blob and "{password}" not in blob:
        warnings.append("your username/password were not found in the request: check that you pasted the login request")

    section = {
        "enabled": True,
        "url": url,
        "method": method,
        "content_type": "json" if req.json_body else "form",
        "fields": fields,
        "query": {},
        "headers": headers,
        "verify_tls": not req.insecure,
    }
    return section, warnings
