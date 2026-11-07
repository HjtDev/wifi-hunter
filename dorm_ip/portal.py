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
import socket
import time
import tomllib
from collections.abc import Callable
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qsl, quote, urljoin, urlsplit, urlunsplit

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


DEFAULT_CONNECTIVITY_URL = "http://connectivitycheck.gstatic.com/generate_204"


def _login_flow(
        cfg: PortalCfg, *, dorm_dns, source_ip, client, connectivity_url: str, trace: list[str] | None = None
) -> tuple[bool, str]:
    from . import tests as nettests  # imported late: nothing at module level depends on it

    def verify() -> tuple[str, str | None]:
        state, _bytes, extra = nettests.check_url(connectivity_url, source_ip)
        return state, extra

    return flow_login(
        cfg, connectivity_url=connectivity_url, dorm_dns=dorm_dns, source_ip=source_ip, client=client,
        trace=trace, verify=verify,
    )


def login_trace(
        cfg: PortalCfg, *, dorm_dns: list[str] | None = None, source_ip: str | None = None,
        connectivity_url: str = DEFAULT_CONNECTIVITY_URL, client: httpx.Client | None = None,
) -> tuple[bool, str, list[str]]:
    """Like login_detail, plus a step-by-step trace with no credentials in it (for `login --debug`)."""
    if not cfg.enabled:
        return False, "auto-login is not enabled (portal.enabled = false)", []
    if cfg.mode != "flow":
        ok, detail = login_detail(cfg, dorm_dns=dorm_dns, source_ip=source_ip, client=client)
        return ok, detail, [f"replay mode: {cfg.method} {_short(cfg.url)} -> {detail}"]
    trace: list[str] = []
    ok, detail = _login_flow(
        cfg, dorm_dns=dorm_dns, source_ip=source_ip, client=client, connectivity_url=connectivity_url, trace=trace
    )
    return ok, detail, trace


def login_detail(
        cfg: PortalCfg | None,
        *,
        ip: str = "",
        mac: str = "",
        client: httpx.Client | None = None,
        dorm_dns: list[str] | None = None,
        source_ip: str | None = None,
        connectivity_url: str = DEFAULT_CONNECTIVITY_URL,
) -> tuple[bool, str]:
    """-> (success, short reason). The reason never contains credentials.

    The portal host is resolved through `dorm_dns` (the dorm DNS servers) when given, so the
    login works while the system DNS is the override DNS."""
    if cfg is None or not cfg.enabled:
        return False, "auto-login is not enabled (portal.enabled = false)"
    if cfg.mode == "flow":
        return _login_flow(cfg, dorm_dns=dorm_dns, source_ip=source_ip, client=client, connectivity_url=connectivity_url)
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


# ---------------------------------------------------------------- flow mode (what a browser does)

BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}
LOCAL_SUFFIXES = (".local", ".lan", ".internal", ".localdomain", ".home.arpa")
REDIRECTS = (301, 302, 303, 307, 308)
VERIFY_TRIES = 4
MAX_PORTAL_HOPS = 4

# Portals recognised when their login page has no <form> we can parse (the page is built by JavaScript).
KERIO = {
    "name": "Kerio Control",
    "post_path": "/internal/dologin.php",
    "user_field": "kerio_username",
    "pass_field": "kerio_password",
}


@dataclass
class FormField:
    name: str
    type: str
    value: str = ""
    checked: bool = False


@dataclass
class Form:
    action: str
    method: str
    fields: list[FormField] = field(default_factory=list)


class _FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[Form] = []
        self._cur: Form | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._cur = Form(a.get("action", ""), (a.get("method") or "get").lower())
            self.forms.append(self._cur)
        elif tag == "input" and self._cur is not None:
            self._cur.fields.append(
                FormField(a.get("name", ""), (a.get("type") or "text").lower(), a.get("value", ""), "checked" in a)
            )

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._cur = None


def parse_forms(html: str) -> list[Form]:
    parser = _FormParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # broken markup: use whatever was parsed so far
        pass
    return parser.forms


def pick_login_form(forms: list[Form]) -> Form | None:
    """The first form that has a password input."""
    return next((f for f in forms if any(i.type == "password" for i in f.fields)), None)


_USER_HINTS = ("user", "login", "name", "mail", "phone", "account")


def fill_form(form: Form, username: str, password: str, user_field: str = "", pass_field: str = "") -> dict[str, str]:
    """What a browser would submit: hidden and default values as they are, plus the credentials."""
    pw_name = pass_field or next((f.name for f in form.fields if f.type == "password" and f.name), "")
    if not pw_name:
        raise PortalError("the login form has no named password field")
    user_name = user_field
    if not user_name:
        texts = [f.name for f in form.fields if f.type in ("text", "email", "tel", "number") and f.name]
        user_name = next((n for n in texts if any(h in n.lower() for h in _USER_HINTS)), texts[0] if texts else "")
    if not user_name:
        raise PortalError("cannot tell which form field takes the username (set portal.form_username_field)")
    data: dict[str, str] = {}
    for f in form.fields:
        if not f.name or f.type in ("submit", "button", "image", "reset", "file"):
            continue
        if f.type in ("checkbox", "radio"):
            if f.checked:
                data[f.name] = f.value or "on"
            continue
        data[f.name] = f.value
    data[user_name], data[pw_name] = username, password
    return data


def derive_post_url(login_url: str, post_path: str, drop: list[str]) -> str:
    """Submit address built from the login page address: same host and query, new path.

    The raw query string is kept as it is (only the dropped parameters are removed), because values such as
    base64 tokens contain characters that decoding and re-encoding would damage."""
    u = urlsplit(login_url)
    query = "&".join(p for p in u.query.split("&") if p and p.split("=", 1)[0] not in drop)
    return urlunsplit((u.scheme, u.netloc, post_path, query, ""))


def known_portal(login_url: str, server_header: str | None) -> dict | None:
    u = urlsplit(login_url)
    keys = {p.split("=", 1)[0] for p in u.query.split("&")}
    if "kerio" in (server_header or "").lower() or (u.path.startswith("/login") and {"NTLM", "dest"} <= keys):
        return KERIO
    return None


def _is_local_name(host: str) -> bool:
    return "." not in host or host.lower().endswith(LOCAL_SUFFIXES)


def make_flow_resolver(
        cfg: PortalCfg, dorm_dns: list[str] | None, portal_hosts: set[str], note: Callable[[str], None]
) -> Callable[[str], str | None]:
    """Portal host and local names -> the dorm DNS (system resolvers often send *.local to mDNS only);
    everything else keeps using the system DNS, falling back to the dorm DNS if that fails."""

    def resolver(host: str) -> str | None:
        if cfg.host_ip and host in portal_hosts:
            note(f"   {host} -> {cfg.host_ip} (portal.host_ip)")
            return cfg.host_ip
        if not cfg.resolve_via_dorm_dns or not dorm_dns:
            return None
        if host in portal_hosts or _is_local_name(host):
            ip = dnsq.resolve_via(dorm_dns, host)
            note(f"   {host} -> {ip or 'no answer'} (dorm DNS)")
            return ip
        try:
            socket.getaddrinfo(host, None, socket.AF_INET)
            return None  # the system DNS can resolve it
        except OSError:
            ip = dnsq.resolve_via(dorm_dns, host)
            note(f"   {host} -> {ip or 'no answer'} (dorm DNS, the system DNS failed)")
            return ip

    return resolver


def _flow_client(
        cfg: PortalCfg, dorm_dns: list[str] | None, source_ip: str | None, portal_hosts: set[str], note
) -> httpx.Client:
    transport = ResolvingTransport(
        httpx.HTTPTransport(verify=cfg.verify_tls, local_address=source_ip),
        make_flow_resolver(cfg, dorm_dns, portal_hosts, note),
    )
    return httpx.Client(
        transport=transport, follow_redirects=True, max_redirects=6, timeout=cfg.timeout,
        trust_env=False, headers=BROWSER_HEADERS,
    )


def _short(url: str, limit: int = 110) -> str:
    return url if len(url) <= limit else url[: limit - 1] + "…"


def flow_login(
        cfg: PortalCfg,
        *,
        connectivity_url: str,
        dorm_dns: list[str] | None = None,
        source_ip: str | None = None,
        client: httpx.Client | None = None,
        trace: list[str] | None = None,
        verify: Callable[[], tuple[str, str | None]] | None = None,
        sleep: Callable[[float], None] = time.sleep,
) -> tuple[bool, str]:
    """Log in the way a browser does, then judge the result by whether the internet opened.

    1. Ask for the connectivity URL: an unauthenticated client is redirected to the portal's login page, and
       that address carries fresh per-client values (so nothing is ever copied from an old session).
    2. Load the login page (this sets the session cookies) and find its form.
    3. Submit the form with the credentials, from the same source address, with the cookies.
    4. Verify with the connectivity check; the portal's own response codes are not trusted.
    `verify` returns (state, detail) of that check (state: open | portal | dead)."""
    note = trace.append if trace is not None else (lambda _m: None)
    try:
        creds = load_credentials(cfg)
    except PortalError as e:
        return False, str(e)
    portal_hosts: set[str] = set()
    own = client is None
    http = client or _flow_client(cfg, dorm_dns, source_ip, portal_hosts, note)
    try:
        # ---- 1. where does the portal send us?
        r = http.get(connectivity_url, follow_redirects=False)
        loc = r.headers.get("location")
        note(f"1. GET {_short(connectivity_url)} -> HTTP {r.status_code}" + (f", redirected to {_short(loc)}" if loc else ""))
        if r.status_code == 204:
            return True, "the internet is already open: no login needed"
        if r.status_code in REDIRECTS and loc:
            login_url = urljoin(str(r.url), loc)
        elif "html" in r.headers.get("content-type", "").lower() and "<form" in r.text.lower():
            login_url = str(r.url)  # the portal answered with its login page directly
        else:
            return False, f"the connectivity check returned HTTP {r.status_code}, not a portal redirect"
        portal_host = urlsplit(login_url).hostname or ""
        portal_hosts.add(portal_host)

        # ---- 2. the login page
        page = http.get(login_url)
        page_url = str(page.url)
        note(f"2. GET {_short(page_url)} -> HTTP {page.status_code} {page.headers.get('content-type', '')}")
        note("   cookies: " + (", ".join(sorted({c.name for c in http.cookies.jar})) or "none"))
        if page.status_code >= 400:
            return False, f"the portal's login page answered HTTP {page.status_code}"
        form = pick_login_form(parse_forms(page.text))
        known = known_portal(page_url, page.headers.get("server"))
        if form is not None:
            post_url = urljoin(page_url, form.action) if form.action else page_url
            method = form.method
            data = fill_form(form, creds[0], creds[1], cfg.form_username_field, cfg.form_password_field)
            note(f"   form: {method.upper()} {_short(post_url)}; fields: " + ", ".join(
                f"{f.name} ({f.type})" for f in form.fields if f.name))
        else:
            post_path = cfg.post_path or (known or {}).get("post_path", "")
            user_f = cfg.form_username_field or (known or {}).get("user_field", "")
            pass_f = cfg.form_password_field or (known or {}).get("pass_field", "")
            if not (post_path and user_f and pass_f):
                return False, (
                    "no login form found on the portal page and no portal.post_path / form field names configured: "
                    "run `dorm-ip login --debug` and send the trace"
                )
            post_url = derive_post_url(page_url, post_path, cfg.post_drop_params)
            method, data = "post", {user_f: creds[0], pass_f: creds[1]}
            note(f"   no parsable form; using {known['name'] if known and not cfg.post_path else 'portal.post_path'}: "
                 f"POST {_short(post_url)}; fields: {user_f}, {pass_f}")

        # ---- 3. submit
        origin = "{0.scheme}://{0.netloc}".format(urlsplit(page_url))
        headers = {"Referer": page_url, "Origin": origin}
        if method == "post":
            resp = http.post(post_url, data=data, headers=headers, follow_redirects=False)
        else:
            resp = http.get(post_url, params=data, headers=headers, follow_redirects=False)
        hops = 0
        while resp.status_code in REDIRECTS and resp.headers.get("location") and hops < MAX_PORTAL_HOPS:
            nxt = urljoin(str(resp.url), resp.headers["location"])
            note(f"3. {resp.request.method} {_short(str(resp.url))} -> HTTP {resp.status_code}, redirected to {_short(nxt)}")
            if (urlsplit(nxt).hostname or "") not in portal_hosts:
                break  # leaving the portal (back to the page you asked for): the login is done or has failed
            resp = http.get(nxt, headers=headers, follow_redirects=False)
            hops += 1
        final_loc = resp.headers.get("location", "")
        note(f"3. {resp.request.method} {_short(str(resp.url))} -> HTTP {resp.status_code}"
             + (f", redirected to {_short(final_loc)}" if final_loc else ""))
        rejected = "reason=failure" in final_loc or "reason=failure" in str(resp.url)

        # ---- 4. did the internet open?
        state, extra = "portal", None
        for attempt in range(VERIFY_TRIES):
            state, extra = verify() if verify else ("portal", None)
            if state == "open":
                break
            if attempt < VERIFY_TRIES - 1:
                sleep(0.7)
        note(f"4. connectivity check: {state}" + (f" ({extra})" if extra and state == "dead" else ""))
        if state == "open":
            return True, f"logged in (the portal answered HTTP {resp.status_code})"
        if state == "dead":
            return False, f"logged in, but there is no internet afterwards: {extra or 'connectivity check failed'}"
        if rejected:
            return False, "the portal rejected the login (it sent you back to the login page): check the username and password"
        return False, f"the portal still blocks the connection after the login (HTTP {resp.status_code}{', to ' + _short(final_loc, 60) if final_loc else ''})"
    except httpx.HTTPError as e:
        note(f"   request failed: {type(e).__name__}: {e}")
        return False, f"request failed: {type(e).__name__}"
    except PortalError as e:
        return False, str(e)
    finally:
        if own:
            http.close()


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
