"""Flow-mode login, modelled on a real Kerio Control captive portal (values from a browser HAR)."""
import base64
from dataclasses import replace
from urllib.parse import parse_qs, quote, urlsplit

import httpx
import pytest
from typer.testing import CliRunner

from dorm_ip import cli, hunter, netinfo, portal
from dorm_ip import tests as nt
from dorm_ip.config import PortalCfg
from dorm_ip.models import NetProfile

USER, PASSWORD = "USER1234", "PASS5678"
CONNECT = "http://connectivitycheck.gstatic.com/generate_204"
# the real addresses from the HAR
HAR_LOGIN = ("http://account.tvct1.local:4080/login/?reason=failure&NTLM=0&dest=aHR0cDovL2ZpcmVmb3gtcG9ydGFsLWRldGVjdGlvbi5jb20vZ2VuZXJhdGVfMjA0"
             "&host=MTcyLjE4LjQwLjE1MSA3YmFhMzBiMjgzMjYwOWVhNjhiNWRhNzYxNmIwNDliOQ%3D%3D")
HAR_POST = ("http://account.tvct1.local:4080/internal/dologin.php?NTLM=0&dest=aHR0cDovL2ZpcmVmb3gtcG9ydGFsLWRldGVjdGlvbi5jb20vZ2VuZXJhdGVfMjA0"
            "&host=MTcyLjE4LjQwLjE1MSA3YmFhMzBiMjgzMjYwOWVhNjhiNWRhNzYxNmIwNDliOQ%3D%3D")


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def enc(s: str) -> str:
    """Browsers percent-encode '=' in query values: ...bg==  ->  ...bg%3D%3D"""
    return quote(s, safe="")


DEST = "http://firefox-portal-detection.com/generate_204"  # the page you asked for before the redirect (from the HAR)


FORM_PAGE = """<html><body><form action="/internal/dologin.php?NTLM=0&amp;dest={dest}&amp;host={host}" method="post">
<input type="text" name="kerio_username"><input type="password" name="kerio_password"><input type="submit" value="Login">
</form></body></html>"""
JS_PAGE = "<html><body><div id='app'></div><script>buildLoginForm()</script></body></html>"


class KerioSim:
    """Behaves like the portal in the HAR: per-client token in the redirect, session cookies, 302 on POST either way."""

    def __init__(self, page="form", token="7baa30b2832609ea68b5da7616b049b9", ip="172.18.40.151", server="Kerio Control Embedded Web Server"):
        self.page, self.token, self.ip, self.server = page, token, ip, server
        self.logged_in = False
        self.requests: list[tuple[str, str]] = []
        self.posts: list[dict] = []
        self.always_302_failure = False  # reports "invalid credentials" even though the login worked

    @property
    def host_param(self) -> str:
        return b64(f"{self.ip} {self.token}")

    def login_url(self, reason=False) -> str:
        q = ("reason=failure&" if reason else "") + f"NTLM=0&dest={enc(b64(DEST))}&host={enc(self.host_param)}"
        return "http://account.tvct1.local:4080/login/?" + q

    def handle(self, req: httpx.Request) -> httpx.Response:
        url = str(req.url)
        self.requests.append((req.method, url))
        if req.url.host == "connectivitycheck.gstatic.com" and req.url.path == "/generate_204":
            if self.logged_in:
                return httpx.Response(204)
            return httpx.Response(302, headers={"Location": self.login_url()})
        if req.url.path.startswith("/login") and req.method == "GET":
            body = FORM_PAGE.format(dest=enc(b64(DEST)), host=enc(self.host_param)) if self.page == "form" else JS_PAGE
            headers = [("Content-Type", "text/html"), ("Set-Cookie", "SESSION_CONTROL_WEBIFACE=sess1; path=/; HttpOnly"),
                       ("Set-Cookie", "TOKEN_CONTROL_WEBIFACE=tok1; path=/")]
            if self.server:
                headers.append(("Server", self.server))
            return httpx.Response(200, headers=headers, text=body)
        if req.url.path == "/internal/dologin.php" and req.method == "POST":
            fields = {k: v[0] for k, v in parse_qs(req.content.decode()).items()}
            self.posts.append({"url": url, "fields": fields, "cookie": req.headers.get("cookie", ""),
                               "referer": req.headers.get("referer"), "origin": req.headers.get("origin")})
            host_ok = parse_qs(req.url.query.decode())["host"][0] == self.host_param
            good = ("SESSION_CONTROL_WEBIFACE" in req.headers.get("cookie", "") and host_ok
                    and fields == {"kerio_username": USER, "kerio_password": PASSWORD})
            if good:
                self.logged_in = True
            if good and not self.always_302_failure:
                return httpx.Response(302, headers={"Location": DEST})
            return httpx.Response(302, headers={"Location": self.login_url(reason=True)})
        if req.url.path == "/status":
            return httpx.Response(200, text="status")
        return httpx.Response(404)

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handle), follow_redirects=True, headers=portal.BROWSER_HEADERS)

    def verify(self):
        return ("open", None) if self.logged_in else ("portal", None)


@pytest.fixture
def creds(tmp_path):
    p = tmp_path / "credentials.toml"
    p.write_text(f'username = "{USER}"\npassword = "{PASSWORD}"\n')
    p.chmod(0o600)
    return p


def cfg_for(creds, **kw):
    return PortalCfg(enabled=True, mode="flow", credentials_file=str(creds), **kw)


def run(creds, sim, trace=None, verify=None, sleep=lambda s: None, **kw):
    return portal.flow_login(cfg_for(creds, **kw), connectivity_url=CONNECT, client=sim.client(), trace=trace,
                             verify=verify or sim.verify, sleep=sleep)


# ---- facts from the HAR
def test_derived_post_url_is_exactly_what_the_browser_sent():
    assert portal.derive_post_url(HAR_LOGIN, "/internal/dologin.php", ["reason"]) == HAR_POST


def test_the_raw_query_survives_base64_characters():
    url = "http://p/login/?x=1&host=ab+cd/ef%3D%3D&reason=failure"
    assert portal.derive_post_url(url, "/do", ["reason"]) == "http://p/do?x=1&host=ab+cd/ef%3D%3D"


def test_the_host_token_really_contains_the_client_ip():
    # why pasting one request breaks: the per-client token cannot be reused for another IP
    token = parse_qs(urlsplit(HAR_LOGIN).query)["host"][0]
    assert base64.b64decode(token).decode().startswith("172.18.40.151 ")


# ---- form parsing
def test_parse_forms_decodes_entities_and_finds_the_login_form():
    html = ('<form action="/search"><input name="q"></form>'
            '<form action="/go?a=1&amp;b=2" method="POST"><input type=hidden name=csrf value=abc>'
            '<input name=user><input type=password name=pw><input type=submit name=go value=Login></form>')
    forms = portal.parse_forms(html)
    assert len(forms) == 2 and portal.pick_login_form(forms) is forms[1]
    assert forms[1].action == "/go?a=1&b=2" and forms[1].method == "post"


def test_no_password_input_means_no_login_form():
    assert portal.pick_login_form(portal.parse_forms("<form><input name=q></form>")) is None
    assert portal.parse_forms("<<<not html") == []


def test_fill_form_keeps_hidden_values_and_skips_buttons_and_unchecked_boxes():
    form = portal.parse_forms(
        '<form><input type=hidden name=csrf value=T123><input name=email><input type=password name=pw>'
        '<input type=checkbox name=remember value=1><input type=checkbox name=terms value=yes checked>'
        '<input type=submit name=go value=Login></form>')[0]
    data = portal.fill_form(form, "me@x", "secret")
    assert data == {"csrf": "T123", "email": "me@x", "pw": "secret", "terms": "yes"}


def test_fill_form_picks_the_username_by_name_and_honours_overrides():
    form = portal.parse_forms("<form><input name=captcha><input name=account_id><input type=password name=p></form>")[0]
    assert portal.fill_form(form, "u", "p")["account_id"] == "u"
    assert portal.fill_form(form, "u", "p", user_field="captcha")["captcha"] == "u"
    with pytest.raises(portal.PortalError, match="username"):
        portal.fill_form(portal.parse_forms("<form><input type=password name=p></form>")[0], "u", "p")
    with pytest.raises(portal.PortalError, match="password"):
        portal.fill_form(portal.parse_forms("<form><input type=password></form>")[0], "u", "p")


# ---- the whole flow
def test_login_with_a_form_uses_the_fresh_token_and_the_session_cookies(creds):
    sim = KerioSim()
    trace = []
    ok, detail = run(creds, sim, trace)
    assert ok and "logged in" in detail
    post = sim.posts[0]
    assert post["url"] == HAR_POST  # the very request the browser made
    assert post["fields"] == {"kerio_username": USER, "kerio_password": PASSWORD}
    assert "SESSION_CONTROL_WEBIFACE=sess1" in post["cookie"] and "TOKEN_CONTROL_WEBIFACE=tok1" in post["cookie"]
    assert post["referer"].startswith("http://account.tvct1.local:4080/login/") and post["origin"] == "http://account.tvct1.local:4080"


def test_the_trace_never_contains_the_credentials(creds):
    trace = []
    run(creds, KerioSim(), trace)
    text = "\n".join(trace)
    assert USER not in text and PASSWORD not in text
    assert "form: POST" in text and "kerio_username (text)" in text and "kerio_password (password)" in text
    assert "SESSION_CONTROL_WEBIFACE" in text and text.rstrip().endswith("4. connectivity check: open")


def test_a_javascript_only_page_works_for_kerio_through_the_known_endpoint(creds):
    sim = KerioSim(page="js")
    trace = []
    ok, _ = run(creds, sim, trace)
    assert ok and sim.posts[0]["url"] == HAR_POST
    assert "Kerio Control" in "\n".join(trace)


def test_kerio_is_recognised_by_its_address_even_without_a_server_header(creds):
    assert run(creds, KerioSim(page="js", server=""))[0]


def test_an_unknown_portal_without_a_form_gives_an_actionable_error(creds):
    class Other(KerioSim):
        def handle(self, req):
            if req.url.host == "connectivitycheck.gstatic.com":
                return httpx.Response(302, headers={"Location": "http://hotspot.example/welcome"})
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text=JS_PAGE)

    ok, detail = run(creds, Other())
    assert not ok and "login --debug" in detail and "post_path" in detail


def test_post_path_and_field_names_can_be_configured_for_other_portals(creds):
    class Other(KerioSim):
        def handle(self, req):
            self.requests.append((req.method, str(req.url)))
            if req.url.host == "connectivitycheck.gstatic.com":
                return httpx.Response(204) if self.logged_in else httpx.Response(302, headers={"Location": "http://hs.example/login?mac=aa&reason=x"})
            if req.method == "GET":
                return httpx.Response(200, headers={"Content-Type": "text/html"}, text=JS_PAGE)
            self.posts.append({"url": str(req.url), "fields": dict(parse_qs(req.content.decode()))})
            self.logged_in = True
            return httpx.Response(302, headers={"Location": DEST})

    sim = Other()
    ok, _ = run(creds, sim, post_path="/do-login", form_username_field="u", form_password_field="p")
    assert ok and sim.posts[0]["url"] == "http://hs.example/do-login?mac=aa"  # `reason` dropped, the rest kept
    assert set(sim.posts[0]["fields"]) == {"u", "p"}


def test_a_wrong_password_is_reported_as_such(creds, tmp_path):
    bad = tmp_path / "bad.toml"
    bad.write_text('username = "USER1234"\npassword = "nope"\n')
    bad.chmod(0o600)
    sim = KerioSim()
    ok, detail = portal.flow_login(PortalCfg(enabled=True, mode="flow", credentials_file=str(bad)),
                                   connectivity_url=CONNECT, client=sim.client(), verify=sim.verify, sleep=lambda s: None)
    assert not ok and "rejected the login" in detail and "username and password" in detail


def test_the_internet_opening_beats_a_failure_looking_response(creds):
    """The portal said 'invalid credentials' (302 back to the login page) but the login worked: trust the internet."""
    sim = KerioSim()
    sim.always_302_failure = True
    ok, detail = run(creds, sim)
    assert ok and "logged in" in detail


def test_each_ip_gets_its_own_token(creds):
    first, second = KerioSim(ip="172.18.40.151", token="a" * 32), KerioSim(ip="172.18.40.77", token="b" * 32)
    assert run(creds, first)[0] and run(creds, second)[0]
    assert first.posts[0]["url"] != second.posts[0]["url"]
    token = lambda sim: base64.b64decode(parse_qs(urlsplit(sim.posts[0]["url"]).query)["host"][0]).decode()  # noqa: E731
    assert token(first) == "172.18.40.151 " + "a" * 32 and token(second) == "172.18.40.77 " + "b" * 32


def test_already_open_means_no_login_and_no_post(creds):
    sim = KerioSim()
    sim.logged_in = True
    ok, detail = run(creds, sim)
    assert ok and "already open" in detail and sim.posts == []


def test_the_connectivity_check_must_look_like_a_portal(creds):
    class Odd(KerioSim):
        def handle(self, req):
            return httpx.Response(503)

    ok, detail = run(creds, Odd())
    assert not ok and "HTTP 503" in detail


def test_the_login_page_may_answer_directly_instead_of_redirecting(creds):
    class Direct(KerioSim):
        def handle(self, req):
            if req.url.host == "connectivitycheck.gstatic.com" and req.url.path == "/generate_204" and not self.logged_in:
                self.requests.append((req.method, str(req.url)))
                return httpx.Response(200, headers=[("Content-Type", "text/html"), ("Set-Cookie", "SESSION_CONTROL_WEBIFACE=s; path=/")],
                                      text=FORM_PAGE.format(dest=enc(b64(DEST)), host=enc(self.host_param)))
            return super().handle(req)

    sim = Direct()
    ok, _ = run(creds, sim)
    assert ok and len(sim.posts) == 1  # the form on the page itself was found and submitted


def test_login_propagation_delay_is_waited_out(creds):
    sim = KerioSim()
    answers = iter([("portal", None), ("portal", None), ("open", None)])
    slept = []
    ok, _ = run(creds, sim, verify=lambda: next(answers), sleep=slept.append)
    assert ok and slept == [0.7, 0.7]


def test_no_internet_after_the_login_is_reported_separately(creds):
    ok, detail = run(creds, KerioSim(), verify=lambda: ("dead", "no answer within 5 s (connection timed out)"))
    assert not ok and "no internet afterwards" in detail and "timed out" in detail


def test_still_blocked_without_a_failure_hint(creds):
    sim = KerioSim()
    sim.always_302_failure = True
    sim.handle_orig = sim.handle

    def never_open(req):
        r = sim.handle_orig(req)
        sim.logged_in = False
        return r

    sim.handle = never_open
    ok, detail = run(creds, sim, verify=lambda: ("portal", None))
    assert not ok and ("rejected" in detail or "still blocks" in detail)


def test_redirects_inside_the_portal_are_followed_but_not_outside(creds):
    sim = KerioSim()
    original = sim.handle

    def with_status_hop(req):
        r = original(req)
        if req.method == "POST" and r.status_code == 302 and "reason" not in r.headers["location"]:
            return httpx.Response(302, headers={"Location": "http://account.tvct1.local:4080/status"})
        return r

    sim.handle = with_status_hop
    assert run(creds, sim)[0]
    assert ("GET", "http://account.tvct1.local:4080/status") in sim.requests
    assert not any("firefox-portal-detection" in u for _m, u in sim.requests)  # never wandered off to the internet


def test_a_dead_portal_is_a_clear_failure(creds):
    def boom(req):
        if req.url.host == "connectivitycheck.gstatic.com":
            return httpx.Response(302, headers={"Location": "http://account.tvct1.local:4080/login/?NTLM=0"})
        raise httpx.ConnectTimeout("t")

    client = httpx.Client(transport=httpx.MockTransport(boom), follow_redirects=True)
    trace = []
    ok, detail = portal.flow_login(cfg_for(creds), connectivity_url=CONNECT, client=client, trace=trace)
    assert not ok and detail == "request failed: ConnectTimeout" and any("request failed" in t for t in trace)


def test_missing_credentials_fail_before_any_request(tmp_path):
    sim = KerioSim()
    ok, detail = portal.flow_login(PortalCfg(enabled=True, mode="flow", credentials_file=str(tmp_path / "none.toml")),
                                   connectivity_url=CONNECT, client=sim.client())
    assert not ok and "no credentials" in detail and sim.requests == []


# ---- name resolution
def test_portal_and_local_names_use_the_dorm_dns_other_names_the_system(monkeypatch):
    asked = []
    monkeypatch.setattr(portal.dnsq, "resolve_via", lambda servers, host, timeout=2.0: asked.append(host) or "192.168.50.2")
    monkeypatch.setattr(portal.socket, "getaddrinfo", lambda host, *a, **k: [] if host == "connectivitycheck.gstatic.com" else (_ for _ in ()).throw(OSError("nx")))
    notes = []
    r = portal.make_flow_resolver(PortalCfg(), ["172.18.32.1"], {"account.tvct1.local"}, notes.append)
    assert r("account.tvct1.local") == "192.168.50.2"  # the portal host
    assert r("printer.local") == "192.168.50.2"  # *.local would go to mDNS on many systems
    assert r("intranet") == "192.168.50.2"  # single-label name
    assert r("connectivitycheck.gstatic.com") is None  # the system DNS (the override) can resolve it
    assert r("only-in-dorm-dns.example") == "192.168.50.2"  # the system DNS failed: fall back to the dorm DNS
    assert asked == ["account.tvct1.local", "printer.local", "intranet", "only-in-dorm-dns.example"]
    assert any("(dorm DNS)" in n for n in notes)


def test_host_ip_pins_the_portal_and_the_dorm_dns_can_be_switched_off(monkeypatch):
    monkeypatch.setattr(portal.dnsq, "resolve_via", lambda *a, **k: pytest.fail("must not ask"))
    pinned = portal.make_flow_resolver(PortalCfg(host_ip="192.168.50.2"), ["172.18.32.1"], {"p.local"}, lambda m: None)
    assert pinned("p.local") == "192.168.50.2"
    off = portal.make_flow_resolver(PortalCfg(resolve_via_dorm_dns=False), ["172.18.32.1"], {"p.local"}, lambda m: None)
    assert off("p.local") is None
    assert portal.make_flow_resolver(PortalCfg(), None, {"p.local"}, lambda m: None)("p.local") is None


# ---- dispatch, trace and the CLI
def test_login_detail_uses_the_flow_in_flow_mode_and_passes_what_it_needs(creds, monkeypatch):
    seen = {}
    monkeypatch.setattr(portal, "flow_login", lambda cfg, **kw: seen.update(kw) or (True, "ok"))
    assert portal.login_detail(cfg_for(creds), dorm_dns=["172.18.32.1"], source_ip="172.18.40.9",
                               connectivity_url="http://x/gen")[0]
    assert seen["connectivity_url"] == "http://x/gen" and seen["dorm_dns"] == ["172.18.32.1"] and seen["source_ip"] == "172.18.40.9"
    assert callable(seen["verify"])


def test_login_detail_in_flow_mode_needs_no_url(creds):
    assert cfg_for(creds).url == ""  # flow mode works without any pasted request
    ok, detail = portal.login_detail(PortalCfg(enabled=False, mode="flow"))
    assert not ok and "not enabled" in detail


def test_login_trace_for_replay_mode_is_one_line(creds, monkeypatch):
    monkeypatch.setattr(portal, "login_detail", lambda *a, **k: (False, "HTTP 403"))
    ok, detail, trace = portal.login_trace(PortalCfg(enabled=True, mode="replay", url="http://p/x", credentials_file=str(creds)))
    assert not ok and trace == ["replay mode: POST http://p/x -> HTTP 403"]


def test_the_hunter_hands_the_connectivity_url_and_source_to_the_login(cfg, monkeypatch):
    seen = {}
    monkeypatch.setattr(portal, "login_detail", lambda pc, **kw: seen.update(kw) or (True, "ok"))
    hunter._login(cfg, "172.18.40.9", "aa:bb")
    assert seen["connectivity_url"] == cfg.tests.connectivity_url and seen["source_ip"] == "172.18.40.9"
    assert seen["dorm_dns"] == cfg.dns.default


def test_check_url_works_with_any_url(monkeypatch):
    seen = []
    monkeypatch.setattr(nt, "_client", lambda timeout=None, source=None: httpx.Client(
        transport=httpx.MockTransport(lambda r: seen.append(str(r.url)) or httpx.Response(204))))
    assert nt.check_url("http://example.test/generate_204")[0] == "open" and seen == ["http://example.test/generate_204"]


PROFILE = NetProfile("wlan0", "Khabgah", "manual", "172.18.40.9", 21, "172.18.47.254", ["8.8.8.8"], "aa:bb")


@pytest.fixture
def invoke(cfg, monkeypatch, tmp_path, creds):
    cfgfile = tmp_path / "config.toml"
    cfgfile.write_text(cfg.source.read_text() + f'\n[portal]\nenabled = true\nmode = "flow"\ncredentials_file = "{creds}"\n')
    monkeypatch.setattr(netinfo, "get_profile", lambda i, c: PROFILE)
    return lambda *a: CliRunner().invoke(cli.app, ["--config", str(cfgfile), *a])


def test_cli_login_debug_prints_the_trace_without_secrets(invoke, monkeypatch):
    sim = KerioSim()
    states = iter(["portal", "open"])
    monkeypatch.setattr(nt, "check_portal", lambda c, source=None: (next(states), 0, "http://account.tvct1.local:4080/login/?x" if False else None))

    def fake_trace(pc, **kw):
        return True, "logged in (the portal answered HTTP 302)", ["1. GET connectivity -> HTTP 302", "2. GET login page -> HTTP 200", "3. POST form -> HTTP 302", "4. connectivity check: open"]

    monkeypatch.setattr(portal, "login_trace", fake_trace)
    r = invoke("login", "--debug")
    flat = " ".join(r.output.split())
    assert r.exit_code == 0 and "1. GET connectivity" in flat and "Logged in:" in flat
    assert USER not in r.output and PASSWORD not in r.output
    assert sim  # (the simulator is exercised in the tests above)


def test_cli_login_failure_prints_the_trace_and_a_hint(invoke, monkeypatch):
    monkeypatch.setattr(nt, "check_portal", lambda c, source=None: ("portal", 0, None))
    monkeypatch.setattr(portal, "login_trace", lambda pc, **kw: (False, "the portal rejected the login", ["1. step one", "3. POST -> 302"]))
    r = invoke("login", "--force")
    flat = " ".join(r.output.split())
    assert r.exit_code == 1 and "1. step one" in flat and "Login failed:" in flat and "login --debug" in flat


def test_cli_login_dry_run_describes_the_flow(invoke):
    r = invoke("--dry-run", "login")
    assert r.exit_code == 0 and "open the portal's login page" in " ".join(r.output.split())


# ---- no mocks: a real HTTP server on localhost plays the portal (real sockets, cookies, name rewriting)
def test_flow_over_real_sockets_with_a_portal_name_that_only_resolves_through_our_override(creds):
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    state = {"logged_in": False, "hosts": [], "posts": []}

    class Portal(BaseHTTPRequestHandler):
        def log_message(self, *a):  # keep the test output quiet
            pass

        def _send(self, code, headers=(), body=b""):
            self.send_response(code)
            for k, v in headers:
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            port = self.server.server_address[1]
            state["hosts"].append(self.headers["Host"])
            if self.path == "/generate_204":
                if state["logged_in"]:
                    return self._send(204)
                loc = f"http://account.tvct1.local:{port}/login/?NTLM=0&dest={enc(b64(DEST))}&host={enc(b64('172.18.40.151 ' + 'f' * 32))}"
                return self._send(302, [("Location", loc)])
            if self.path.startswith("/login/"):
                form = FORM_PAGE.format(dest=enc(b64(DEST)), host=enc(b64("172.18.40.151 " + "f" * 32))).encode()
                return self._send(200, [("Content-Type", "text/html"), ("Set-Cookie", "SESSION_CONTROL_WEBIFACE=real1; path=/")], form)
            self._send(404)

        def do_POST(self):
            state["hosts"].append(self.headers["Host"])
            body = self.rfile.read(int(self.headers["Content-Length"])).decode()
            fields = {k: v[0] for k, v in parse_qs(body).items()}
            state["posts"].append((self.path, fields, self.headers.get("Cookie", "")))
            ok = fields == {"kerio_username": USER, "kerio_password": PASSWORD} and "SESSION_CONTROL_WEBIFACE=real1" in self.headers.get("Cookie", "")
            state["logged_in"] = state["logged_in"] or ok
            self._send(302, [("Location", DEST if ok else "/login/?reason=failure")])

    server = ThreadingHTTPServer(("127.0.0.1", 0), Portal)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    try:
        connectivity = f"http://127.0.0.1:{port}/generate_204"
        cfg = PortalCfg(enabled=True, mode="flow", credentials_file=str(creds), host_ip="127.0.0.1", timeout=5)
        trace = []
        ok, detail = portal._login_flow(cfg, dorm_dns=None, source_ip=None, client=None, connectivity_url=connectivity, trace=trace)
        assert ok, (detail, trace)
        # the portal name was never resolvable here: the request went to 127.0.0.1 but still carried the real Host header
        assert f"account.tvct1.local:{port}" in state["hosts"]
        path, fields, cookie = state["posts"][0]
        assert path.startswith("/internal/dologin.php?NTLM=0&dest=") and fields == {"kerio_username": USER, "kerio_password": PASSWORD}
        assert "SESSION_CONTROL_WEBIFACE=real1" in cookie
        assert "host=" + enc(b64("172.18.40.151 " + "f" * 32)) in path  # the fresh token from the redirect, byte for byte
        assert USER not in "\n".join(trace) and PASSWORD not in "\n".join(trace)
        # logging in again is a no-op: the portal now lets us through
        again, why = portal._login_flow(cfg, dorm_dns=None, source_ip=None, client=None, connectivity_url=connectivity)
        assert again and "already open" in why and len(state["posts"]) == 1
    finally:
        server.shutdown()