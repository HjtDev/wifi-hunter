import json
from dataclasses import replace

import httpx
import pytest

from dorm_ip import portal
from dorm_ip.config import PortalCfg


@pytest.fixture
def creds(tmp_path):
    p = tmp_path / "credentials.toml"
    p.write_text('username = "u123"\npassword = "p@ss{word}&x"\n')
    p.chmod(0o600)
    return p


def pcfg(creds, **kw):
    base = PortalCfg(
        enabled=True, url="http://portal.local/login?ip={ip}", method="POST", content_type="form",
        fields={"user": "{username}", "pass": "{password}", "mac": "{mac}", "mode": "login"},
        headers={"X-Test": "1"}, credentials_file=str(creds),
    )
    return replace(base, **kw)


def client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)


def test_render_only_known_tokens():
    out = portal.render('{"a": "{username}", "b": "{other}"}', {"username": "u", "password": "p", "ip": "", "mac": ""})
    assert out == '{"a": "u", "b": "{other}"}'


def test_credentials_permissions_enforced(creds):
    creds.chmod(0o644)
    with pytest.raises(portal.PortalError, match="chmod 600"):
        portal.load_credentials(pcfg(creds))
    creds.chmod(0o600)
    assert portal.load_credentials(pcfg(creds)) == ("u123", "p@ss{word}&x")


def test_credentials_missing_and_malformed(tmp_path):
    with pytest.raises(portal.PortalError, match="no credentials"):
        portal.load_credentials(PortalCfg(credentials_file=str(tmp_path / "nope.toml")))
    bad = tmp_path / "c.toml"
    bad.write_text('username = "x"\n')
    bad.chmod(0o600)
    with pytest.raises(portal.PortalError, match="password"):
        portal.load_credentials(PortalCfg(credentials_file=str(bad)))


def test_form_login_sends_rendered_fields(creds):
    seen = {}

    def handler(req):
        seen["url"], seen["body"], seen["h"] = str(req.url), req.content.decode(), req.headers["x-test"]
        return httpx.Response(200, text="Welcome")

    ok, detail = portal.login_detail(pcfg(creds), ip="172.18.40.9", mac="aa:bb", client=client(handler))
    assert ok and detail == "HTTP 200"
    assert seen["url"] == "http://portal.local/login?ip=172.18.40.9" and seen["h"] == "1"
    assert "user=u123" in seen["body"] and "pass=p%40ss%7Bword%7D%26x" in seen["body"] and "mac=aa%3Abb" in seen["body"]


def test_json_login(creds):
    seen = {}

    def handler(req):
        seen["json"] = json.loads(req.content)
        return httpx.Response(200, json={"ok": True})

    assert portal.login(pcfg(creds, content_type="json"), client=client(handler))
    assert seen["json"]["user"] == "u123" and seen["json"]["pass"] == "p@ss{word}&x"


def test_get_login_puts_fields_in_query(creds):
    seen = {}

    def handler(req):
        seen["params"] = dict(req.url.params)
        return httpx.Response(200)

    portal.login(pcfg(creds, method="GET", query={"a": "1"}), client=client(handler))
    assert seen["params"]["user"] == "u123" and seen["params"]["a"] == "1"


def test_success_and_failure_text(creds):
    ok = lambda text: portal.login_detail(  # noqa: E731
        pcfg(creds, success_contains="logged in", failure_contains="invalid"),
        client=client(lambda req: httpx.Response(200, text=text)),
    )
    assert ok("You are logged in")[0]
    assert not ok("invalid password")[0]
    assert "success_contains" in ok("something else")[1]


def test_http_error_and_network_error(creds):
    assert portal.login_detail(pcfg(creds), client=client(lambda r: httpx.Response(403))) == (False, "HTTP 403")

    def boom(req):
        raise httpx.ConnectTimeout("x")

    ok, detail = portal.login_detail(pcfg(creds), client=client(boom))
    assert not ok and "ConnectTimeout" in detail


def test_follows_redirect_to_success(creds):
    def handler(req):
        if req.url.path == "/login":
            return httpx.Response(302, headers={"location": "http://portal.local/ok"})
        return httpx.Response(200, text="done")

    assert portal.login(pcfg(creds), client=client(handler))


def test_disabled_or_none_is_false(creds):
    assert portal.login(None) is False
    ok, detail = portal.login_detail(pcfg(creds, enabled=False))
    assert not ok and "not enabled" in detail


def test_secrets_never_in_reason(creds):
    ok, detail = portal.login_detail(pcfg(creds), client=client(lambda r: httpx.Response(500, text="p@ss{word}&x")))
    assert "p@ss" not in detail and "u123" not in detail


# ---- resolving through the dorm DNS
def test_resolving_transport_connects_to_ip_but_keeps_name():
    seen = {}

    def handler(req):
        seen["url"], seen["host"], seen["sni"] = str(req.url), req.headers["host"], req.extensions.get("sni_hostname")
        return httpx.Response(200)

    tr = portal.ResolvingTransport(httpx.MockTransport(handler), lambda h: "172.18.32.50")
    with httpx.Client(transport=tr) as c:
        c.get("https://portal.dorm.local/login?a=1")
    assert seen == {"url": "https://172.18.32.50/login?a=1", "host": "portal.dorm.local", "sni": "portal.dorm.local"}


def test_resolving_transport_caches_and_falls_back():
    calls = []

    def resolver(h):
        calls.append(h)
        return None

    urls = []
    tr = portal.ResolvingTransport(httpx.MockTransport(lambda r: urls.append(str(r.url)) or httpx.Response(200)), resolver)
    with httpx.Client(transport=tr) as c:
        c.get("http://portal.dorm.local/a")
        c.get("http://portal.dorm.local/b")
        c.get("http://10.0.0.1/c")  # IP literals are never resolved
    assert calls == ["portal.dorm.local"] and urls[0] == "http://portal.dorm.local/a" and urls[2] == "http://10.0.0.1/c"


def test_login_uses_dorm_dns_for_the_portal_host(creds, monkeypatch):
    asked = []
    monkeypatch.setattr(portal.dnsq, "resolve_via", lambda servers, host, timeout=2.0: asked.append((servers, host)) or "172.18.32.50")
    seen = {}
    monkeypatch.setattr(
        portal.httpx, "HTTPTransport",
        lambda verify=True: httpx.MockTransport(lambda r: seen.update(url=str(r.url), host=r.headers["host"]) or httpx.Response(200, text="ok")),
    )
    ok, _ = portal.login_detail(pcfg(creds, url="http://portal.dorm.local/login"), dorm_dns=["172.18.32.1"])
    assert ok and asked == [(["172.18.32.1"], "portal.dorm.local")]
    assert seen == {"url": "http://172.18.32.50/login", "host": "portal.dorm.local"}


def test_host_ip_overrides_dns_and_dns_can_be_disabled(creds, monkeypatch):
    monkeypatch.setattr(portal.dnsq, "resolve_via", lambda *a, **k: pytest.fail("DNS must not be asked"))
    seen = {}
    monkeypatch.setattr(
        portal.httpx, "HTTPTransport",
        lambda verify=True: httpx.MockTransport(lambda r: seen.update(url=str(r.url)) or httpx.Response(200)),
    )
    portal.login_detail(pcfg(creds, url="http://portal.dorm.local/x", host_ip="10.9.9.9"), dorm_dns=["172.18.32.1"])
    assert seen["url"] == "http://10.9.9.9/x"
    portal.login_detail(pcfg(creds, url="http://portal.dorm.local/x", resolve_via_dorm_dns=False), dorm_dns=["172.18.32.1"])
    assert seen["url"] == "http://portal.dorm.local/x"
