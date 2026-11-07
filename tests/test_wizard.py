import os
import stat
import tomllib

import pytest

from dorm_ip import portal, wizard
from dorm_ip.config import load_config

CURL = r"""curl 'http://portal.dorm.local/login.php?x=1' \
  -H 'Accept: text/html' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Cookie: PHPSESSID=abc' \
  -H 'sec-ch-ua: "Chromium"' \
  --data-raw $'user=USER1234&pass=PASS5678&ip=172.18.40.9&mode=login' \
  --compressed"""


class Scripted(wizard.Prompter):
    """Answers keyed by a substring of the question; anything else gets the default."""

    def __init__(self, answers=None, confirms=None, secret="", paste=""):
        self.answers, self.confirms, self._secret, self._paste = answers or {}, confirms or {}, secret, paste
        self.said, self.asked = [], []

    def say(self, text): self.said.append(text)

    def ask(self, text, default=""):
        self.asked.append(text)
        return next((v for k, v in self.answers.items() if k in text), default)

    def confirm(self, text, default=True):
        return next((v for k, v in self.confirms.items() if k in text), default)

    def secret(self, text): return self._secret
    def choose(self, text, choices, default): return next((v for k, v in self.answers.items() if k in text), default)
    def paste(self, text): return self._paste


DET = wizard.Detected("wlp3s0", "Khabgah", "172.18.47.254", 21, ["172.18.32.1"], "auto", "172.18.40.9", "aa:bb:cc:dd:ee:ff")


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    return tmp_path


def run(home, prompter, detect=lambda: DET, curl_text=None, **kw):
    target = home / "cfg" / "dorm-ip" / "config.toml"
    creds = home / "creds.toml"
    # point credentials at the temp dir via an existing config that only sets that path
    base = home / "base.toml"
    base.write_text(f'[portal]\ncredentials_file = "{creds}"\n')
    return wizard.run_init(prompter, target=target, curl_text=curl_text, detect=detect, source=base, **kw), target, creds


def test_render_roundtrip_and_loadable(tmp_path):
    values = wizard.example_values()
    text = wizard.render_config(values)
    assert tomllib.loads(text) == values
    p = tmp_path / "c.toml"
    p.write_text(text)
    assert load_config(p).network.gateway == values["network"]["gateway"]


def test_toml_value_escapes():
    assert wizard.toml_str('a"b\\c') == '"a\\"b\\\\c"'
    assert tomllib.loads(f"x = {wizard.toml_value({'k': ['a', 1, True, 2.5]})}") == {"x": {"k": ["a", 1, True, 2.5]}}


def test_example_has_no_credentials_or_portal_details():
    ex = wizard.example_values()["portal"]
    assert ex["enabled"] is False and ex["url"] == "" and ex["fields"] == {}


def test_defaults_wizard_uses_detected_network(home):
    res, target, _ = run(home, Scripted())
    cfg = load_config(target)
    assert res.config_path == target and not res.portal_enabled
    assert cfg.network.interface == "wlp3s0" and cfg.network.gateway == "172.18.47.254"
    assert cfg.dns.final_mode == "override" and cfg.network.prefer_unused
    assert cfg.thresholds.speed_rule == "either" and cfg.thresholds.min_speed_mbps == 8


def test_answers_are_applied(home):
    p = Scripted(
        answers={"Minimum speed": "2", "Maximum ping": "300", "Daily data budget": "0",
                 "Override DNS": "1.1.1.1, 8.8.8.8", "Seconds between": "60", "Candidates": "10"},
        confirms={"EITHER": False, "Try IPs nobody": False, "Desktop notifications": False},
    )
    res, target, _ = run(home, p)
    cfg = load_config(target)
    assert cfg.thresholds.min_speed_mbps == 16 and cfg.thresholds.min_sustained_mbps == 16
    assert cfg.thresholds.speed_rule == "both" and cfg.thresholds.max_ping_ms == 300
    assert cfg.tests.data_budget_mb == 0 and cfg.tests.budget_bytes() == float("inf")
    assert cfg.dns.override == ["1.1.1.1", "8.8.8.8"] and cfg.watchdog.interval_seconds == 60
    assert cfg.hunt.max_candidates == 10 and cfg.network.prefer_unused is False and cfg.watchdog.notify is False


def test_invalid_answer_is_asked_again(home):
    answers = iter(["abc", "-3", "1"])

    class P(Scripted):
        def ask(self, text, default=""):
            return next(answers) if "Minimum speed" in text else default

    run(home, P())
    assert not list(answers)  # all three were consumed: two rejected, one accepted


def test_portal_setup_from_curl_without_secrets_in_config(home):
    p = Scripted(secret="PASS5678", answers={"Portal username": "USER1234", "successful login": "Welcome",
                                             "How should I log in": "replay"}, paste=CURL)
    res, target, creds = run(home, p)
    text = target.read_text()
    assert "USER1234" not in text and "PASS5678" not in text and "PHPSESSID" not in text
    cfg = load_config(target)
    assert res.portal_enabled and cfg.portal.enabled and cfg.portal.url.startswith("http://portal.dorm.local/login.php")
    assert cfg.portal.fields == {"user": "{username}", "pass": "{password}", "ip": "{ip}", "mode": "login"}
    assert cfg.portal.success_contains == "Welcome" and cfg.portal.login_during_hunt is True
    assert "sec-ch-ua" not in cfg.portal.headers and "Accept" in cfg.portal.headers
    # credentials file: only readable by the user, correct TOML
    assert stat.S_IMODE(os.stat(creds).st_mode) == 0o600
    assert tomllib.loads(creds.read_text()) == {"username": "USER1234", "password": "PASS5678"}
    assert res.credentials_path == creds


def test_curl_file_option_skips_pasting(home):
    p = Scripted(secret="PASS5678", answers={"Portal username": "USER1234"}, paste="SHOULD NOT BE USED")
    res, target, _ = run(home, p, curl_text=CURL)
    assert res.portal_enabled


def test_missing_login_request_keeps_portal_off_but_saves_credentials(home):
    res, target, creds = run(home, Scripted(secret="pw", answers={"Portal username": "u", "How should I log in": "replay"}, paste=""))
    assert not res.portal_enabled and not load_config(target).portal.enabled
    assert creds.exists() and any("No login request" in n for n in res.notes)


def test_missing_password_keeps_portal_off(home):
    res, target, creds = run(home, Scripted(secret="", answers={"Portal username": "u"}))
    assert not res.portal_enabled and not creds.exists() and any("No username/password" in n for n in res.notes)


def test_bad_curl_is_reported_not_fatal(home):
    p = Scripted(secret="pw", answers={"Portal username": "u", "How should I log in": "replay"}, paste="this is not curl")
    res, target, _ = run(home, p)
    assert not res.portal_enabled and any("cURL" in s for s in p.said)


def test_rerun_keeps_existing_values_and_backs_up(home):
    p = Scripted(secret="PASS5678", answers={"Portal username": "USER1234"}, paste=CURL)
    run(home, p)
    target = home / "cfg" / "dorm-ip" / "config.toml"
    first = target.read_text()
    # second run: keep saved password (Enter), keep existing request
    p2 = Scripted(secret="", answers={"Portal username": "USER1234"})
    res, _, creds = run(home, p2)
    assert res.portal_enabled and "{password}" in target.read_text()
    assert tomllib.loads(creds.read_text())["password"] == "PASS5678"
    assert target.with_name("config.toml.bak").read_text() == first


def test_declining_overwrite_changes_nothing(home):
    run(home, Scripted())
    target = home / "cfg" / "dorm-ip" / "config.toml"
    before = target.read_text()
    res, _, _ = run(home, Scripted(confirms={"exists. Update it": False}))
    assert res is None and target.read_text() == before


def test_not_connected_uses_defaults(home):
    res, target, _ = run(home, Scripted(), detect=lambda: None)
    assert load_config(target).network.interface == "wlan0"


def test_manual_method_does_not_overwrite_dns(home):
    det = wizard.Detected("wlan0", "K", "172.18.47.254", 21, ["8.8.8.8"], "manual")
    _, target, _ = run(home, Scripted(), detect=lambda: det)
    assert load_config(target).dns.default == ["172.18.32.1"]


def test_auto_prompter_accepts_defaults(home):
    target = home / "cfg" / "dorm-ip" / "config.toml"
    res = wizard.run_init(wizard.AutoPrompter(lambda m: None), target=target, detect=lambda: None)
    assert res and load_config(target)


# ---- cURL parser
def test_parse_curl_basics():
    r = portal.parse_curl(CURL)
    assert r.method == "POST" and r.url.startswith("http://portal.dorm.local") and "user=USER1234" in r.body


def test_parse_curl_get_json_and_errors():
    g = portal.parse_curl("curl 'http://p/login?u=1' -H 'X: y'")
    assert g.method == "GET" and g.body is None
    j = portal.parse_curl("""curl 'http://p/api' -X POST -H 'content-type: application/json' --data-raw '{"u":"alice1","n":5}'""")
    section, warns = portal.curl_to_portal(j, username="alice1", password="zzzz")
    assert section["content_type"] == "json" and section["fields"] == {"u": "{username}", "n": "5"}
    assert any("not a string" in w for w in warns)
    with pytest.raises(portal.PortalError):
        portal.parse_curl("wget http://x")
    with pytest.raises(portal.PortalError):
        portal.parse_curl("curl -H")


def test_curl_warns_when_credentials_not_found():
    r = portal.parse_curl("curl 'http://p/login' --data-raw 'a=b'")
    _, warns = portal.curl_to_portal(r, username="nobody123", password="nothing456")
    assert any("not found" in w for w in warns)


def test_curl_url_encoded_secret_in_url():
    r = portal.parse_curl("curl 'http://p/login?pw=p%40ss%21word&u=USER1234'")
    section, _ = portal.curl_to_portal(r, username="USER1234", password="p@ss!word")
    assert "{password}" in section["url"] and "{username}" in section["url"] and "p%40ss" not in section["url"]


def test_curl_insecure_and_unsupported_method():
    r = portal.parse_curl("curl 'https://p/x' -X PUT -k --data-raw 'a=1'")
    section, warns = portal.curl_to_portal(r, username="uuuu", password="pppp")
    assert section["verify_tls"] is False and section["method"] == "POST" and any("PUT" in w for w in warns)


# ---- the real prompts (typer), driven through stdin
def test_wizard_has_no_direct_click_dependency():
    from pathlib import Path

    assert "import click" not in Path(wizard.__file__).read_text()


def test_typer_prompter_choose_reprompts_until_valid():
    import typer
    from typer.testing import CliRunner

    app = typer.Typer()

    @app.command()
    def go():
        print("got", wizard.TyperPrompter(print).choose("Pick", ["override", "default", "auto"], "override"))

    r = CliRunner().invoke(app, input="bogus\nAUTO\n")
    assert "got auto" in r.output and "please type one of" in r.output
    assert "got override" in CliRunner().invoke(app, input="\n").output  # Enter = the default


def test_init_end_to_end_through_the_real_prompts(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from dorm_ip import cli, netinfo

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(netinfo, "get_profile", lambda i, c: (_ for _ in ()).throw(netinfo.NetError("no wifi")))
    answers = "\n".join([
        "",              # network settings correct? (Enter = yes)
        "",              # try unused IPs first? (Enter = yes)
        "",              # override DNS
        "",              # DNS to keep
        "",              # minimum speed
        "",              # either/or
        "",              # max ping
        "",              # candidates
        "",              # order
        "",              # budget
        "",              # log in automatically? (Enter = yes)
        "USER1234",      # username
        "PASS5678",      # password (hidden)
        "replay",        # how to log in (flow is the default)
        *CURL.splitlines(),
        "",              # end of the pasted request
        "Welcome",       # success text
        "",              # log in during hunts? (Enter = yes)
        "",              # watchdog interval
        "",              # notifications
    ]) + "\n"
    # --no-shell: this test is about the prompts above; the shell question has its own tests (test_shellint.py)
    r = CliRunner().invoke(cli.app, ["init", "--no-shell"], input=answers)
    assert r.exit_code == 0, r.output + str(r.exception)
    target = tmp_path / "cfg" / "dorm-ip" / "config.toml"
    cfg = load_config(target)
    assert cfg.portal.enabled and cfg.portal.success_contains == "Welcome" and cfg.portal.login_during_hunt
    assert "PASS5678" not in target.read_text() and "USER1234" not in target.read_text()
    creds = tmp_path / ".config" / "dorm-ip" / "credentials.toml"
    assert stat.S_IMODE(os.stat(creds).st_mode) == 0o600
    assert tomllib.loads(creds.read_text()) == {"username": "USER1234", "password": "PASS5678"}


# ---- flow mode in the wizard (the default: nothing to paste)
def test_flow_is_the_default_and_needs_no_login_request(home):
    p = Scripted(secret="PASS5678", answers={"Portal username": "USER1234"}, paste="SHOULD NOT BE ASKED")
    res, target, creds = run(home, p)
    cfg = load_config(target)
    assert res.portal_enabled and cfg.portal.enabled and cfg.portal.mode == "flow" and cfg.portal.url == ""
    assert cfg.portal.login_during_hunt is True
    assert not any("Copy as cURL" in s for s in p.said) and any("Nothing to paste" in s for s in p.said)
    assert tomllib.loads(creds.read_text()) == {"username": "USER1234", "password": "PASS5678"}
    assert "PASS5678" not in target.read_text()


def test_existing_pasted_request_keeps_replay_as_the_default(home):
    first = Scripted(secret="PASS5678", answers={"Portal username": "USER1234", "How should I log in": "replay"}, paste=CURL)
    run(home, first)
    target = home / "cfg" / "dorm-ip" / "config.toml"
    text = target.read_text().replace('mode = "replay"  # flow', 'MODE_REMOVED  # flow')
    target.write_text("\n".join(l for l in text.splitlines() if not l.startswith("MODE_REMOVED")) + "\n")  # an old config
    assert "mode =" not in target.read_text().split("[portal]")[1].split("enabled")[1].split("url")[0]
    asked = []

    class Spy(Scripted):
        def choose(self, text, choices, default):
            if "How should I log in" in text:
                asked.append(default)
            return super().choose(text, choices, default)

    res, _, _ = run(home, Spy(secret="", answers={"Portal username": "USER1234"}))
    assert asked == ["replay"] and res.portal_enabled


def test_curl_file_forces_replay_without_asking(home):
    p = Scripted(secret="PASS5678", answers={"Portal username": "USER1234"})
    res, target, _ = run(home, p, curl_text=CURL)
    assert load_config(target).portal.mode == "replay" and not any("How should I log in" in q for q in p.asked)
