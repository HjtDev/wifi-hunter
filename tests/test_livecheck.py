from dataclasses import replace

import pytest
from typer.testing import CliRunner

from dorm_ip import applier, cli, livecheck, netinfo
from dorm_ip import tests as nt
from dorm_ip.livecheck import StepTiming
from dorm_ip.models import NetProfile

PROFILE = NetProfile("wlan0", "Khabgah", "auto", "172.18.40.5", 21, "172.18.47.254", ["172.18.32.1"], "aa:bb")


class World:
    """A fake machine: tracks the live address and when the gateway starts answering."""

    def __init__(self, monkeypatch, live_works=True, live_reachable=True):
        self.t = 0.0
        self.addr = "172.18.40.5"
        self.ready_at = 0.0
        self.log = []
        self.live_works, self.live_reachable = live_works, live_reachable
        monkeypatch.setattr(applier, "apply_live", self.apply_live)
        monkeypatch.setattr(applier, "apply_static", self.apply_static)
        monkeypatch.setattr(applier, "restore", self.restore)
        monkeypatch.setattr(netinfo, "live_addresses", lambda dev: [self.addr])
        monkeypatch.setattr(nt, "ping", lambda host, n, wait=2: (20.0, 0.0 if self.t >= self.ready_at else 100.0, 1.0))

    def sleep(self, s): self.t += s
    def clock(self): return self.t

    def apply_live(self, ip, prefix, gw, dns, *, device, dry_run=False):
        self.log.append("live")
        self.t += 0.2
        if self.live_works:
            self.addr = ip
            self.ready_at = self.t + (0.3 if self.live_reachable else 1e9)

    def apply_static(self, ip, prefix, gw, dns, *, connection, dry_run=False):
        self.log.append("reconnect")
        self.t += 0.5
        self.addr = ip
        self.ready_at = self.t + 6.0

    def restore(self, dry_run=False, keep_backup=False):
        self.log.append("restore-keep" if keep_backup else "restore")
        self.addr = "172.18.40.5"
        self.ready_at = self.t + 5.0
        return "Dorm"


def run(cfg, w, compare=False):
    return livecheck.run_live_check(cfg, applier.Target("Dorm", "wlan0"), "172.18.40.9", compare=compare,
                                    sleep=w.sleep, clock=w.clock)


def test_live_works_and_is_faster(cfg, monkeypatch):
    w = World(monkeypatch)
    steps = run(cfg, w, compare=True)
    assert [s.method for s in steps] == ["live", "reconnect"]
    assert steps[0].gateway_s < 1.0 < 5.0 < steps[1].gateway_s
    assert w.log == ["live", "restore-keep", "reconnect", "restore"]  # always ends with the original profile
    level, msg = livecheck.verdict(steps)
    assert level == "ok" and "Live switching works" in msg and "slower" in msg


def test_live_without_compare_only_measures_live(cfg, monkeypatch):
    w = World(monkeypatch)
    steps = run(cfg, w)
    assert len(steps) == 1 and w.log == ["live", "restore"]


def test_address_never_changes_means_it_does_not_work(cfg, monkeypatch):
    w = World(monkeypatch, live_works=False)
    steps = run(cfg, w)
    assert steps[0].visible_s is None
    level, msg = livecheck.verdict(steps)
    assert level == "bad" and 'live_change = "off"' in msg and w.log[-1] == "restore"


def test_address_changes_but_gateway_silent_is_inconclusive(cfg, monkeypatch):
    w = World(monkeypatch, live_reachable=False)
    steps = run(cfg, w)
    assert steps[0].visible_s is not None and steps[0].gateway_s is None
    level, msg = livecheck.verdict(steps)
    assert level == "warn" and "--ip" in msg


def test_nmcli_refusal_is_reported_and_profile_restored(cfg, monkeypatch):
    w = World(monkeypatch)

    def refuse(*a, **k):
        raise netinfo.NetError("Device not connected")

    monkeypatch.setattr(applier, "apply_live", refuse)
    steps = run(cfg, w)
    assert livecheck.verdict(steps)[0] == "bad" and "Device not connected" in steps[0].note and w.log == ["restore"]


def test_restore_happens_even_if_the_second_step_blows_up(cfg, monkeypatch):
    w = World(monkeypatch)

    def boom(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(applier, "apply_static", boom)
    with pytest.raises(RuntimeError):
        run(cfg, w, compare=True)
    assert w.log[-1] == "restore"


# ---- the CLI command
@pytest.fixture
def invoke(cfg, monkeypatch, tmp_path):
    cfgfile = tmp_path / "config.toml"
    cfgfile.write_text(cfg.source.read_text())
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setattr(netinfo, "get_profile", lambda i, c: PROFILE)
    monkeypatch.setattr(netinfo, "tunnel_device", lambda i: None)
    monkeypatch.setattr(applier, "begin_change", lambda i, c, dry_run=False, notify=None: applier.Target("Khabgah", "wlan0"))
    return lambda *a: CliRunner().invoke(cli.app, ["--config", str(cfgfile), *a])


def test_cli_needs_a_known_good_ip(invoke):
    r = invoke("live-check")
    assert r.exit_code == 1 and "known-good IP" in str(r.exception)


def test_cli_refuses_the_current_ip(invoke):
    r = invoke("live-check", "--ip", "172.18.40.5")
    assert r.exit_code == 1 and "already your current IP" in str(r.exception)


def test_cli_reports_timings_and_verdict(invoke, monkeypatch):
    steps = [StepTiming("live", 0.2, 0.3, 0.6), StepTiming("reconnect", 0.5, 4.0, 6.5)]
    monkeypatch.setattr(livecheck, "run_live_check", lambda *a, **k: steps)
    r = invoke("live-check", "--ip", "172.18.40.9", "--compare")
    assert r.exit_code == 0
    flat = " ".join(r.output.split())
    assert "Live switching works" in flat and "0.6s" in flat and "6.5s" in flat and "11x slower" in flat


def test_cli_exit_code_is_1_when_live_does_not_work(invoke, monkeypatch):
    monkeypatch.setattr(livecheck, "run_live_check", lambda *a, **k: [StepTiming("live", 0.2, None, None)])
    r = invoke("live-check", "--ip", "172.18.40.9")
    assert r.exit_code == 1 and "does not work" in " ".join(r.output.split())


def test_cli_dry_run_prints_the_command_and_changes_nothing(invoke, monkeypatch, capsys):
    monkeypatch.setattr(livecheck, "run_live_check", lambda *a, **k: pytest.fail("must not run"))
    r = invoke("--dry-run", "live-check", "--ip", "172.18.40.9")
    assert r.exit_code == 0 and "device modify wlan0" in r.output.replace("\n", " ")