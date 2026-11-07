import random

import pytest

from dorm_ip import netinfo, scanner
from dorm_ip.netinfo import NetError

ARP = """172.18.40.5\t94:bb:43:d5:37:3a\t(Unknown)
172.18.40.7\taa:bb:cc:dd:ee:01\tSome Vendor Inc
172.18.40.7\taa:bb:cc:dd:ee:01\tSome Vendor Inc (DUP: 2)
172.18.99.9\taa:bb:cc:dd:ee:02\tOutside candidates
garbage line
"""


def test_parse_arp_scan():
    assert scanner.parse_arp_scan(ARP) == {"172.18.40.5", "172.18.40.7", "172.18.99.9"}
    assert scanner.parse_arp_scan("") == set()


def test_arp_command_uses_configured_ranges_only(cfg):
    cmd = scanner.arp_command(cfg, "wlan0")
    assert cmd[:3] == ["arp-scan", "--interface", "wlan0"]
    assert cmd[-1] == "172.18.40.1-172.18.40.20"
    assert "--localnet" not in cmd


def test_scan_used_intersects_with_candidates(cfg, monkeypatch):
    monkeypatch.setattr(scanner.shutil, "which", lambda n: "/usr/bin/arp-scan")
    monkeypatch.setattr(netinfo, "run", lambda cmd, timeout=30: ARP)
    assert scanner.scan_used(cfg, "wlan0") == {"172.18.40.5", "172.18.40.7"}


def test_scan_retries_with_sudo_on_permission_error(cfg, monkeypatch):
    calls = []

    def fake(cmd, timeout=30):
        calls.append(cmd)
        if cmd[0] != "sudo":
            raise NetError("arp-scan failed: You don't have permission to capture on that device")
        return ARP

    monkeypatch.setattr(scanner.shutil, "which", lambda n: "/usr/bin/arp-scan")
    monkeypatch.setattr(scanner.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(netinfo, "run", fake)
    assert "172.18.40.5" in scanner.scan_used(cfg, "wlan0")
    assert [c[0] for c in calls] == ["arp-scan", "sudo"]


def test_scan_other_errors_are_not_retried(cfg, monkeypatch):
    monkeypatch.setattr(scanner.shutil, "which", lambda n: "/usr/bin/arp-scan")
    monkeypatch.setattr(scanner.os, "geteuid", lambda: 1000)

    def boom(cmd, timeout=30):
        raise NetError("interface wlan9 does not exist")

    monkeypatch.setattr(netinfo, "run", boom)
    with pytest.raises(NetError, match="wlan9"):
        scanner.scan_used(cfg, "wlan0")


def test_scan_missing_binary_and_dry_run(cfg, monkeypatch, capsys):
    monkeypatch.setattr(scanner.shutil, "which", lambda n: None)
    with pytest.raises(NetError, match="pacman"):
        scanner.scan_used(cfg, "wlan0")
    assert scanner.scan_used(cfg, "wlan0", dry_run=True) == set()
    assert "[dry-run] arp-scan" in capsys.readouterr().out


# ---- ordering
USED = {"172.18.40.3", "172.18.40.4"}


def test_unused_first_then_used(cfg):
    order = scanner.candidates(cfg, USED, rng=random.Random(1))
    assert len(order) == 20 and set(order) == set(cfg.ips)
    assert set(order[-2:]) == USED
    assert not set(order[:18]) & USED


def test_sequential_within_groups(cfg):
    order = scanner.candidates(cfg, USED, order="sequential")
    assert order[0] == "172.18.40.1" and order[1] == "172.18.40.2" and order[2] == "172.18.40.5"
    assert order[-2:] == ["172.18.40.3", "172.18.40.4"]
    assert order[:3] == sorted(order[:3])


def test_random_is_seedable_and_shuffled(cfg):
    a = scanner.candidates(cfg, set(), rng=random.Random(7))
    b = scanner.candidates(cfg, set(), rng=random.Random(7))
    assert a == b and a != sorted(a, key=scanner._ip_key)


def test_prefer_unused_false_mixes(cfg):
    from dataclasses import replace

    cfg2 = replace(cfg, network=replace(cfg.network, prefer_unused=False))
    order = scanner.candidates(cfg2, USED, order="sequential")
    assert order == sorted(cfg2.ips, key=scanner._ip_key)


def test_best_history_orders_by_score_unknown_neutral(cfg):
    scores = {"172.18.40.9": 90.0, "172.18.40.8": 70.0, "172.18.40.2": 10.0}
    order = scanner.candidates(cfg, set(), order="best-history", scores=scores, rng=random.Random(3))
    assert order[:2] == ["172.18.40.9", "172.18.40.8"]
    assert order[-1] == "172.18.40.2"


def test_best_history_without_scores_is_random(cfg):
    order = scanner.candidates(cfg, set(), order="best-history", rng=random.Random(3))
    assert set(order) == set(cfg.ips)


# ---- smart ordering (phase 1)
def with_order(cfg, order="best-history", **kw):
    from dataclasses import replace

    return replace(cfg, hunt=replace(cfg.hunt, order=order, **kw))


def test_skipped_ips_go_last_shortest_cooldown_first(cfg):
    skip = {"172.18.40.3": 30.0, "172.18.40.4": 5.0}
    order = scanner.candidates(cfg, set(), order="sequential", skip=skip)
    assert order[-2:] == ["172.18.40.4", "172.18.40.3"] and len(order) == 20
    assert not set(order[:-2]) & set(skip)


def test_skip_works_with_every_order(cfg):
    for o in ("random", "sequential", "best-history"):
        order = scanner.candidates(cfg, set(), order=o, skip={"172.18.40.1": 9.0}, rng=random.Random(1))
        assert order[-1] == "172.18.40.1"


def test_busy_ips_rank_lower_in_best_history(cfg):
    busy = {"172.18.40.9": 1.0, "172.18.40.8": 0.5}
    order = scanner.candidates(with_order(cfg), set(), busy=busy, rng=random.Random(2))
    assert order[-1] == "172.18.40.9" and order[-2] == "172.18.40.8"


def test_busy_is_ignored_for_random_order(cfg):
    a = scanner.candidates(with_order(cfg, "random"), set(), busy={"172.18.40.9": 1.0}, rng=random.Random(5))
    b = scanner.candidates(with_order(cfg, "random"), set(), rng=random.Random(5))
    assert a == b


def test_untested_neighbors_of_good_ips_come_first(cfg):
    scores = {"172.18.40.10": 90.0}
    order = scanner.candidates(with_order(cfg), set(), scores=scores, rng=random.Random(3))
    assert order[0] == "172.18.40.10"  # the known-good IP itself
    near = set(order[1:7])
    assert {"172.18.40.7", "172.18.40.8", "172.18.40.9", "172.18.40.11", "172.18.40.12", "172.18.40.13"} == near


def test_near_good_bonus_can_be_disabled(cfg):
    scores = {"172.18.40.10": 90.0}
    order = scanner.candidates(with_order(cfg, explore_near_good=False), set(), scores=scores, rng=random.Random(3))
    assert order[0] == "172.18.40.10" and set(order[1:7]) != {"172.18.40.7", "172.18.40.8", "172.18.40.9", "172.18.40.11", "172.18.40.12", "172.18.40.13"}


def test_known_bad_ips_rank_below_untested(cfg):
    scores = {"172.18.40.5": 0.0}
    order = scanner.candidates(with_order(cfg), set(), scores=scores, rng=random.Random(4))
    assert order[-1] == "172.18.40.5"
