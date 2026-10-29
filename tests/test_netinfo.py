import pytest

from dorm_ip import netinfo
from dorm_ip.config import load_config
from dorm_ip.models import NetProfile

ACTIVE = "Dorm\\:5G:802-11-wireless:wlan0\nlo:loopback:lo\nWired:802-3-ethernet:enp3s0\n"
LIVE = (
    "IP4.ADDRESS[1]:172.18.40.77/21\n"
    "IP4.GATEWAY:172.18.47.254\n"
    "IP4.DNS[1]:172.18.32.1\n"
    "IP4.DNS[2]:8.8.8.8\n"
)
SAVED_DHCP = (
    "ipv4.method:auto\nipv4.addresses:\nipv4.gateway:--\nipv4.dns:\nipv4.ignore-auto-dns:no\n"
)
SAVED_STATIC = (
    "ipv4.method:manual\nipv4.addresses:172.18.40.9/21\nipv4.gateway:172.18.47.254\n"
    "ipv4.dns:1.1.1.1,8.8.8.8\nipv4.ignore-auto-dns:yes\n"
)


def test_split_terse_unescapes():
    assert netinfo.split_terse("Dorm\\:5G:wifi:wlan0") == ["Dorm:5G", "wifi", "wlan0"]


def test_parse_active_and_wifi_filter(monkeypatch):
    monkeypatch.setattr(netinfo, "nmcli", lambda *a: ACTIVE)
    assert netinfo.active_wifi() == [("Dorm:5G", "wlan0")]


def test_new_nmcli_type_name(monkeypatch):
    monkeypatch.setattr(netinfo, "nmcli", lambda *a: "Home:wifi:wlp2s0\n")
    assert netinfo.active_wifi() == [("Home", "wlp2s0")]


def test_parse_live():
    ip, prefix, gw, dns = netinfo.parse_live(LIVE)
    assert (ip, prefix, gw, dns) == ("172.18.40.77", 21, "172.18.47.254", ["172.18.32.1", "8.8.8.8"])


def test_parse_live_disconnected():
    assert netinfo.parse_live("") == (None, None, None, [])


def test_parse_kv_dashes_become_empty():
    assert netinfo.parse_kv(SAVED_DHCP)["ipv4.gateway"] == ""


def test_resolve_falls_back_to_single_wifi(monkeypatch):
    monkeypatch.setattr(netinfo, "nmcli", lambda *a: "Home:wifi:wlp2s0\n")
    conn, dev, notes = netinfo.resolve_connection("wlan0", "")
    assert (conn, dev) == ("Home", "wlp2s0") and notes


def test_resolve_errors(monkeypatch):
    monkeypatch.setattr(netinfo, "nmcli", lambda *a: "lo:loopback:lo\n")
    with pytest.raises(netinfo.NetError, match="no active wifi"):
        netinfo.resolve_connection("", "")
    monkeypatch.setattr(netinfo, "nmcli", lambda *a: "A:wifi:wlan0\nB:wifi:wlan1\n")
    with pytest.raises(netinfo.NetError, match="several"):
        netinfo.resolve_connection("", "")


def test_get_profile(monkeypatch):
    def fake(*a):
        if "--active" in a:
            return ACTIVE
        if a[-3:-1] == ("con", "show"):
            return SAVED_DHCP
        return LIVE

    monkeypatch.setattr(netinfo, "nmcli", fake)
    monkeypatch.setattr(netinfo, "read_mac", lambda d: "aa:bb:cc:dd:ee:ff")
    p = netinfo.get_profile("wlan0", "")
    assert p.connection == "Dorm:5G" and p.method == "auto"
    assert (p.ip, p.prefix, p.gateway) == ("172.18.40.77", 21, "172.18.47.254")


def _cfg(tmp_path):
    f = tmp_path / "c.toml"
    f.write_text('[network]\nprefix=21\ngateway="172.18.47.254"\nranges=["172.18.40.1"]\n[dns]\ndefault=["172.18.32.1"]')
    return load_config(f)


def test_prefix_mismatch_warning(tmp_path):
    p = NetProfile("wlan0", "Dorm", "auto", "172.18.40.77", 23, "172.18.47.254", [], "m")
    w = netinfo.check_profile(p, _cfg(tmp_path))
    assert len(w) == 1 and "/23" in w[0] and "outside" in w[0] and "DHCP lease" in w[0]


def test_no_warning_when_matching(tmp_path):
    p = NetProfile("wlan0", "Dorm", "auto", "172.18.40.77", 21, "172.18.47.254", [], "m")
    assert netinfo.check_profile(p, _cfg(tmp_path)) == []