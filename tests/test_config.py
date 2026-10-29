import pytest

from dorm_ip.config import ConfigError, load_config, parse_range, with_overrides

BASE = """
[network]
prefix = 21
gateway = "172.18.47.254"
ranges = ["172.18.40.1-172.18.40.255", "172.18.41.1-172.18.41.255"]
exclude = ["172.18.47.254", "172.18.40.10"]
[dns]
default = ["172.18.32.1"]
"""


def write(tmp_path, text):
    p = tmp_path / "config.toml"
    p.write_text(text)
    return p


def test_range_expansion_and_exclude(tmp_path):
    cfg = load_config(write(tmp_path, BASE))
    assert len(cfg.ips) == 510 - 1  # 2*255 minus the excluded .10
    assert cfg.ips[0] == "172.18.40.1"
    assert "172.18.40.10" not in cfg.ips
    assert cfg.warnings == []


def test_parse_range_single_and_errors():
    assert [str(i) for i in parse_range("10.0.0.5")] == ["10.0.0.5"]
    assert len(parse_range("10.0.0.1-10.0.0.3")) == 3
    with pytest.raises(ConfigError):
        parse_range("10.0.0.9-10.0.0.1")
    with pytest.raises(ConfigError):
        parse_range("nope")


def test_out_of_subnet_warns(tmp_path):
    cfg = load_config(write(tmp_path, BASE.replace("prefix = 21", "prefix = 24")))
    assert any("outside" in w for w in cfg.warnings)


def test_broadcast_dropped_with_23(tmp_path):
    text = BASE.replace("prefix = 21", "prefix = 23").replace(
        'ranges = ["172.18.40.1-172.18.40.255", "172.18.41.1-172.18.41.255"]',
        'ranges = ["172.18.40.0-172.18.41.255"]',
    ).replace("172.18.47.254", "172.18.41.254")
    cfg = load_config(write(tmp_path, text))
    assert "172.18.40.0" not in cfg.ips and "172.18.41.255" not in cfg.ips
    assert any("broadcast" in w for w in cfg.warnings)


def test_missing_network_values_are_errors_not_defaults(tmp_path):
    with pytest.raises(ConfigError, match="network.gateway"):
        load_config(write(tmp_path, '[network]\nprefix=21\nranges=["1.1.1.1"]\n[dns]\ndefault=["1.1.1.1"]'))


def test_unknown_key_and_bad_type(tmp_path):
    with pytest.raises(ConfigError, match="unknown key"):
        load_config(write(tmp_path, BASE + "\n[hunt]\nbogus = 1\n"))
    with pytest.raises(ConfigError, match="wrong type"):
        load_config(write(tmp_path, BASE.replace("prefix = 21", 'prefix = "21"')))


def test_bad_enum(tmp_path):
    with pytest.raises(ConfigError, match="final_mode"):
        load_config(write(tmp_path, BASE.replace('default = ["172.18.32.1"]', 'default = ["172.18.32.1"]\nfinal_mode = "x"')))


def test_overrides_recompute(tmp_path):
    cfg = load_config(write(tmp_path, BASE))
    c2 = with_overrides(cfg, ranges=["172.18.40.1-172.18.40.3"])
    assert c2.ips == ["172.18.40.1", "172.18.40.2", "172.18.40.3"]
    assert len(cfg.ips) > 3  # original untouched