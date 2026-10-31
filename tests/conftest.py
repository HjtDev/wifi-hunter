import pytest

from dorm_ip.config import load_config

CFG = """
[network]
prefix = 21
gateway = "172.18.47.254"
ranges = ["172.18.40.1-172.18.40.20"]
[dns]
default = ["172.18.32.1"]
override = ["8.8.8.8"]
[tests]
sustained_seconds = 1
sample_interval = 0.1
[thresholds]
max_ping_ms = 80
"""


@pytest.fixture
def cfg(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text(CFG)
    return load_config(p)