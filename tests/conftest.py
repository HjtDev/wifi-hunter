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


@pytest.fixture(autouse=True)
def isolated_environment(tmp_path_factory, monkeypatch):
    """No test may depend on, or write to, the developer's real home, shell or XDG folders.

    (A test once passed on a machine without $SHELL and failed on one with it: `init` found the login
    shell and asked a question.) Tests that need a particular shell or home set their own after this."""
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("HOME", str(home))
    for var in ("SHELL", "ZDOTDIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "VISUAL", "EDITOR"):
        monkeypatch.delenv(var, raising=False)
