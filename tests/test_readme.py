"""The README must document every command, option and config key (so features never go undocumented)."""
import tomllib
from pathlib import Path

import typer.main

from dorm_ip import cli, wizard

ROOT = Path(__file__).resolve().parent.parent
README = (ROOT / "README.md").read_text()
SKIP = {"--help", "--install-completion", "--show-completion"}


def walk(group, prefix=""):
    for name, cmd in group.commands.items():
        path = f"{prefix}{name}"
        yield path, cmd
        if getattr(cmd, "commands", None):
            yield from walk(cmd, path + " ")


def all_commands():
    return list(walk(typer.main.get_command(cli.app)))


def test_every_command_is_documented():
    missing = []
    for path, cmd in all_commands():
        if getattr(cmd, "commands", None):
            continue  # a group is documented through its subcommands
        needle = path if " " in path else f"dorm-ip {path}"  # subcommands: "dns override"; top level: "dorm-ip hunt"
        if needle not in README:
            missing.append(path)
    assert not missing, f"commands missing from the README: {missing}"


def test_every_option_is_documented():
    root = typer.main.get_command(cli.app)
    missing = set()
    for cmd in [root, *(c for _p, c in all_commands())]:
        for param in cmd.params:
            for opt in [*param.opts, *getattr(param, "secondary_opts", [])]:
                if opt.startswith("--") and opt not in SKIP and f"`{opt}`" not in README and opt not in README:
                    missing.add(opt)
    assert not missing, f"options missing from the README: {sorted(missing)}"


def test_every_config_key_is_documented():
    values = wizard.example_values()
    missing = [f"[{sec}] {key}" for sec, keys in values.items() for key in keys if f"`{key}`" not in README]
    assert not missing, f"config keys missing from the README: {missing}"


def test_readme_mentions_the_current_version():
    from dorm_ip import __version__

    major_minor = ".".join(__version__.split(".")[:2])
    assert f"Version {major_minor}" in README


def test_version_is_consistent():
    from dorm_ip import __version__

    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert pyproject["project"]["version"] == __version__
    assert f"## [{__version__}]" in (ROOT / "CHANGELOG.md").read_text()


def test_ci_workflow_runs_the_tests_on_pull_requests():
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert "pull_request" in text and "uv run pytest" in text and "uv sync" in text


def test_makefile_documents_its_targets():
    make = (ROOT / "Makefile").read_text()
    for target in ("init", "edit-config", "edit-credentials", "arp-cap", "test"):
        assert f"make {target}" in README and f"{target}:" in make