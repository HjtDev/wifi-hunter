import os
import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from dorm_ip import cli, shellint, wizard
from dorm_ip.shellint import BEGIN, END, ShellInfo

PROJECT = Path("/home/me/Projects/wifi hunter's repo")  # spaces and a quote on purpose


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "home"
    h.mkdir()
    for var in ("ZDOTDIR", "XDG_CONFIG_HOME"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HOME", str(h))
    monkeypatch.setenv("SHELL", "/usr/bin/zsh")
    monkeypatch.setattr(shellint.shutil, "which", lambda n: f"/usr/bin/{n}" if n in ("bash", "zsh", "fish", "uv") else None)
    return h


def test_rc_paths(home):
    assert shellint.rc_path("bash") == home / ".bashrc"
    assert shellint.rc_path("zsh") == home / ".zshrc"
    assert shellint.rc_path("fish") == home / ".config/fish/conf.d/dorm-ip.fish"
    assert shellint.rc_path("zsh", {"ZDOTDIR": "/z"}) == Path("/z/.zshrc")
    assert shellint.rc_path("fish", {"XDG_CONFIG_HOME": "/x"}) == Path("/x/fish/conf.d/dorm-ip.fish")
    with pytest.raises(shellint.ShellError):
        shellint.rc_path("tcsh")


def test_only_shells_you_use_are_detected(home):
    assert [s.name for s in shellint.detect_shells()] == ["zsh"]  # login shell only: no bash/fish config exists
    (home / ".bashrc").write_text("# mine\n")
    (home / ".config/fish").mkdir(parents=True)
    found = shellint.detect_shells()
    assert [s.name for s in found] == ["bash", "zsh", "fish"] and [s.current for s in found] == [False, True, False]


def test_missing_shell_binaries_are_skipped(home, monkeypatch):
    (home / ".bashrc").write_text("")
    monkeypatch.setattr(shellint.shutil, "which", lambda n: None)
    assert shellint.detect_shells() == []


def test_bash_block_is_a_function_with_a_safely_quoted_path():
    b = shellint.block("bash", PROJECT)
    assert b.startswith(BEGIN) and b.rstrip().endswith(END)
    assert 'dorm-ip() { uv run --quiet --project' in b and '"$@"' in b
    assert "'/home/me/Projects/wifi hunter'\"'\"'s repo'" in b  # shlex.quote of the awkward path


def test_fish_block_uses_a_fish_function_and_argv():
    b = shellint.block("fish", PROJECT)
    assert "function dorm-ip" in b and "$argv" in b and "end" in b and "\\'" in b


def test_install_appends_without_touching_the_rest_and_backs_up_once(home):
    rc = home / ".zshrc"
    rc.write_text("export A=1\nalias ll='ls -l'")  # no trailing newline
    sh = ShellInfo("zsh", rc, True, False)
    assert "added" in shellint.install(sh, PROJECT)
    text = rc.read_text()
    assert text.startswith("export A=1\nalias ll='ls -l'\n\n" + BEGIN) and text.count(BEGIN) == 1
    backup = home / ".zshrc.dorm-ip.bak"
    assert backup.read_text() == "export A=1\nalias ll='ls -l'"
    shellint.install(ShellInfo("zsh", rc, True, True), Path("/other/project"))  # a second install
    assert backup.read_text() == "export A=1\nalias ll='ls -l'"  # the first backup is kept


def test_install_is_idempotent_and_refreshes_the_block(home):
    rc = home / ".bashrc"
    rc.write_text("# top\n")
    sh = ShellInfo("bash", rc, False, False)
    shellint.install(sh, PROJECT)
    once = rc.read_text()
    assert "already up to date" in shellint.install(sh, PROJECT) and rc.read_text() == once
    assert "updated" in shellint.install(sh, Path("/new/place"))
    text = rc.read_text()
    assert text.count(BEGIN) == 1 and "/new/place" in text and "wifi hunter" not in text and text.startswith("# top\n")


def test_install_creates_missing_files_and_folders(home):
    sh = ShellInfo("fish", shellint.rc_path("fish"), False, False)
    shellint.install(sh, PROJECT)
    assert sh.rc_path.read_text().startswith(BEGIN)
    bash = ShellInfo("bash", home / ".bashrc", False, False)
    shellint.install(bash, PROJECT)
    assert (home / ".bashrc").read_text().startswith(BEGIN)  # nothing to back up for a new file
    assert not (home / ".bashrc.dorm-ip.bak").exists()


def test_uninstall_removes_only_our_block(home):
    rc = home / ".zshrc"
    rc.write_text("export A=1\n")
    sh = ShellInfo("zsh", rc, True, False)
    shellint.install(sh, PROJECT)
    rc.write_text(rc.read_text() + "export B=2\n")
    assert "removed" in shellint.uninstall(sh)
    assert rc.read_text() == "export A=1\nexport B=2\n"
    assert "nothing to remove" in shellint.uninstall(sh)


def test_uninstall_deletes_the_fish_file_and_handles_missing_files(home):
    sh = ShellInfo("fish", shellint.rc_path("fish"), False, False)
    assert "nothing to remove" in shellint.uninstall(sh)
    shellint.install(sh, PROJECT)
    assert "removed" in shellint.uninstall(sh) and not sh.rc_path.exists()


def test_select(home):
    assert [s.name for s in shellint.select("all")] == ["zsh"]
    assert [s.name for s in shellint.select("fish")] == ["fish"]
    with pytest.raises(shellint.ShellError, match="supported"):
        shellint.select("nu")


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_the_bash_function_really_runs_uv_in_the_project_from_any_folder(tmp_path):
    proj = tmp_path / "my project's dir"
    proj.mkdir()
    fakebin = tmp_path / "bin"
    fakebin.mkdir()
    uv = fakebin / "uv"
    uv.write_text('#!/bin/sh\nfor a in "$@"; do printf "[%s]\\n" "$a"; done\n')
    uv.chmod(0o755)
    rc = tmp_path / "rc"
    rc.write_text(shellint.block("bash", proj))
    elsewhere = tmp_path / "somewhere else"
    elsewhere.mkdir()
    out = subprocess.run(
        ["bash", "-c", f"source '{rc}'; cd '{elsewhere}'; dorm-ip hunt --find 3 'a b'"],
        capture_output=True, text=True, env={**os.environ, "PATH": f"{fakebin}:{os.environ['PATH']}"},
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.splitlines() == [
        "[run]", "[--quiet]", "[--project]", f"[{proj}]", "[dorm-ip]", "[hunt]", "[--find]", "[3]", "[a b]"
    ]  # the path with a space and a quote, and the argument with a space, arrive intact
    assert subprocess.run(["bash", "-n", str(rc)]).returncode == 0  # valid syntax


# ---- the init step and the commands
class Said(wizard.Prompter):
    def __init__(self, answers=()):
        self.answers, self.said, self.asked = list(answers), [], []

    def say(self, text): self.said.append(text)

    def confirm(self, text, default=True):
        self.asked.append(text)
        return self.answers.pop(0) if self.answers else default


def test_wizard_step_asks_per_shell_and_installs_only_the_accepted(home, monkeypatch, tmp_path):
    monkeypatch.setattr(shellint, "project_dir", lambda: tmp_path)
    (home / ".bashrc").write_text("")
    p = Said([False, True])  # no for bash, yes for zsh
    lines = shellint.wizard_step(p)
    assert len(lines) == 1 and "zsh" in lines[0]
    assert BEGIN not in (home / ".bashrc").read_text() and BEGIN in (home / ".zshrc").read_text()
    assert any(".bashrc" in q for q in p.asked) and any(".zshrc" in q for q in p.asked)


def test_wizard_step_when_installed_as_a_package(home, monkeypatch):
    monkeypatch.setattr(shellint, "project_dir", lambda: None)
    p = Said()
    assert shellint.wizard_step(p) == [] and any("already a normal command" in s for s in p.said)
    assert not (home / ".zshrc").exists()


def test_wizard_step_with_no_known_shell(home, monkeypatch, tmp_path):
    monkeypatch.setattr(shellint, "project_dir", lambda: tmp_path)
    monkeypatch.setattr(shellint.shutil, "which", lambda n: None)
    assert shellint.wizard_step(Said()) == []


def test_run_init_calls_the_shell_step_only_when_given(tmp_path):
    target = tmp_path / "c" / "config.toml"
    called = []
    res = wizard.run_init(wizard.AutoPrompter(lambda m: None), target=target, detect=lambda: None,
                          shell_step=lambda p: called.append(1) or ["zsh: added"])
    assert called == [1] and res.shell_lines == ["zsh: added"]
    target2 = tmp_path / "d" / "config.toml"
    assert wizard.run_init(wizard.AutoPrompter(lambda m: None), target=target2, detect=lambda: None).shell_lines == []


@pytest.fixture
def invoke(tmp_path, home, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setattr(shellint, "project_dir", lambda: tmp_path)
    monkeypatch.chdir(tmp_path)
    return lambda *a, input=None: CliRunner().invoke(cli.app, list(a), input=input)


def test_cli_shell_install_status_uninstall(invoke, home):
    (home / ".zshrc").write_text("export A=1\n")
    r = invoke("shell", "install", "--shell", "zsh")
    assert r.exit_code == 0 and "added" in r.output and BEGIN in (home / ".zshrc").read_text()
    assert "zsh: installed" in invoke("shell", "status").output
    r = invoke("shell", "uninstall")
    assert "removed" in r.output and (home / ".zshrc").read_text() == "export A=1\n"
    assert "zsh: not installed" in invoke("shell", "status").output


def test_cli_shell_install_rejects_unknown_shells(invoke):
    r = invoke("shell", "install", "--shell", "nushell")
    assert r.exit_code == 1 and "unsupported shell" in str(r.exception)


def test_init_yes_never_touches_dotfiles_and_no_shell_skips_the_question(invoke, home):
    assert invoke("init", "--yes").exit_code == 0
    assert not (home / ".zshrc").exists()
    r = invoke("init", "--no-shell", input="\n" * 40)
    assert r.exit_code == 0 and not (home / ".zshrc").exists()


def test_init_asks_and_installs_when_you_say_yes(invoke, home):
    # 10 questions answered with Enter, "n" to portal auto-login, 2 more Enters (watchdog), Enter = yes to the shell step
    r = invoke("init", input="\n" * 10 + "n\n" + "\n" * 3)
    assert r.exit_code == 0, r.output + str(r.exception)
    assert BEGIN in (home / ".zshrc").read_text()
    flat = " ".join(r.output.split())
    assert "zsh: added the dorm-ip command" in flat and "Open a new terminal" in flat


def test_version_flag(invoke):
    r = invoke("--version")
    assert r.exit_code == 0 and r.output.strip() == f"dorm-ip {cli.__version__}"


def test_init_does_not_depend_on_the_developers_login_shell(tmp_path, monkeypatch):
    """Regression: with $SHELL=bash and a ~/.bashrc, `init` asks the shell question; scripted input must cover it."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("SHELL", "/bin/bash")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setattr(shellint.shutil, "which", lambda n: f"/usr/bin/{n}" if n in ("bash", "uv") else None)
    monkeypatch.setattr(shellint, "project_dir", lambda: tmp_path)
    (tmp_path / ".bashrc").write_text("export A=1\n")
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    # no answer left for the shell question: nothing may be written (and it must not crash the setup silently)
    answers = "\n".join([""] * 10 + ["n", "", ""]) + "\n"
    r = runner.invoke(cli.app, ["init"], input=answers)
    assert (tmp_path / ".bashrc").read_text() == "export A=1\n"
    assert "Add the dorm-ip command in" in " ".join(r.output.split())
    assert (tmp_path / "cfg" / "dorm-ip" / "config.toml").exists()  # the config is written before the shell question
    # and with --no-shell it never asks (fresh config folder, so no "Update it?" question shifts the answers)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg2"))
    r2 = runner.invoke(cli.app, ["init", "--no-shell"], input=answers)
    assert r2.exit_code == 0, r2.output + str(r2.exception)
    assert "Add the dorm-ip command" not in r2.output
    assert (tmp_path / ".bashrc").read_text() == "export A=1\n"
