"""Shell integration: a `dorm-ip` command that works from any directory (bash, zsh, fish).

The command is a tiny function that runs the project's own environment:
`uv run --project <repo> dorm-ip "$@"`. It lives in a marker-delimited block, so it can be updated
and removed cleanly and nothing else in your shell config is touched.
"""

from __future__ import annotations

import os
import shlex
import shutil
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

BEGIN = "# >>> dorm-ip >>>"
END = "# <<< dorm-ip <<<"
SHELLS = ("bash", "zsh", "fish")
HEADER = "# Added by `dorm-ip init`. Remove with `dorm-ip shell uninstall`."


class ShellError(Exception):
    pass


@dataclass
class ShellInfo:
    name: str
    rc_path: Path
    current: bool  # it is your login shell ($SHELL)
    installed: bool  # the dorm-ip block is already there


def project_dir() -> Path | None:
    """The repository this code runs from, or None when installed as a package (then `dorm-ip` is
    already a normal command and no function is needed)."""
    root = Path(__file__).resolve().parent.parent
    return root if (root / "pyproject.toml").is_file() else None


def rc_path(name: str, env: Mapping[str, str] | None = None, home: Path | None = None) -> Path:
    env = os.environ if env is None else env
    home = home or Path.home()
    if name == "bash":
        return home / ".bashrc"
    if name == "zsh":
        return Path(env.get("ZDOTDIR") or home) / ".zshrc"
    if name == "fish":
        return Path(env.get("XDG_CONFIG_HOME") or home / ".config") / "fish" / "conf.d" / "dorm-ip.fish"
    raise ShellError(f"unsupported shell: {name} (supported: {', '.join(SHELLS)})")


def fish_quote(s: str) -> str:
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"


def block(name: str, project: Path) -> str:
    if name == "fish":
        return (
            f"{BEGIN}\n{HEADER}\nfunction dorm-ip --description 'Find and keep a fast dorm wifi IP'\n"
            f"    uv run --quiet --project {fish_quote(str(project))} dorm-ip $argv\nend\n{END}\n"
        )
    return (
        f"{BEGIN}\n{HEADER}\n"
        f'dorm-ip() {{ uv run --quiet --project {shlex.quote(str(project))} dorm-ip "$@"; }}\n{END}\n'
    )


def _has_block(text: str) -> bool:
    return BEGIN in text and END in text and text.index(BEGIN) < text.index(END)


def detect_shells(
    env: Mapping[str, str] | None = None,
    home: Path | None = None,
    which: Callable[[str], str | None] | None = None,
) -> list[ShellInfo]:
    """Shells that are installed and actually used: your login shell, or one with a config in place."""
    env = os.environ if env is None else env
    which = which or shutil.which
    current = Path(env.get("SHELL", "")).name
    found = []
    for name in SHELLS:
        if which(name) is None:
            continue
        path = rc_path(name, env, home)
        used = name == current or path.exists() or (name == "fish" and path.parent.parent.is_dir())
        if not used:
            continue
        installed = path.exists() and _has_block(path.read_text(errors="replace"))
        found.append(ShellInfo(name, path, name == current, installed))
    return found


def install(shell: ShellInfo, project: Path) -> str:
    """Add (or refresh) the block. Backs the file up once. Returns a one-line summary."""
    path = shell.rc_path
    new = block(shell.name, project)
    old = path.read_text(errors="replace") if path.exists() else ""
    if shell.name == "fish":
        text = new  # the whole file belongs to us
    elif _has_block(old):
        a, b = old.index(BEGIN), old.index(END) + len(END)
        text = old[:a] + new.rstrip("\n") + old[b:]
    else:
        text = old + ("" if not old or old.endswith("\n") else "\n") + ("\n" if old else "") + new
    if text == old:
        return f"{shell.name}: already up to date ({path})"
    path.parent.mkdir(parents=True, exist_ok=True)
    backup = path.with_name(path.name + ".dorm-ip.bak")
    if old and not backup.exists():
        shutil.copy2(path, backup)
    path.write_text(text)
    return f"{shell.name}: {'updated' if _has_block(old) else 'added'} the dorm-ip command in {path}"


def uninstall(shell: ShellInfo) -> str:
    path = shell.rc_path
    if not path.exists():
        return f"{shell.name}: nothing to remove"
    old = path.read_text(errors="replace")
    if not _has_block(old):
        return f"{shell.name}: nothing to remove"
    a, b = old.index(BEGIN), old.index(END) + len(END)
    rest = (old[:a].rstrip("\n") + "\n" + old[b:].lstrip("\n")).strip("\n")
    if shell.name == "fish" and not rest.strip():
        path.unlink()
        return f"fish: removed {path}"
    path.write_text(rest + "\n" if rest else "")
    return f"{shell.name}: removed the dorm-ip block from {path}"


def select(
    which_shell: str, env: Mapping[str, str] | None = None, home: Path | None = None,
    which: Callable[[str], str | None] | None = None,
) -> list[ShellInfo]:
    """`--shell` value -> shells to act on ('all' = every detected shell)."""
    if which_shell == "all":
        return detect_shells(env, home, which)
    if which_shell not in SHELLS:
        raise ShellError(f"unsupported shell: {which_shell} (supported: {', '.join(SHELLS)}, all)")
    path = rc_path(which_shell, env, home)
    current = Path((os.environ if env is None else env).get("SHELL", "")).name == which_shell
    return [ShellInfo(which_shell, path, current, path.exists() and _has_block(path.read_text(errors="replace")))]


def wizard_step(p, *, env=None, home: Path | None = None, which=None) -> list[str]:
    """The `dorm-ip init` question: add the command to each shell you use. Returns result lines."""
    proj = project_dir()
    if proj is None:
        p.say("\n== Shell command ==\n`dorm-ip` is installed as a package: it is already a normal command.")
        return []
    shells = detect_shells(env, home, which)
    p.say("\n== Shell command ==")
    if not shells:
        p.say("No bash, zsh or fish setup found; skipping. (`dorm-ip shell install --shell bash` does it by hand.)")
        return []
    p.say(
        "To run `dorm-ip` from any folder I can add a small command to your shell config "
        "(it runs this project's environment). Found: " + ", ".join(f"{s.name} ({s.rc_path})" for s in shells)
    )
    lines = []
    for sh in shells:
        verb = "Update" if sh.installed else "Add"
        if p.confirm(f"{verb} the dorm-ip command in {sh.rc_path}?", True):
            lines.append(install(sh, proj))
    return lines