"""Install and uninstall VibeFort shell hooks and git hooks."""

import os
import stat
import subprocess
from pathlib import Path

import vibefort.constants as constants

_PACKAGE_MANAGERS = [
    # Python
    ("pip", "pip"),
    ("pip3", "pip"),
    ("uv", "uv"),
    ("pipx", "pipx"),
    ("poetry", "poetry"),
    ("pdm", "pdm"),
    # Node.js
    ("npm", "npm"),
    ("npx", "npx"),
    ("yarn", "yarn"),
    ("pnpm", "pnpm"),
    ("bun", "bun"),
    ("bunx", "bunx"),
]


def _build_wrapper(func_name: str, manager: str) -> str:
    """Build a single shell wrapper function."""
    return (
        f"{func_name}() {{\n"
        f"    if command -v vibefort &>/dev/null; then\n"
        f'        vibefort intercept {manager} "$@"\n'
        f"    else\n"
        f'        command {func_name} "$@"\n'
        f"    fi\n"
        f"}}"
    )


def _build_hook_block() -> str:
    """Build the full shell hook block including wrappers and prompt indicator."""
    lines = [constants.SHELL_HOOK_START]

    # Package manager wrappers
    for func_name, manager in _PACKAGE_MANAGERS:
        lines.append(_build_wrapper(func_name, manager))

    # Terminal title + right prompt status
    # Uses cached files to avoid spawning Python on every prompt
    lines.append("")
    lines.append("# VibeFort terminal title and status")
    lines.append('if [ -f "$HOME/.vibefort/active" ]; then')
    lines.append('    # Refresh cached banner files (runs in background, fast)')
    lines.append('    _vibefort_refresh() {')
    lines.append('        local cfg="$HOME/.vibefort/config.toml"')
    lines.append('        local cache="$HOME/.vibefort/cache/banner_short.txt"')
    lines.append('        # Only regenerate if config is newer than cache')
    lines.append('        if [ ! -f "$cache" ] || [ "$cfg" -nt "$cache" ]; then')
    lines.append('            command -v vibefort &>/dev/null && {')
    lines.append('                vibefort banner --short 2>/dev/null > "$HOME/.vibefort/cache/banner_short.txt"')
    lines.append('                vibefort banner --title 2>/dev/null > "$HOME/.vibefort/cache/banner_title.txt"')
    lines.append('            }')
    lines.append('        fi')
    lines.append('    }')
    lines.append('    # Initial refresh')
    lines.append('    mkdir -p "$HOME/.vibefort/cache"')
    lines.append('    _vibefort_refresh')
    lines.append('    if [ -n "$ZSH_VERSION" ]; then')
    lines.append('        # Right prompt reads from cache (instant)')
    lines.append('        _vibefort_rprompt() {')
    lines.append('            [ -f "$HOME/.vibefort/cache/banner_short.txt" ] && RPROMPT="$(cat "$HOME/.vibefort/cache/banner_short.txt")"')
    lines.append('        }')
    lines.append('        # Title bar reads from cache')
    lines.append('        _vibefort_title() {')
    lines.append('            [ -f "$HOME/.vibefort/cache/banner_title.txt" ] && printf "\\033]0;%s\\007" "$(cat "$HOME/.vibefort/cache/banner_title.txt")"')
    lines.append('        }')
    lines.append('        autoload -Uz add-zsh-hook')
    lines.append('        add-zsh-hook precmd _vibefort_rprompt')
    lines.append('        add-zsh-hook precmd _vibefort_title')
    lines.append('    else')
    lines.append(f'        PS1="{constants.FORT_ICON} $PS1"')
    lines.append('        _vibefort_title() {')
    lines.append('            [ -f "$HOME/.vibefort/cache/banner_title.txt" ] && printf "\\033]0;%s\\007" "$(cat "$HOME/.vibefort/cache/banner_title.txt")"')
    lines.append('        }')
    lines.append('        PROMPT_COMMAND="_vibefort_title; $PROMPT_COMMAND"')
    lines.append("    fi")
    lines.append("fi")

    lines.append(constants.SHELL_HOOK_END)
    return "\n".join(lines) + "\n"


def get_shell_rc_path() -> Path:
    """Detect the current shell and return the appropriate RC file path."""
    shell = os.environ.get("SHELL", "")
    if "zsh" in shell:
        return Path.home() / ".zshrc"
    return Path.home() / ".bashrc"


def _remove_hook_block(content: str) -> str:
    """Remove the vibefort hook block from file content."""
    lines = content.splitlines(keepends=True)
    result: list[str] = []
    inside_block = False
    for line in lines:
        if line.rstrip() == constants.SHELL_HOOK_START:
            inside_block = True
            continue
        if line.rstrip() == constants.SHELL_HOOK_END:
            inside_block = False
            continue
        if not inside_block:
            result.append(line)
    return "".join(result)


def install_shell_hook(*, rc_path: Path | None = None) -> Path:
    """Add the vibefort hook block to the shell RC file (idempotent).

    Returns the path that was written to.
    """
    if rc_path is None:
        rc_path = get_shell_rc_path()

    rc_path = Path(rc_path)

    existing = ""
    if rc_path.exists():
        existing = rc_path.read_text()

    # Remove any existing block first (idempotent)
    cleaned = _remove_hook_block(existing)

    # Ensure trailing newline before appending
    if cleaned and not cleaned.endswith("\n"):
        cleaned += "\n"

    cleaned += _build_hook_block()
    rc_path.write_text(cleaned)

    # Create the active marker file
    constants.VIBEFORT_HOME.mkdir(parents=True, exist_ok=True)
    (constants.VIBEFORT_HOME / "active").touch()

    return rc_path


def uninstall_shell_hook(*, rc_path: Path | None = None) -> Path:
    """Remove the vibefort hook block from the shell RC file.

    Returns the path that was modified.
    """
    if rc_path is None:
        rc_path = get_shell_rc_path()

    rc_path = Path(rc_path)

    if not rc_path.exists():
        return rc_path

    content = rc_path.read_text()
    cleaned = _remove_hook_block(content)
    rc_path.write_text(cleaned)

    # Remove active marker
    active_file = constants.VIBEFORT_HOME / "active"
    if active_file.exists():
        active_file.unlink()

    return rc_path


_GIT_HOOK_SCRIPT = """\
#!/usr/bin/env bash
# Installed by vibefort
vibefort scan-secrets
exit $?
"""


def install_git_hook() -> Path:
    """Write the pre-commit hook and set global core.hooksPath.

    Returns the path to the hook file.
    """
    hooks_dir = constants.HOOKS_DIR
    hooks_dir.mkdir(parents=True, exist_ok=True)

    hook_path = hooks_dir / "pre-commit"
    hook_path.write_text(_GIT_HOOK_SCRIPT)
    hook_path.chmod(hook_path.stat().st_mode | stat.S_IEXEC)

    subprocess.run(
        ["git", "config", "--global", "core.hooksPath", str(hooks_dir)],
        check=True,
    )
    return hook_path


def uninstall_git_hook() -> None:
    """Remove the pre-commit hook and unset core.hooksPath if it points to ours."""
    hook_path = constants.HOOKS_DIR / "pre-commit"
    if hook_path.exists():
        hook_path.unlink()

    # Unset global core.hooksPath only if it points to our hooks dir
    result = subprocess.run(
        ["git", "config", "--global", "--get", "core.hooksPath"],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        configured = result.stdout.strip()
        if configured == str(constants.HOOKS_DIR):
            subprocess.run(
                ["git", "config", "--global", "--unset", "core.hooksPath"],
                check=True,
            )
