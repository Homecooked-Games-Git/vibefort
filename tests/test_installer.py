"""Tests for vibefort.installer module."""

from pathlib import Path
from unittest.mock import patch, MagicMock

import vibefort.constants as constants
from vibefort.installer import (
    install_shell_hook,
    uninstall_shell_hook,
    install_git_hook,
    uninstall_git_hook,
)


def test_install_shell_hook_zsh(tmp_vibefort_home, tmp_path):
    """All package managers should appear in the hook block."""
    rc = tmp_path / ".zshrc"
    install_shell_hook(rc_path=rc)
    content = rc.read_text()

    # Markers present
    assert constants.SHELL_HOOK_START in content
    assert constants.SHELL_HOOK_END in content

    # Every manager wrapper is present
    for name in ["pip", "pip3", "uv", "pipx", "npm", "npx", "yarn", "pnpm", "bun", "bunx"]:
        assert f"{name}()" in content, f"missing wrapper for {name}"
        assert f"command {name}" in content

    # Intercept commands
    assert 'vibefort intercept pip "$@"' in content
    assert 'vibefort intercept uv "$@"' in content
    assert 'vibefort intercept npm "$@"' in content
    assert 'vibefort intercept bun "$@"' in content
    assert 'vibefort intercept bunx "$@"' in content

    # Prompt indicator for zsh
    assert "PROMPT=" in content
    assert "PS1=" in content
    assert constants.FORT_ICON in content


def test_install_shell_hook_idempotent(tmp_vibefort_home, tmp_path):
    """Installing twice should produce only one hook block."""
    rc = tmp_path / ".zshrc"
    install_shell_hook(rc_path=rc)
    install_shell_hook(rc_path=rc)
    content = rc.read_text()

    assert content.count(constants.SHELL_HOOK_START) == 1
    assert content.count(constants.SHELL_HOOK_END) == 1


def test_uninstall_shell_hook(tmp_vibefort_home, tmp_path):
    """Uninstalling should remove the hook block cleanly."""
    rc = tmp_path / ".zshrc"
    rc.write_text("# existing config\nexport FOO=bar\n")
    install_shell_hook(rc_path=rc)

    # Verify it was added
    assert constants.SHELL_HOOK_START in rc.read_text()

    uninstall_shell_hook(rc_path=rc)
    content = rc.read_text()

    assert constants.SHELL_HOOK_START not in content
    assert constants.SHELL_HOOK_END not in content
    assert "export FOO=bar" in content


@patch("vibefort.installer.subprocess.run")
def test_install_git_hook(mock_run, tmp_vibefort_home):
    """Hook file should exist, be executable, and contain scan-secrets."""
    mock_run.return_value = MagicMock(returncode=0)

    hook_path = install_git_hook()

    assert hook_path.exists()
    assert hook_path.stat().st_mode & 0o100  # executable
    content = hook_path.read_text()
    assert "vibefort scan-secrets" in content
    assert content.startswith("#!/usr/bin/env bash")

    # Verify git config was called
    mock_run.assert_called_once_with(
        ["git", "config", "--global", "core.hooksPath", str(constants.HOOKS_DIR)],
        check=True,
    )


@patch("vibefort.installer.subprocess.run")
def test_uninstall_git_hook(mock_run, tmp_vibefort_home):
    """Uninstalling should remove the hook file."""
    # First install the hook
    mock_run.return_value = MagicMock(returncode=0)
    hook_path = install_git_hook()
    assert hook_path.exists()

    # Mock git config --get to return our hooks dir
    def side_effect(cmd, **kwargs):
        result = MagicMock()
        if "--get" in cmd:
            result.returncode = 0
            result.stdout = str(constants.HOOKS_DIR) + "\n"
        else:
            result.returncode = 0
        return result

    mock_run.reset_mock()
    mock_run.side_effect = side_effect

    uninstall_git_hook()

    assert not hook_path.exists()
    # Should have called --get and then --unset
    assert mock_run.call_count == 2
