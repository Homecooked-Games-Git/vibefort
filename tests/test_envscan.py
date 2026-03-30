"""Tests for .env file watchdog module."""

import os
import stat

import pytest

from vibefort.envscan import EnvFinding, check_env_files, _parse_env_values


# --- Helper: _parse_env_values ---

def test_parse_env_values_basic():
    content = "KEY=value\nSECRET=abc123\n"
    result = _parse_env_values(content)
    assert result == {"KEY": "value", "SECRET": "abc123"}


def test_parse_env_values_skips_comments_and_blanks():
    content = "# comment\n\nKEY=value\n  \n# another\nFOO=bar\n"
    result = _parse_env_values(content)
    assert result == {"KEY": "value", "FOO": "bar"}


def test_parse_env_values_empty_value():
    content = "KEY=\n"
    result = _parse_env_values(content)
    assert result == {"KEY": ""}


def test_parse_env_values_value_with_equals():
    content = "KEY=val=ue\n"
    result = _parse_env_values(content)
    assert result == {"KEY": "val=ue"}


def test_parse_env_values_quoted():
    content = 'KEY="hello world"\nFOO=\'bar baz\'\n'
    result = _parse_env_values(content)
    assert result == {"KEY": "hello world", "FOO": "bar baz"}


# --- No .env file ---

def test_no_env_file_no_findings(tmp_path):
    findings = check_env_files(str(tmp_path))
    assert findings == []


# --- env-not-gitignored ---

def test_env_not_in_gitignore_detected(tmp_path):
    (tmp_path / ".env").write_text("SECRET=abc\n")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".gitignore").write_text("*.log\n")
    findings = check_env_files(str(tmp_path))
    assert any(f.rule == "env-not-gitignored" and f.severity == "critical" for f in findings)


def test_env_in_gitignore_ok(tmp_path):
    (tmp_path / ".env").write_text("SECRET=abc\n")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".gitignore").write_text(".env\n")
    findings = check_env_files(str(tmp_path))
    assert not any(f.rule == "env-not-gitignored" for f in findings)


def test_env_in_gitignore_wildcard_star_env(tmp_path):
    (tmp_path / ".env").write_text("SECRET=abc\n")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".gitignore").write_text("*.env\n")
    findings = check_env_files(str(tmp_path))
    assert not any(f.rule == "env-not-gitignored" for f in findings)


def test_env_in_gitignore_wildcard_dot_env_star(tmp_path):
    (tmp_path / ".env").write_text("SECRET=abc\n")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".gitignore").write_text(".env*\n")
    findings = check_env_files(str(tmp_path))
    assert not any(f.rule == "env-not-gitignored" for f in findings)


def test_env_in_gitignore_wildcard_dot_env_dot_star(tmp_path):
    (tmp_path / ".env").write_text("SECRET=abc\n")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".gitignore").write_text(".env.*\n")
    findings = check_env_files(str(tmp_path))
    assert not any(f.rule == "env-not-gitignored" for f in findings)


def test_no_gitignore_file_detected(tmp_path):
    (tmp_path / ".env").write_text("SECRET=abc\n")
    (tmp_path / ".git").mkdir()
    findings = check_env_files(str(tmp_path))
    assert any(f.rule == "env-not-gitignored" and f.severity == "critical" for f in findings)


def test_env_exists_but_no_git_dir_no_gitignore_check(tmp_path):
    """If not a git repo, skip gitignore check."""
    (tmp_path / ".env").write_text("SECRET=abc\n")
    findings = check_env_files(str(tmp_path))
    assert not any(f.rule == "env-not-gitignored" for f in findings)


# --- env-world-readable ---

def test_env_world_readable_detected(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("SECRET=abc\n")
    os.chmod(str(env_file), 0o644)  # others can read
    findings = check_env_files(str(tmp_path))
    assert any(f.rule == "env-world-readable" and f.severity == "high" for f in findings)


def test_env_restricted_permissions_ok(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("SECRET=abc\n")
    os.chmod(str(env_file), 0o600)  # owner only
    findings = check_env_files(str(tmp_path))
    assert not any(f.rule == "env-world-readable" for f in findings)


# --- env-example-has-secrets ---

def test_env_example_with_real_secrets_detected(tmp_path):
    (tmp_path / ".env").write_text("API_KEY=sk-1234567890abcdef\n")
    (tmp_path / ".env.example").write_text("API_KEY=sk-1234567890abcdef\n")
    findings = check_env_files(str(tmp_path))
    assert any(f.rule == "env-example-has-secrets" and f.severity == "critical" for f in findings)


def test_env_example_with_ghp_token_detected(tmp_path):
    token = "ghp_" + "abc123def456ghi789"  # noqa: S105
    (tmp_path / ".env").write_text(f"GH_TOKEN={token}\n")
    (tmp_path / ".env.example").write_text(f"GH_TOKEN={token}\n")
    findings = check_env_files(str(tmp_path))
    assert any(f.rule == "env-example-has-secrets" for f in findings)


def test_env_example_with_akia_detected(tmp_path):
    (tmp_path / ".env").write_text("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
    (tmp_path / ".env.example").write_text("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
    findings = check_env_files(str(tmp_path))
    assert any(f.rule == "env-example-has-secrets" for f in findings)


def test_env_example_with_placeholder_ok(tmp_path):
    (tmp_path / ".env").write_text("API_KEY=sk-real-secret-key\n")
    (tmp_path / ".env.example").write_text("API_KEY=changeme\n")
    findings = check_env_files(str(tmp_path))
    assert not any(f.rule == "env-example-has-secrets" for f in findings)


def test_env_example_with_your_star_placeholder_ok(tmp_path):
    (tmp_path / ".env").write_text("API_KEY=sk-real-secret-key\n")
    (tmp_path / ".env.example").write_text("API_KEY=your-api-key-here\n")
    findings = check_env_files(str(tmp_path))
    assert not any(f.rule == "env-example-has-secrets" for f in findings)


def test_env_example_with_empty_value_ok(tmp_path):
    (tmp_path / ".env").write_text("API_KEY=sk-real-secret-key\n")
    (tmp_path / ".env.example").write_text("API_KEY=\n")
    findings = check_env_files(str(tmp_path))
    assert not any(f.rule == "env-example-has-secrets" for f in findings)


def test_env_example_different_values_ok(tmp_path):
    (tmp_path / ".env").write_text("API_KEY=sk-real-secret-key\n")
    (tmp_path / ".env.example").write_text("API_KEY=sk-different-key\n")
    findings = check_env_files(str(tmp_path))
    assert not any(f.rule == "env-example-has-secrets" for f in findings)


def test_env_example_with_todo_placeholder_ok(tmp_path):
    (tmp_path / ".env").write_text("API_KEY=sk-real-secret-key\n")
    (tmp_path / ".env.example").write_text("API_KEY=TODO\n")
    findings = check_env_files(str(tmp_path))
    assert not any(f.rule == "env-example-has-secrets" for f in findings)


def test_env_example_with_xxx_placeholder_ok(tmp_path):
    (tmp_path / ".env").write_text("API_KEY=sk-real-secret-key\n")
    (tmp_path / ".env.example").write_text("API_KEY=xxx\n")
    findings = check_env_files(str(tmp_path))
    assert not any(f.rule == "env-example-has-secrets" for f in findings)


def test_env_example_with_long_hex_detected(tmp_path):
    hex_val = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
    (tmp_path / ".env").write_text(f"TOKEN={hex_val}\n")
    (tmp_path / ".env.example").write_text(f"TOKEN={hex_val}\n")
    findings = check_env_files(str(tmp_path))
    assert any(f.rule == "env-example-has-secrets" for f in findings)


def test_env_example_with_base64_detected(tmp_path):
    b64_val = "dGhpcyBpcyBhIHNlY3JldCBrZXkgdGhhdCBpcyBsb25n"
    (tmp_path / ".env").write_text(f"SECRET={b64_val}\n")
    (tmp_path / ".env.example").write_text(f"SECRET={b64_val}\n")
    findings = check_env_files(str(tmp_path))
    assert any(f.rule == "env-example-has-secrets" for f in findings)


def test_no_env_example_no_secrets_check(tmp_path):
    (tmp_path / ".env").write_text("API_KEY=sk-1234567890abcdef\n")
    findings = check_env_files(str(tmp_path))
    assert not any(f.rule == "env-example-has-secrets" for f in findings)


# --- BOM handling ---

def test_bom_env_file(tmp_path):
    from vibefort.envscan import _parse_env_values
    content = "\ufeffAPI_KEY=test123"
    values = _parse_env_values(content)
    assert "API_KEY" in values  # BOM should not corrupt key name


# --- .env.local scanned ---

def test_env_local_not_gitignored(tmp_path):
    from vibefort.envscan import check_env_files
    import os
    (tmp_path / ".git").mkdir()
    (tmp_path / ".env").write_text("X=1\n")
    (tmp_path / ".env.local").write_text("SECRET=abc\n")
    (tmp_path / ".gitignore").write_text(".env\n")
    os.chmod(str(tmp_path / ".env"), 0o600)
    findings = check_env_files(str(tmp_path))
    assert any(f.rule == "env-not-gitignored" and ".env.local" in f.file for f in findings)
