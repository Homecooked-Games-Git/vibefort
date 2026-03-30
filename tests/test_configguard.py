"""Tests for config guard module — monitors sensitive dotfile changes."""

from pathlib import Path

from vibefort.configguard import (
    ConfigAlert,
    snapshot_config_files,
    check_config_changes,
)


def _make_home(tmp_path: Path) -> Path:
    """Create a fake HOME with some config files."""
    home = tmp_path / "home"
    home.mkdir()
    ssh = home / ".ssh"
    ssh.mkdir()
    (ssh / "config").write_text("Host *\n  ForwardAgent no\n")
    (ssh / "authorized_keys").write_text("ssh-rsa AAAAB...\n")
    (home / ".gitconfig").write_text("[user]\n  name = test\n")
    return home


# --- snapshot ---

def test_snapshot_creates_checksums_for_existing_files(tmp_path):
    home = _make_home(tmp_path)
    checksums_path = str(tmp_path / "checksums.toml")
    result = snapshot_config_files(checksums_path, home=str(home))
    # Should include the 3 files we created
    assert len(result) == 3
    assert str(home / ".ssh" / "config") in result
    assert str(home / ".ssh" / "authorized_keys") in result
    assert str(home / ".gitconfig") in result
    # Values should be hex sha256 hashes (64 chars)
    for v in result.values():
        assert len(v) == 64


def test_snapshot_skips_missing_files(tmp_path):
    home = tmp_path / "emptyhome"
    home.mkdir()
    checksums_path = str(tmp_path / "checksums.toml")
    result = snapshot_config_files(checksums_path, home=str(home))
    assert result == {}


def test_snapshot_creates_parent_dirs(tmp_path):
    home = _make_home(tmp_path)
    checksums_path = str(tmp_path / "deep" / "nested" / "checksums.toml")
    snapshot_config_files(checksums_path, home=str(home))
    assert Path(checksums_path).exists()


def test_snapshot_writes_toml_file(tmp_path):
    home = _make_home(tmp_path)
    checksums_path = str(tmp_path / "checksums.toml")
    snapshot_config_files(checksums_path, home=str(home))
    content = Path(checksums_path).read_text()
    assert "[checksums]" in content


# --- check_config_changes: first run ---

def test_first_run_no_alerts(tmp_path):
    home = _make_home(tmp_path)
    checksums_path = str(tmp_path / "checksums.toml")
    # No previous snapshot exists
    alerts = check_config_changes(checksums_path, home=str(home))
    assert alerts == []
    # But snapshot file should now exist
    assert Path(checksums_path).exists()


# --- check_config_changes: no changes ---

def test_no_alert_when_unchanged(tmp_path):
    home = _make_home(tmp_path)
    checksums_path = str(tmp_path / "checksums.toml")
    # First run: creates snapshot
    check_config_changes(checksums_path, home=str(home))
    # Second run: nothing changed
    alerts = check_config_changes(checksums_path, home=str(home))
    assert alerts == []


# --- check_config_changes: modified file ---

def test_detects_modified_file(tmp_path):
    home = _make_home(tmp_path)
    checksums_path = str(tmp_path / "checksums.toml")
    # First run
    check_config_changes(checksums_path, home=str(home))
    # Modify a file
    (home / ".gitconfig").write_text("[user]\n  name = hacker\n")
    # Second run
    alerts = check_config_changes(checksums_path, home=str(home))
    assert len(alerts) >= 1
    modified = [a for a in alerts if a.rule == "config-modified"]
    assert len(modified) == 1
    assert modified[0].severity == "high"
    assert str(home / ".gitconfig") == modified[0].file


# --- check_config_changes: new file appeared ---

def test_detects_new_file(tmp_path):
    home = _make_home(tmp_path)
    checksums_path = str(tmp_path / "checksums.toml")
    # First run
    check_config_changes(checksums_path, home=str(home))
    # Add a new watched file
    (home / ".npmrc").write_text("//registry.npmjs.org/:_authToken=secret\n")
    # Second run
    alerts = check_config_changes(checksums_path, home=str(home))
    new_alerts = [a for a in alerts if a.rule == "config-new-file"]
    assert len(new_alerts) == 1
    assert new_alerts[0].severity == "high"
    assert str(home / ".npmrc") == new_alerts[0].file


# --- check_config_changes: updates snapshot after check ---

def test_snapshot_updated_after_check(tmp_path):
    home = _make_home(tmp_path)
    checksums_path = str(tmp_path / "checksums.toml")
    check_config_changes(checksums_path, home=str(home))
    # Modify
    (home / ".gitconfig").write_text("[user]\n  name = changed\n")
    alerts = check_config_changes(checksums_path, home=str(home))
    assert len(alerts) >= 1
    # Third run: no alerts since snapshot was updated
    alerts2 = check_config_changes(checksums_path, home=str(home))
    assert alerts2 == []


# --- ConfigAlert dataclass ---

def test_config_alert_fields():
    alert = ConfigAlert(
        rule="config-modified",
        description="Git config modified",
        severity="high",
        file="/home/user/.gitconfig",
    )
    assert alert.rule == "config-modified"
    assert alert.file == "/home/user/.gitconfig"
