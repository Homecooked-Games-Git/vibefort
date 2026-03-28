from pathlib import Path
from vibefort.banner import (
    _is_project_dir, _is_newer, get_title, get_short, get_banner,
)


def test_is_project_dir_with_requirements(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("flask\n")
    monkeypatch.chdir(tmp_path)
    assert _is_project_dir() is True


def test_is_project_dir_with_package_json(tmp_path, monkeypatch):
    (tmp_path / "package.json").write_text("{}")
    monkeypatch.chdir(tmp_path)
    assert _is_project_dir() is True


def test_is_project_dir_empty(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert _is_project_dir() is False


def test_is_project_dir_deleted_directory(tmp_path, monkeypatch):
    sub = tmp_path / "subdir"
    sub.mkdir()
    monkeypatch.chdir(sub)
    sub.rmdir()  # Delete the directory we're in
    assert _is_project_dir() is False


def test_is_newer_basic():
    assert _is_newer("0.2.0", "0.1.0") is True
    assert _is_newer("0.1.0", "0.2.0") is False
    assert _is_newer("0.1.0", "0.1.0") is False
    assert _is_newer("1.0.0", "0.9.9") is True


def test_is_newer_invalid():
    assert _is_newer("abc", "0.1.0") is False
    assert _is_newer("", "0.1.0") is False


def test_get_title_inactive(tmp_vibefort_home):
    title = get_title()
    assert title == ""


def test_get_short_inactive(tmp_vibefort_home):
    short = get_short()
    assert short == ""


def test_get_banner_inactive(tmp_vibefort_home):
    banner = get_banner()
    assert banner == ""


def test_get_title_active(tmp_vibefort_home):
    from vibefort.config import Config, save_config
    config = Config(shell_hook_installed=True)
    save_config(config)
    title = get_title()
    assert "protected" in title


def test_get_short_active(tmp_vibefort_home):
    from vibefort.config import Config, save_config
    config = Config(shell_hook_installed=True)
    save_config(config)
    short = get_short()
    assert "protected" in short


def test_get_banner_active(tmp_vibefort_home):
    from vibefort.config import Config, save_config
    config = Config(shell_hook_installed=True)
    save_config(config)
    banner = get_banner()
    assert "protected" in banner
