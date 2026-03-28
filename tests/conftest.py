import pytest
from pathlib import Path


@pytest.fixture
def tmp_vibefort_home(tmp_path, monkeypatch):
    """Redirect VIBEFORT_HOME to a temp directory."""
    home = tmp_path / ".vibefort"
    monkeypatch.setattr("vibefort.constants.VIBEFORT_HOME", home)
    monkeypatch.setattr("vibefort.constants.CONFIG_PATH", home / "config.toml")
    monkeypatch.setattr("vibefort.constants.DB_PATH", home / "data" / "vibefort.db")
    monkeypatch.setattr("vibefort.constants.HOOKS_DIR", home / "hooks")
    monkeypatch.setattr("vibefort.constants.BIN_DIR", home / "bin")
    monkeypatch.setattr("vibefort.constants.BETTERLEAKS_PATH", home / "bin" / "betterleaks")
    monkeypatch.setattr("vibefort.constants.CACHE_DIR", home / "cache")
    return home
