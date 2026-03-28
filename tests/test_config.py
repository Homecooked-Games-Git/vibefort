import stat
from vibefort.config import load_config, save_config, Config


def test_load_config_default_when_no_file(tmp_vibefort_home):
    config = load_config()
    assert config.shell_hook_installed is False
    assert config.packages_scanned == 0


def test_save_and_load_roundtrip(tmp_vibefort_home):
    config = Config(shell_hook_installed=True, packages_scanned=42)
    save_config(config)
    loaded = load_config()
    assert loaded.shell_hook_installed is True
    assert loaded.packages_scanned == 42


def test_config_file_permissions(tmp_vibefort_home):
    config = Config(shell_hook_installed=True)
    save_config(config)
    from vibefort.constants import CONFIG_PATH
    mode = CONFIG_PATH.stat().st_mode
    # File should not be world-readable (600)
    assert not (mode & stat.S_IROTH)
    assert not (mode & stat.S_IWOTH)
