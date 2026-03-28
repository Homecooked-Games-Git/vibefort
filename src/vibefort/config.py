"""Configuration loading and saving for ~/.vibefort/config.toml."""

from dataclasses import dataclass, asdict
from pathlib import Path
import os
import stat
import toml

import vibefort.constants as constants


@dataclass
class Config:
    """VibeFort configuration."""

    shell_hook_installed: bool = False
    git_hook_installed: bool = False

    # Stats
    packages_scanned: int = 0
    packages_blocked: int = 0
    commits_scanned: int = 0
    secrets_caught: int = 0


def load_config() -> Config:
    """Load config from disk, returning defaults if file doesn't exist."""
    if not constants.CONFIG_PATH.exists():
        return Config()

    data = toml.load(constants.CONFIG_PATH)
    known_fields = {f.name for f in Config.__dataclass_fields__.values()}
    filtered = {k: v for k, v in data.items() if k in known_fields}
    return Config(**filtered)


def save_config(config: Config) -> None:
    """Save config to disk with restrictive permissions."""
    constants.VIBEFORT_HOME.mkdir(parents=True, exist_ok=True)
    # Restrict home directory to owner only
    os.chmod(constants.VIBEFORT_HOME, stat.S_IRWXU)

    data = asdict(config)
    # Remove None values for cleaner TOML
    data = {k: v for k, v in data.items() if v is not None}

    constants.CONFIG_PATH.write_text(toml.dumps(data))

    # Restrict permissions: owner read/write only
    os.chmod(constants.CONFIG_PATH, stat.S_IRUSR | stat.S_IWUSR)
