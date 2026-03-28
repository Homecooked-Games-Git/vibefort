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

    try:
        data = toml.load(constants.CONFIG_PATH)
    except (toml.TomlDecodeError, ValueError):
        return Config()  # Return defaults if config is corrupted

    known_fields = {f.name for f in Config.__dataclass_fields__.values()}
    filtered = {k: v for k, v in data.items() if k in known_fields}
    return Config(**filtered)


def save_config(config: Config) -> None:
    """Save config to disk with restrictive permissions."""
    constants.ensure_home_dir()

    data = asdict(config)
    # Remove None values for cleaner TOML
    data = {k: v for k, v in data.items() if v is not None}

    # Set restrictive umask before writing, then restore
    old_umask = os.umask(0o077)
    try:
        constants.CONFIG_PATH.write_text(toml.dumps(data))
    finally:
        os.umask(old_umask)
