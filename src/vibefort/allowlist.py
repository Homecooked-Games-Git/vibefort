"""Allow/ignore system for VibeFort — per-project configuration."""

import os
from pathlib import Path

import toml


def _find_config() -> dict:
    """Find and load .vibefort.toml from current directory or parents."""
    cwd = Path.cwd()
    for directory in [cwd, *cwd.parents]:
        config_path = directory / ".vibefort.toml"
        if config_path.exists():
            try:
                return toml.load(config_path)
            except (toml.TomlDecodeError, ValueError):
                return {}
    return {}


def is_package_allowed(package: str) -> bool:
    """Check if a package is explicitly allowed (skip scanning)."""
    config = _find_config()
    allowed = config.get("allow-packages", {})
    return package.lower() in {k.lower() for k in allowed}


def is_file_allowed(filepath: str) -> bool:
    """Check if a file should be skipped in secret scanning."""
    config = _find_config()
    allowed = config.get("allow-files", {})
    # Match against filename or relative path
    path = Path(filepath)
    allowed_set = {k.lower() for k in allowed}
    return (
        str(path).lower() in allowed_set
        or path.name.lower() in allowed_set
        or str(path.relative_to(Path.cwd())).lower() in allowed_set
        if path.is_absolute() else str(path).lower() in allowed_set
    )


def is_rule_allowed(rule_id: str) -> bool:
    """Check if a betterleaks rule should be skipped."""
    config = _find_config()
    allowed = config.get("allow-rules", {})
    return rule_id.lower() in {k.lower() for k in allowed}


def get_allowed_packages() -> dict[str, str]:
    """Get all allowed packages with their reasons."""
    config = _find_config()
    return config.get("allow-packages", {})
