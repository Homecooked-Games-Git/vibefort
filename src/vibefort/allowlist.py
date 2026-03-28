"""Allow/ignore system for VibeFort — per-project configuration."""

import sys
from pathlib import Path

import toml

import vibefort.constants as constants

# Track whether we've warned about project-level allowlist this session
_warned_project_allowlist = False


def _find_config() -> tuple[dict, str]:
    """Find and load .vibefort.toml.

    Priority:
    1. ~/.vibefort/allowlist.toml (user-level, always trusted)
    2. .vibefort.toml in CWD or parents (project-level, prints warning)

    Returns (config_dict, source_path).
    """
    # User-level allowlist (always trusted)
    user_config = constants.VIBEFORT_HOME / "allowlist.toml"
    if user_config.exists():
        try:
            return toml.load(user_config), str(user_config)
        except (toml.TomlDecodeError, ValueError):
            pass

    # Project-level allowlist (warn user)
    cwd = Path.cwd()
    for directory in [cwd, *cwd.parents]:
        config_path = directory / ".vibefort.toml"
        if config_path.exists():
            global _warned_project_allowlist
            if not _warned_project_allowlist:
                print(
                    f"vibefort: using project allowlist at {config_path} "
                    "(packages/rules listed here will skip scanning)",
                    file=sys.stderr,
                )
                _warned_project_allowlist = True
            try:
                return toml.load(config_path), str(config_path)
            except (toml.TomlDecodeError, ValueError):
                return {}, ""

    return {}, ""


def is_package_allowed(package: str) -> bool:
    """Check if a package is explicitly allowed (skip scanning)."""
    config, _ = _find_config()
    allowed = config.get("allow-packages", {})
    return package.lower() in {k.lower() for k in allowed}


def is_file_allowed(filepath: str) -> bool:
    """Check if a file should be skipped in secret scanning."""
    config, _ = _find_config()
    allowed = config.get("allow-files", {})
    if not allowed:
        return False

    path = Path(filepath)
    allowed_set = {k.lower() for k in allowed}

    # Match by exact path or filename
    checks = [str(path).lower(), path.name.lower()]

    # Try relative path if absolute
    if path.is_absolute():
        try:
            checks.append(str(path.relative_to(Path.cwd())).lower())
        except ValueError:
            pass

    return any(c in allowed_set for c in checks)


def is_rule_allowed(rule_id: str) -> bool:
    """Check if a betterleaks rule should be skipped."""
    config, _ = _find_config()
    allowed = config.get("allow-rules", {})
    return rule_id.lower() in {k.lower() for k in allowed}


def get_allowed_packages() -> dict[str, str]:
    """Get all allowed packages with their reasons."""
    config, _ = _find_config()
    return config.get("allow-packages", {})
