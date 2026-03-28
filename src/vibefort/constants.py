"""Paths, URLs, and constants."""

from pathlib import Path
import platform

# VibeFort home directory
VIBEFORT_HOME = Path.home() / ".vibefort"
CONFIG_PATH = VIBEFORT_HOME / "config.toml"
DB_PATH = VIBEFORT_HOME / "data" / "vibefort.db"
HOOKS_DIR = VIBEFORT_HOME / "hooks"
BIN_DIR = VIBEFORT_HOME / "bin"
BETTERLEAKS_PATH = BIN_DIR / "betterleaks"
CACHE_DIR = VIBEFORT_HOME / "cache"

# betterleaks download
BETTERLEAKS_VERSION = "1.1.1"
BETTERLEAKS_BASE_URL = "https://github.com/betterleaks/betterleaks/releases/download"


def get_betterleaks_download_url() -> str:
    """Get platform-specific betterleaks download URL."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    os_name = {"darwin": "darwin", "linux": "linux", "windows": "windows"}.get(system)
    if os_name is None:
        raise RuntimeError(f"Unsupported OS: {system}")

    arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "x64", "amd64": "x64"}.get(machine)
    if arch is None:
        raise RuntimeError(f"Unsupported architecture: {machine}")

    ext = "zip" if system == "windows" else "tar.gz"
    filename = f"betterleaks_{BETTERLEAKS_VERSION}_{os_name}_{arch}.{ext}"
    return f"{BETTERLEAKS_BASE_URL}/v{BETTERLEAKS_VERSION}/{filename}"


# Shell hook marker
SHELL_HOOK_START = "# >>> vibefort >>>"
SHELL_HOOK_END = "# <<< vibefort <<<"

# Prompt indicator
FORT_ICON = "\U0001f3f0"  # Castle emoji

# Top packages cache
TOP_PACKAGES_COUNT = 10_000
