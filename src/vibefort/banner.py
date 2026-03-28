"""VibeFort shell banner — terminal title and right prompt status."""

import json
from datetime import datetime, timedelta
from pathlib import Path

import vibefort.constants as constants
from vibefort.config import load_config


def get_title() -> str:
    """Plain text for terminal window/tab title (no ANSI colors)."""
    config = load_config()
    if not config.shell_hook_installed and not config.git_hook_installed:
        return ""

    parts = ["\U0001f3f0 VibeFort"]

    if config.packages_blocked:
        parts.append(f"{config.packages_blocked} blocked")

    if config.secrets_caught:
        parts.append(f"{config.secrets_caught} secrets caught")

    update = _check_for_update()
    if update:
        parts.append(f"\u2191 {update}")

    return " \u00b7 ".join(parts)


def get_short() -> str:
    """Compact status for zsh RPROMPT (with ANSI colors, no newlines).

    Uses zsh %{ %} escapes so ANSI codes don't break prompt width calculation.
    """
    config = load_config()
    if not config.shell_hook_installed and not config.git_hook_installed:
        return ""

    parts = []

    # Fort
    parts.append("%{\033[32m%}\U0001f3f0%{\033[0m%}")

    # Key stats
    if config.packages_blocked:
        parts.append(f"%{{\033[31m%}}{config.packages_blocked}blk%{{\033[0m%}}")
    if config.secrets_caught:
        parts.append(f"%{{\033[31m%}}{config.secrets_caught}sec%{{\033[0m%}}")

    # Update
    update = _check_for_update()
    if update:
        parts.append(f"%{{\033[33m%}}\u2191%{{\033[0m%}}")

    return " ".join(parts)


def get_banner() -> str:
    """Full banner with ANSI colors (for `vibefort banner` command)."""
    config = load_config()

    if not config.shell_hook_installed and not config.git_hook_installed:
        return ""

    parts = []

    parts.append("\033[32m\U0001f3f0 VibeFort\033[0m")

    stats = []
    if config.packages_scanned:
        stats.append(f"{config.packages_scanned} scanned")
    if config.packages_blocked:
        stats.append(f"\033[31m{config.packages_blocked} blocked\033[0m")
    if config.secrets_caught:
        stats.append(f"\033[31m{config.secrets_caught} secrets caught\033[0m")
    if stats:
        parts.append(" \u00b7 ".join(stats))

    last_scan = _get_last_scan_time()
    if last_scan:
        parts.append(f"\033[90m{last_scan}\033[0m")

    update = _check_for_update()
    if update:
        parts.append(f"\033[33m\u2191 {update}\033[0m")

    return " \u00b7 ".join(parts)


def _get_last_scan_time() -> str:
    """Get a human-readable 'last scan' time."""
    try:
        from vibefort.db import get_last_scan
        last = get_last_scan()
        if not last:
            return ""
        scan_time = datetime.fromisoformat(last["timestamp"])
        delta = datetime.now() - scan_time
        if delta < timedelta(minutes=1):
            return "scanned just now"
        elif delta < timedelta(hours=1):
            mins = int(delta.total_seconds() / 60)
            return f"scanned {mins}m ago"
        elif delta < timedelta(days=1):
            hours = int(delta.total_seconds() / 3600)
            return f"scanned {hours}h ago"
        else:
            days = delta.days
            return f"scanned {days}d ago"
    except Exception:
        return ""


def _check_for_update() -> str:
    """Check cached update info (no network call)."""
    cache_file = constants.CACHE_DIR / "update_check.json"

    try:
        if cache_file.exists():
            data = json.loads(cache_file.read_text())
            checked_at = datetime.fromisoformat(data.get("checked_at", ""))
            if datetime.now() - checked_at < timedelta(hours=24):
                return data.get("message", "")
    except Exception:
        pass

    return ""


def check_for_update_online() -> str:
    """Check PyPI for updates. Called by `vibefort status`, not the banner."""
    from vibefort import __version__
    import httpx

    try:
        resp = httpx.get("https://pypi.org/pypi/vibefort/json", timeout=5)
        if resp.status_code != 200:
            return ""
        latest = resp.json()["info"]["version"]
        if latest != __version__:
            msg = f"update available ({latest})"
            constants.CACHE_DIR.mkdir(parents=True, exist_ok=True)
            cache_file = constants.CACHE_DIR / "update_check.json"
            cache_file.write_text(json.dumps({
                "checked_at": datetime.now().isoformat(),
                "latest": latest,
                "message": msg,
            }))
            return msg
        return ""
    except Exception:
        return ""
