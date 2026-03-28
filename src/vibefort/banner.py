"""VibeFort shell banner — terminal title and right prompt status."""

import json
from datetime import datetime, timedelta
from pathlib import Path

import vibefort.constants as constants
from vibefort.config import load_config


def _is_project_dir() -> bool:
    """Check if current directory looks like a project (has dependency files)."""
    try:
        cwd = Path.cwd()
    except (FileNotFoundError, OSError):
        return False
    project_files = [
        "requirements.txt", "pyproject.toml", "Pipfile", "setup.py",
        "package.json", "Cargo.toml", "go.mod", "Gemfile",
    ]
    return any((cwd / f).exists() for f in project_files)


def _get_project_scan_info() -> tuple[str, int]:
    """Get last scan time and issue count for current directory.

    Returns (time_str, issue_count). time_str is empty if never scanned.
    """
    try:
        from vibefort.db import _get_conn
        cwd = str(Path.cwd())
        conn = _get_conn()
        conn.execute("PRAGMA busy_timeout = 100")  # Don't freeze prompt if DB is locked
        row = conn.execute(
            "SELECT timestamp, result, details FROM scan_log WHERE target = ? ORDER BY id DESC LIMIT 1",
            (cwd,),
        ).fetchone()
        conn.close()
        if not row:
            return "", 0

        scan_time = datetime.fromisoformat(row[0])
        delta = datetime.now() - scan_time
        if delta < timedelta(minutes=1):
            time_str = "just now"
        elif delta < timedelta(hours=1):
            time_str = f"{int(delta.total_seconds() / 60)}m ago"
        elif delta < timedelta(days=1):
            time_str = f"{int(delta.total_seconds() / 3600)}h ago"
        else:
            time_str = f"{delta.days}d ago"

        # Try to get issue count from details
        try:
            issue_count = int(row[2]) if row[2] else 0
        except (ValueError, TypeError):
            issue_count = 0

        return time_str, issue_count
    except Exception:
        return "", 0


def _check_for_update() -> bool:
    """Check cached update info. Returns True if update available."""
    from vibefort import __version__
    cache_file = constants.CACHE_DIR / "update_check.json"
    try:
        if cache_file.exists():
            data = json.loads(cache_file.read_text())
            checked_at = datetime.fromisoformat(data.get("checked_at", ""))
            if datetime.now() - checked_at < timedelta(hours=24):
                # Verify the cached version is actually newer than what's running
                cached_version = data.get("latest", "")
                if cached_version and _is_newer(cached_version, __version__):
                    return True
                # We're up to date — clear stale cache
                cache_file.unlink()
                return False
    except Exception:
        pass
    return False


def get_title() -> str:
    """Plain text for terminal window/tab title (no ANSI colors)."""
    config = load_config()
    if not config.shell_hook_installed and not config.git_hook_installed:
        return ""

    parts = ["\U0001f3f0 protected"]

    if _is_project_dir():
        scan_time, issues = _get_project_scan_info()
        if issues:
            parts.append(f"{issues} issues")
        elif not scan_time:
            parts.append("never scanned")
        else:
            parts.append(f"scanned {scan_time}")

    if _check_for_update():
        parts.append("update \u2191")

    return " \u00b7 ".join(parts)


def get_short() -> str:
    """Compact status for zsh RPROMPT (with ANSI colors).

    Uses zsh %{ %} escapes so ANSI codes don't break prompt width calculation.
    """
    config = load_config()
    if not config.shell_hook_installed and not config.git_hook_installed:
        return ""

    # Castle + "protected" in green
    parts = ["%{\033[32m%}\U0001f3f0 protected%{\033[0m%}"]

    if _is_project_dir():
        scan_time, issues = _get_project_scan_info()
        if issues:
            parts.append(f"%{{\033[31m%}}{issues} issues%{{\033[0m%}}")
        elif not scan_time:
            parts.append(f"%{{\033[90m%}}never scanned%{{\033[0m%}}")
        else:
            parts.append(f"%{{\033[90m%}}scanned {scan_time}%{{\033[0m%}}")

    if _check_for_update():
        parts.append(f"%{{\033[33m%}}update \u2191%{{\033[0m%}}")

    return " \u00b7 ".join(parts)


def get_banner() -> str:
    """Full banner with ANSI colors (for `vibefort banner` command)."""
    config = load_config()
    if not config.shell_hook_installed and not config.git_hook_installed:
        return ""

    # Castle + "protected" in green
    parts = ["\033[32m\U0001f3f0 protected\033[0m"]

    if _is_project_dir():
        scan_time, issues = _get_project_scan_info()
        if issues:
            parts.append(f"\033[31m{issues} issues\033[0m")
        elif not scan_time:
            parts.append(f"\033[90mnever scanned\033[0m")
        else:
            parts.append(f"\033[90mscanned {scan_time}\033[0m")

    if _check_for_update():
        parts.append(f"\033[33mupdate \u2191\033[0m")

    return " \u00b7 ".join(parts)


def _is_newer(latest: str, current: str) -> bool:
    """Check if latest version is newer than current (semver comparison)."""
    try:
        latest_parts = [int(x) for x in latest.split(".")]
        current_parts = [int(x) for x in current.split(".")]
        return latest_parts > current_parts
    except (ValueError, AttributeError):
        return False


def check_for_update_online() -> str:
    """Check PyPI for updates. Called by `vibefort status`, not the banner."""
    from vibefort import __version__
    import httpx

    try:
        resp = httpx.get("https://pypi.org/pypi/vibefort/json", timeout=5)
        if resp.status_code != 200:
            return ""
        latest = resp.json()["info"]["version"]
        if _is_newer(latest, __version__):
            msg = f"update available ({latest})"
            constants.CACHE_DIR.mkdir(parents=True, exist_ok=True)
            cache_file = constants.CACHE_DIR / "update_check.json"
            cache_file.write_text(json.dumps({
                "checked_at": datetime.now().isoformat(),
                "latest": latest,
                "message": msg,
            }))
            return msg
        # No update — clear any stale cache
        cache_file = constants.CACHE_DIR / "update_check.json"
        if cache_file.exists():
            cache_file.unlink()
        return ""
    except Exception:
        return ""
