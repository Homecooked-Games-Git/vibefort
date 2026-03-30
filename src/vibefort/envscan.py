"""Env file watchdog — checks .env files for security issues."""

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


@dataclass
class EnvFinding:
    rule: str
    description: str
    severity: str  # "critical", "high", "medium"
    file: Optional[str] = None


# Patterns that match .env in .gitignore
_GITIGNORE_ENV_PATTERNS = {".env", ".env*", ".env.*", "*.env"}

# Secret-like value patterns
_SECRET_PATTERNS = [
    re.compile(r"^sk-"),           # OpenAI / Stripe style
    re.compile(r"^ghp_"),          # GitHub personal access token
    re.compile(r"^gho_"),          # GitHub OAuth token
    re.compile(r"^ghu_"),          # GitHub user-to-server token
    re.compile(r"^ghs_"),         # GitHub server-to-server token
    re.compile(r"^ghr_"),          # GitHub refresh token
    re.compile(r"^AKIA"),          # AWS access key
    re.compile(r"^[A-Fa-f0-9]{32,}$"),  # Long hex hash
    re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$"),  # Base64 encoded
]

# Placeholder patterns (should NOT be flagged)
_PLACEHOLDER_PATTERNS = [
    re.compile(r"^changeme$", re.IGNORECASE),
    re.compile(r"^your[-_]", re.IGNORECASE),
    re.compile(r"^replace", re.IGNORECASE),
    re.compile(r"^TODO$", re.IGNORECASE),
    re.compile(r"^xxx+$", re.IGNORECASE),
    re.compile(r"^example$", re.IGNORECASE),
    re.compile(r"^placeholder$", re.IGNORECASE),
    re.compile(r"^CHANGE[-_]?ME$", re.IGNORECASE),
]


def _parse_env_values(content: str) -> dict[str, str]:
    """Parse KEY=VALUE pairs from .env file content.

    Skips comments and empty lines. Handles quoted values.
    """
    result: dict[str, str] = {}
    # Strip BOM if present (common in Windows-edited files)
    content = content.lstrip("\ufeff")
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        # Strip surrounding quotes
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        result[key] = value
    return result


def _is_placeholder(value: str) -> bool:
    """Check if a value looks like a placeholder."""
    for pattern in _PLACEHOLDER_PATTERNS:
        if pattern.search(value):
            return True
    return False


def _looks_like_secret(value: str) -> bool:
    """Check if a value looks like a real secret."""
    for pattern in _SECRET_PATTERNS:
        if pattern.search(value):
            return True
    return False


def _is_git_ignored(directory: Path, filename: str) -> bool:
    """Check if a file is gitignored using git check-ignore (authoritative).

    Falls back to simple .gitignore pattern matching if git is unavailable
    or the directory is not a proper git repository.
    """
    import subprocess
    try:
        result = subprocess.run(
            ["git", "check-ignore", "-q", filename],
            capture_output=True, cwd=str(directory), timeout=5,
        )
        # returncode 0 = ignored, 1 = not ignored, 128 = not a git repo
        if result.returncode in (0, 1):
            return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    # Fallback: simple pattern matching against the specific filename
    gitignore_path = directory / ".gitignore"
    if not gitignore_path.is_file():
        return False
    gitignore_content = gitignore_path.read_text(errors="replace")
    gitignore_lines = {line.strip() for line in gitignore_content.splitlines() if line.strip() and not line.strip().startswith("#")}
    # Check if the filename matches any gitignore pattern using fnmatch
    import fnmatch
    for pattern in gitignore_lines:
        if fnmatch.fnmatch(filename, pattern):
            return True
    return False


def check_env_files(directory: str) -> List[EnvFinding]:
    """Check .env files in a directory for security issues.

    Checks:
    1. .env not in .gitignore (only if .git/ exists)
    2. .env world-readable permissions
    3. .env.example contains real secrets matching .env values
    """
    findings: List[EnvFinding] = []
    dir_path = Path(directory)
    env_path = dir_path / ".env"

    if not env_path.is_file():
        return findings

    # Check 1: .env not in .gitignore
    git_dir = dir_path / ".git"
    if git_dir.is_dir():
        env_ignored = _is_git_ignored(dir_path, ".env")
        if not env_ignored:
            findings.append(EnvFinding(
                rule="env-not-gitignored",
                description=".env file is not gitignored; it may be committed to git",
                severity="critical",
                file=str(env_path),
            ))

    # Check 2: .env world-readable permissions
    try:
        env_stat = os.lstat(str(env_path))
    except OSError:
        env_stat = None
    if env_stat and env_stat.st_mode & stat.S_IROTH:
        findings.append(EnvFinding(
            rule="env-world-readable",
            description=".env file is world-readable; run 'chmod 600 .env' to restrict access",
            severity="high",
            file=str(env_path),
        ))

    # Check 3: .env.example contains real secrets
    env_example_path = dir_path / ".env.example"
    if env_example_path.is_file():
        env_values = _parse_env_values(env_path.read_text(errors="replace"))
        example_values = _parse_env_values(env_example_path.read_text(errors="replace"))

        for key, example_val in example_values.items():
            if not example_val:
                continue
            if _is_placeholder(example_val):
                continue
            if key in env_values and example_val == env_values[key]:
                if _looks_like_secret(example_val):
                    findings.append(EnvFinding(
                        rule="env-example-has-secrets",
                        description=f".env.example contains a real secret for '{key}' that matches .env",
                        severity="critical",
                        file=str(env_example_path),
                    ))
                    break  # One finding is enough

    # Check 4: .env variant files (.env.local, .env.production, etc.)
    # Apply gitignore + permission checks to variants
    if git_dir.is_dir():
        for variant in dir_path.glob(".env.*"):
            if variant.name == ".env.example" or not variant.is_file():
                continue
            if variant.is_symlink():
                continue
            if not _is_git_ignored(dir_path, variant.name):
                findings.append(EnvFinding(
                    rule="env-not-gitignored",
                    description=f"{variant.name} is not gitignored; it may be committed to git",
                    severity="critical",
                    file=str(variant),
                ))
            try:
                vstat = os.lstat(str(variant))
                if vstat.st_mode & stat.S_IROTH:
                    findings.append(EnvFinding(
                        rule="env-world-readable",
                        description=f"{variant.name} is world-readable; run 'chmod 600 {variant.name}'",
                        severity="high",
                        file=str(variant),
                    ))
            except OSError:
                pass

    return findings
