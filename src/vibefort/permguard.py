"""Permission escalation guard — detects dangerous chmod/sudo patterns."""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List


@dataclass
class PermFinding:
    rule: str
    description: str
    severity: str  # "critical", "high", "medium"


# No longer a static set — we check the octal mode programmatically

# Symbolic modes that grant world-writable access
WORLD_WRITABLE_SYMBOLIC = re.compile(r"(?:^|,)(?:o\+[rwxXst]*w|a\+[rwxXst]*w)")

# Suspicious content patterns in files being made executable
SUSPICIOUS_CONTENT_PATTERNS = [
    re.compile(r"curl\b.*\|\s*(?:ba)?sh", re.IGNORECASE),
    re.compile(r"wget\b.*\|\s*(?:ba)?sh", re.IGNORECASE),
    re.compile(r"base64\s+decode", re.IGNORECASE),
    re.compile(r"\beval\b", re.IGNORECASE),
    re.compile(r"\bnc\b", re.IGNORECASE),
    re.compile(r"/dev/tcp/", re.IGNORECASE),
]

# Package managers that should not be run with sudo
PACKAGE_MANAGERS = {
    "pip", "pip3", "npm", "npx", "yarn", "pnpm",
    "bun", "pipx", "uv", "poetry", "pdm",
}

# Safe sudo commands (system package managers and service managers)
SAFE_SUDO_COMMANDS = {
    "systemctl", "service", "apt", "apt-get", "yum",
    "dnf", "pacman", "brew", "zypper", "apk",
    "snap", "flatpak", "journalctl", "mount", "umount",
}

# Dangerous paths for rm -rf
DANGEROUS_PATHS = {"/", "/home", "/etc", "/var", "/usr"}

# Remote-exec patterns inside shell -c strings
REMOTE_EXEC_PATTERNS = [
    re.compile(r"curl\b.*\|\s*(?:ba)?sh", re.IGNORECASE),
    re.compile(r"wget\b.*\|\s*(?:ba)?sh", re.IGNORECASE),
]


def check_chmod_args(args: list[str]) -> list[PermFinding]:
    """Check chmod arguments for dangerous permission patterns."""
    if not args:
        return []

    findings: List[PermFinding] = []

    # Strip flags like -R, -v, -f, --recursive etc.
    non_flag_args = [a for a in args if not a.startswith("-")]

    if not non_flag_args:
        return []

    mode = non_flag_args[0]
    files = non_flag_args[1:]

    # Check for world-writable octal modes (others-write bit set)
    if mode.isdigit() and len(mode) == 3:
        try:
            if int(mode, 8) & 0o002:  # others-write bit
                findings.append(PermFinding(
                    rule="chmod-world-writable",
                    description=f"World-writable mode {mode} allows any user to modify files",
                    severity="critical",
                ))
        except ValueError:
            pass

    # Check for world-writable symbolic modes
    if WORLD_WRITABLE_SYMBOLIC.search(mode):
        findings.append(PermFinding(
            rule="chmod-world-writable",
            description=f"Symbolic mode '{mode}' grants world-writable access",
            severity="critical",
        ))

    # Check +x on files for suspicious content
    if "+x" in mode:
        for filepath in files:
            path = Path(filepath)
            if not path.is_file():
                continue
            try:
                content = path.read_text(errors="replace")
            except (OSError, PermissionError):
                continue

            for pattern in SUSPICIOUS_CONTENT_PATTERNS:
                if pattern.search(content):
                    findings.append(PermFinding(
                        rule="chmod-exec-suspicious",
                        description=f"Making executable a file with suspicious content: {filepath}",
                        severity="high",
                    ))
                    break  # One finding per file

    return findings


def check_sudo_args(args: list[str]) -> list[PermFinding]:
    """Check sudo arguments for dangerous patterns."""
    if not args:
        return []

    findings: List[PermFinding] = []
    cmd = args[0]

    # Safe commands — return early with no findings
    if cmd in SAFE_SUDO_COMMANDS:
        return []

    # Check for package managers
    if cmd in PACKAGE_MANAGERS:
        findings.append(PermFinding(
            rule="sudo-package-manager",
            description=f"Running '{cmd}' with sudo can lead to privilege escalation; use virtual environments instead",
            severity="high",
        ))

    # Check for sudo bash/sh -c with remote exec
    if cmd in ("bash", "sh") and "-c" in args:
        c_idx = args.index("-c")
        if c_idx + 1 < len(args):
            shell_cmd = args[c_idx + 1]
            for pattern in REMOTE_EXEC_PATTERNS:
                if pattern.search(shell_cmd):
                    findings.append(PermFinding(
                        rule="sudo-remote-exec",
                        description="Downloading and executing remote code with sudo is extremely dangerous",
                        severity="critical",
                    ))
                    break

    # Check for sudo python/python3/node -c
    if cmd in ("python", "python3", "node") and "-c" in args:
        findings.append(PermFinding(
            rule="sudo-code-exec",
            description=f"Running '{cmd} -c' with sudo executes arbitrary code as root",
            severity="high",
        ))

    # Check for sudo rm -rf on dangerous paths
    if cmd == "rm":
        has_rf = any(
            a.startswith("-") and "r" in a and "f" in a
            for a in args[1:]
        )
        if has_rf:
            for a in args[1:]:
                if not a.startswith("-"):
                    # Normalize path
                    normalized = a.rstrip("/")
                    if not normalized:
                        normalized = "/"
                    if normalized in DANGEROUS_PATHS:
                        findings.append(PermFinding(
                            rule="sudo-destructive",
                            description=f"sudo rm -rf {a} would destroy critical system files",
                            severity="critical",
                        ))
                        break

    return findings
