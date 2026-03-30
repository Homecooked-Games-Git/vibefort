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
WORLD_WRITABLE_SYMBOLIC = re.compile(r"(?:^|,)(?:o[+=][rwxXst]*w|a[+=][rwxXst]*w)")

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
    # Handles both 3-digit (777) and 4-digit (0777, 2777) forms
    if mode.isdigit() and len(mode) in (3, 4):
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


_SUDO_FLAGS_WITH_VALUE = {"-u", "-g", "-C", "-D", "-R", "-T", "--user", "--group",
                          "--close-from", "--chdir", "--role", "--type"}


def _extract_sudo_command(args: list[str]) -> tuple[str, list[str]]:
    """Extract the actual command from sudo args, skipping sudo flags.

    Returns (command, remaining_args).
    """
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            # Everything after -- is the command
            i += 1
            break
        if arg in _SUDO_FLAGS_WITH_VALUE:
            i += 2  # skip flag + its value
            continue
        if arg.startswith("-"):
            i += 1  # skip boolean flag
            continue
        break  # first non-flag is the command
    if i >= len(args):
        return "", []
    return args[i], args[i + 1:]


def check_sudo_args(args: list[str]) -> list[PermFinding]:
    """Check sudo arguments for dangerous patterns."""
    if not args:
        return []

    findings: List[PermFinding] = []
    cmd, rest = _extract_sudo_command(args)
    if not cmd:
        return []

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

    # Check for sudo su -c (runs command in a login shell)
    cmd_args = [cmd] + rest
    if cmd == "su" and "-c" in cmd_args:
        c_idx = cmd_args.index("-c")
        if c_idx + 1 < len(cmd_args):
            shell_cmd = cmd_args[c_idx + 1]
            # Check if the shell command invokes a package manager
            for pm in PACKAGE_MANAGERS:
                if re.search(rf"\b{pm}\b", shell_cmd):
                    findings.append(PermFinding(
                        rule="sudo-package-manager",
                        description=f"Running '{pm}' via sudo su -c — use virtual environments instead",
                        severity="high",
                    ))
                    break
            for pattern in REMOTE_EXEC_PATTERNS:
                if pattern.search(shell_cmd):
                    findings.append(PermFinding(
                        rule="sudo-remote-exec",
                        description="Downloading and executing remote code with sudo su is extremely dangerous",
                        severity="critical",
                    ))
                    break

    # Check for sudo bash/sh -c with remote exec
    if cmd in ("bash", "sh") and "-c" in cmd_args:
        c_idx = cmd_args.index("-c")
        if c_idx + 1 < len(cmd_args):
            shell_cmd = cmd_args[c_idx + 1]
            for pattern in REMOTE_EXEC_PATTERNS:
                if pattern.search(shell_cmd):
                    findings.append(PermFinding(
                        rule="sudo-remote-exec",
                        description="Downloading and executing remote code with sudo is extremely dangerous",
                        severity="critical",
                    ))
                    break

    # Check for sudo python/python3/node -c
    if cmd in ("python", "python3", "node") and "-c" in cmd_args:
        findings.append(PermFinding(
            rule="sudo-code-exec",
            description=f"Running '{cmd} -c' with sudo executes arbitrary code as root",
            severity="high",
        ))

    # Check for sudo rm -rf on dangerous paths
    if cmd == "rm":
        has_rf = any(
            a.startswith("-") and "r" in a and "f" in a
            for a in rest
        )
        if has_rf:
            for a in rest:
                if not a.startswith("-"):
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
