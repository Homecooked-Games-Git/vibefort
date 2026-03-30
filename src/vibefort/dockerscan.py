"""Dockerfile vulnerability scanner — detects insecure patterns in Dockerfiles."""

import re
from pathlib import Path
from dataclasses import dataclass
from typing import List

SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache"}

SECRET_NAME_PATTERN = re.compile(
    r"(password|passwd|secret|token|api_key|apikey|private_key|access_key)",
    re.IGNORECASE,
)

PLACEHOLDER_VALUES = {
    "", "changeme", "change_me", "placeholder", "xxx", "your_secret_here",
    "your-secret-here", "todo", "fixme", "replace_me", "replace-me",
    "none", "null", "example", "test",
}


@dataclass
class DockerFinding:
    file: str
    line: int
    rule: str
    description: str
    severity: str  # "critical", "high", "medium"


def _is_comment(line: str) -> bool:
    return line.lstrip().startswith("#")


def scan_dockerfile(filepath: str) -> List[DockerFinding]:
    """Scan a single Dockerfile for vulnerability patterns."""
    path = Path(filepath)
    if not path.exists():
        return []

    content = path.read_text(errors="replace")
    raw_lines = content.splitlines()
    if not raw_lines:
        return []

    # Join backslash-continued lines so multi-line RUN commands are scanned as one
    lines: list[tuple[int, str]] = []  # (first_lineno, joined_line)
    i = 0
    while i < len(raw_lines):
        raw = raw_lines[i]
        if _is_comment(raw) or not raw.strip():
            i += 1
            continue
        joined = raw.rstrip()
        first_lineno = i + 1
        while joined.endswith("\\") and i + 1 < len(raw_lines):
            joined = joined[:-1] + " " + raw_lines[i + 1].strip()
            i += 1
        lines.append((first_lineno, joined.strip()))
        i += 1

    findings: List[DockerFinding] = []
    has_non_root_user = False

    for lineno, line in lines:
        if not line:
            continue

        # 1. FROM :latest or untagged
        if line.upper().startswith("FROM "):
            image = line.split()[1] if len(line.split()) > 1 else ""
            # AS alias handling
            image = image.split(" ")[0]
            if "@sha256:" in image:
                pass  # SHA-pinned is OK
            elif ":" not in image:
                findings.append(DockerFinding(
                    file=filepath, line=lineno, rule="from-latest",
                    description=f"Base image '{image}' has no tag (defaults to :latest)",
                    severity="high",
                ))
            elif image.endswith(":latest"):
                findings.append(DockerFinding(
                    file=filepath, line=lineno, rule="from-latest",
                    description=f"Base image '{image}' uses :latest tag",
                    severity="high",
                ))

        # 2. USER directive tracking
        if line.upper().startswith("USER "):
            user = line.split()[1] if len(line.split()) > 1 else ""
            if user.lower() not in ("root", "0"):
                has_non_root_user = True

        # 3. curl|bash patterns in RUN
        if line.upper().startswith("RUN "):
            cmd = line[4:]
            if re.search(r"\b(curl|wget)\b.*\|\s*(bash|sh|zsh)\b", cmd, re.IGNORECASE):
                findings.append(DockerFinding(
                    file=filepath, line=lineno, rule="curl-pipe-shell",
                    description="Piping remote script directly to shell — supply chain risk",
                    severity="critical",
                ))

            # 6. Privileged RUN
            if "--security=insecure" in cmd:
                findings.append(DockerFinding(
                    file=filepath, line=lineno, rule="privileged-run",
                    description="RUN with --security=insecure grants elevated privileges",
                    severity="high",
                ))

        # 4. Secrets in ENV/ARG
        if line.upper().startswith(("ENV ", "ARG ")):
            directive = line.split()[0].upper()
            rest = line[len(directive):].strip()
            # Parse name=value or name value
            if "=" in rest:
                name, _, value = rest.partition("=")
                name = name.strip()
                value = value.strip().strip("'\"")
            else:
                parts = rest.split(None, 1)
                name = parts[0] if parts else ""
                value = parts[1].strip().strip("'\"") if len(parts) > 1 else ""

            if SECRET_NAME_PATTERN.search(name) and value and value.lower() not in PLACEHOLDER_VALUES:
                findings.append(DockerFinding(
                    file=filepath, line=lineno, rule="secret-in-env",
                    description=f"Secret-looking value in {directive} {name}",
                    severity="critical",
                ))

        # 5. ADD from URL
        if line.upper().startswith("ADD "):
            parts = line.split()
            if len(parts) >= 2:
                src = parts[1]
                if src.startswith(("http://", "https://")):
                    findings.append(DockerFinding(
                        file=filepath, line=lineno, rule="add-from-url",
                        description="ADD from URL — use COPY + RUN curl instead for better caching and verification",
                        severity="high",
                    ))

        # 7. Expose 0.0.0.0
        if line.upper().startswith("EXPOSE "):
            if "0.0.0.0" in line:
                findings.append(DockerFinding(
                    file=filepath, line=lineno, rule="expose-all-interfaces",
                    description="EXPOSE binds to all interfaces (0.0.0.0)",
                    severity="medium",
                ))

    # 2b. Check for run-as-root (no non-root USER directive found)
    has_from = any(line.upper().startswith("FROM ") for _, line in lines)
    if has_from and not has_non_root_user:
        user_directives = [
            (ln, line) for ln, line in lines
            if line.upper().startswith("USER ")
        ]
        if not user_directives:
            findings.append(DockerFinding(
                file=filepath, line=1, rule="run-as-root",
                description="No USER directive — container runs as root",
                severity="high",
            ))
        else:
            for ul_lineno, ul_line in user_directives:
                user = ul_line.split()[1] if len(ul_line.split()) > 1 else ""
                if user.lower() in ("root", "0"):
                    findings.append(DockerFinding(
                        file=filepath, line=ul_lineno, rule="run-as-root",
                        description=f"USER set to '{user}' — container runs as root",
                        severity="high",
                    ))

    return findings


def find_dockerfiles(directory: str) -> List[str]:
    """Find Dockerfiles in a directory tree, skipping common non-project dirs."""
    root = Path(directory)
    results: List[str] = []

    for path in root.rglob("Dockerfile*"):
        # Skip if any parent directory is in the skip list
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file() and not path.is_symlink():
            results.append(str(path))

    return sorted(results)
