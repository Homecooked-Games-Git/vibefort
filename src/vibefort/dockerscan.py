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
    lines = content.splitlines()
    if not lines:
        return []

    findings: List[DockerFinding] = []
    has_non_root_user = False

    for lineno, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or _is_comment(raw_line):
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
    has_from = any(
        l.strip().upper().startswith("FROM ") and not _is_comment(l)
        for l in lines
    )
    if has_from and not has_non_root_user:
        # Check if there's a USER directive at all, or only root/0
        user_lines = [
            (i + 1, l.strip())
            for i, l in enumerate(lines)
            if l.strip().upper().startswith("USER ") and not _is_comment(l)
        ]
        if not user_lines:
            findings.append(DockerFinding(
                file=filepath, line=1, rule="run-as-root",
                description="No USER directive — container runs as root",
                severity="high",
            ))
        else:
            for ul_lineno, ul_line in user_lines:
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
        if path.is_file():
            results.append(str(path))

    return sorted(results)
