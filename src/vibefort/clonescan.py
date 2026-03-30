"""Post-clone security scanner — checks for suspicious git hooks and typosquatted orgs."""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from vibefort.scanner.tier1 import _levenshtein_distance


@dataclass
class GitCloneFinding:
    rule: str
    description: str
    severity: str  # "critical", "high", "medium", "low"
    file: Optional[str] = None
    line: Optional[int] = None


# ── Known hook names ─────────────────────────────────────────────────────

KNOWN_HOOKS = {
    "pre-commit", "post-commit", "pre-push", "post-checkout",
    "post-merge", "pre-rebase", "post-rewrite", "prepare-commit-msg",
    "commit-msg", "pre-receive", "post-receive", "update",
}

# ── Dangerous patterns in git hooks ──────────────────────────────────────

HOOK_PATTERNS = [
    (re.compile(r'curl\b.*\|\s*(?:ba)?sh', re.IGNORECASE),
     "hook-curl-pipe-shell", "Suspicious hook: curl piped to shell", "critical"),
    (re.compile(r'wget\b.*\|\s*(?:ba)?sh', re.IGNORECASE),
     "hook-wget-pipe-shell", "Suspicious hook: wget piped to shell", "critical"),
    (re.compile(r'python3?\s+-c\b', re.IGNORECASE),
     "hook-python-inline", "Suspicious hook: inline Python execution", "high"),
    (re.compile(r'base64\b.*\b(?:decode|--decode|-d)\b', re.IGNORECASE),
     "hook-base64-decode", "Suspicious hook: base64 decode detected", "high"),
    (re.compile(r'\beval\b', re.IGNORECASE),
     "hook-eval", "Suspicious hook: eval usage detected", "high"),
    (re.compile(r'\b(?:nc|ncat)\b', re.IGNORECASE),
     "hook-netcat", "Suspicious hook: netcat usage detected", "critical"),
    (re.compile(r'\bimport\s+socket\b'),
     "hook-import-socket", "Suspicious hook: socket import detected", "high"),
    (re.compile(r'\bimport\s+subprocess\b'),
     "hook-import-subprocess", "Suspicious hook: subprocess import detected", "high"),
    (re.compile(r'/dev/tcp/', re.IGNORECASE),
     "hook-dev-tcp", "Suspicious hook: /dev/tcp/ network access", "critical"),
    (re.compile(r'rm\s+-rf\s+~/'),
     "hook-rm-rf-home", "Suspicious hook: recursive deletion of home directory", "critical"),
    (re.compile(r'chmod\s+777\b'),
     "hook-chmod-777", "Suspicious hook: chmod 777 detected", "high"),
]

# ── Known orgs for typosquat detection ───────────────────────────────────

KNOWN_ORGS = [
    "facebook", "google", "microsoft", "apple", "amazon", "netflix",
    "twitter", "github", "vercel", "hashicorp", "docker", "kubernetes",
    "nodejs", "python", "rust-lang", "golang", "angular", "vuejs",
    "reactjs", "tensorflow", "pytorch", "openai", "anthropic", "mozilla",
    "apache",
]


def check_git_hooks(repo_path: Path) -> List[GitCloneFinding]:
    """Scan .git/hooks/ for suspicious patterns."""
    repo_path = Path(repo_path)
    hooks_dir = repo_path / ".git" / "hooks"
    if not hooks_dir.is_dir():
        return []

    findings: List[GitCloneFinding] = []

    for hook_file in hooks_dir.iterdir():
        if not hook_file.is_file() or hook_file.is_symlink():
            continue
        # Skip .sample files
        if hook_file.name.endswith(".sample"):
            continue
        # Only check known hook names
        if hook_file.name not in KNOWN_HOOKS:
            continue

        try:
            content = hook_file.read_text(errors="replace")
        except (OSError, PermissionError):
            continue

        for pattern, rule, description, severity in HOOK_PATTERNS:
            for line_no, line in enumerate(content.splitlines(), 1):
                if pattern.search(line):
                    findings.append(GitCloneFinding(
                        rule=rule,
                        description=description,
                        severity=severity,
                        file=hook_file.name,
                        line=line_no,
                    ))
                    break  # one finding per pattern per hook

    return findings


def check_typosquatted_org(clone_url: str) -> List[GitCloneFinding]:
    """Check if a clone URL's org name is a typosquat of a known org."""
    org = _parse_org(clone_url)
    if org is None:
        return []

    org_lower = org.lower()

    # Exact match means it's the real org — no finding
    if org_lower in KNOWN_ORGS:
        return []

    for known in KNOWN_ORGS:
        dist = _levenshtein_distance(org_lower, known)
        if 1 <= dist <= 2:
            return [GitCloneFinding(
                rule="typosquatted-org",
                description=(
                    f"Possible typosquatted org '{org}' "
                    f"(similar to known org '{known}')"
                ),
                severity="high",
            )]

    return []


def _parse_org(url: str) -> Optional[str]:
    """Extract org/owner from a GitHub/GitLab clone URL."""
    # SSH shorthand: git@github.com:ORG/repo.git
    ssh_match = re.match(r'git@[^:]+:([^/]+)/', url)
    if ssh_match:
        return ssh_match.group(1)
    # HTTPS / SSH protocol / git protocol: https://github.com/ORG/repo.git
    # Also handles ssh://git@github.com/ORG/repo.git and git://github.com/ORG/repo.git
    # Strip optional port for ssh://git@github.com:2222/ORG/repo
    proto_match = re.match(r'(?:https?|ssh|git)://[^/]+/([^/]+)/', url)
    if proto_match:
        return proto_match.group(1)
    return None
