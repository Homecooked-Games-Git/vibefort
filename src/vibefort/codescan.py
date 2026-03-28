"""Code vulnerability scanner — finds insecure patterns in project source files."""

import re
from pathlib import Path
from dataclasses import dataclass

# Safety limits
MAX_SCAN_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


@dataclass
class CodeFinding:
    file: str
    line: int
    rule: str
    description: str
    severity: str  # "critical", "high", "medium", "low"


# Patterns to scan for, grouped by language
PYTHON_PATTERNS = [
    # SQL Injection
    (re.compile(r'(?:execute|cursor\.execute)\s*\(\s*f["\']', re.MULTILINE),
     "sql-injection", "SQL injection — f-string in database query", "critical"),
    (re.compile(r'(?:execute|cursor\.execute)\s*\(\s*["\'].*%s', re.MULTILINE),
     "sql-injection", "SQL injection — string formatting in database query", "critical"),
    (re.compile(r'(?:execute|cursor\.execute)\s*\(\s*.*\+\s*', re.MULTILINE),
     "sql-injection", "SQL injection — string concatenation in database query", "high"),
    # Insecure deserialization
    (re.compile(r'\bpickle\.loads?\b', re.MULTILINE),
     "insecure-deserialize", "Insecure deserialization — pickle.load can execute arbitrary code", "critical"),
    (re.compile(r'\byaml\.load\s*\([^)]*(?!Loader)', re.MULTILINE),
     "insecure-deserialize", "Insecure YAML loading — use yaml.safe_load instead", "high"),
    (re.compile(r'\beval\s*\(\s*(?:request|input|sys\.argv|os\.environ)', re.MULTILINE),
     "code-injection", "Code injection — eval() on user input", "critical"),
    (re.compile(r'\bexec\s*\(\s*(?:request|input)', re.MULTILINE),
     "code-injection", "Code injection — exec() on user input", "critical"),
    # Subprocess with shell=True
    (re.compile(r'subprocess\.\w+\([^)]*shell\s*=\s*True', re.DOTALL),
     "command-injection", "Command injection risk — subprocess with shell=True", "high"),
    (re.compile(r'\bos\.system\s*\(', re.MULTILINE),
     "command-injection", "Command injection risk — os.system() executes shell commands", "high"),
    (re.compile(r'\bos\.popen\s*\(', re.MULTILINE),
     "command-injection", "Command injection risk — os.popen() executes shell commands", "high"),
    # Debug mode
    (re.compile(r'\bDEBUG\s*=\s*True\b', re.MULTILINE),
     "debug-mode", "Debug mode enabled — should be False in production", "medium"),
    (re.compile(r'app\.run\([^)]*debug\s*=\s*True', re.DOTALL),
     "debug-mode", "Flask debug mode enabled in app.run()", "medium"),
    # Insecure randomness
    (re.compile(r'\brandom\.\w+\s*\(', re.MULTILINE),
     "weak-random", "Weak randomness — use secrets module for tokens/keys", "medium"),
    # Hardcoded passwords
    (re.compile(r'(?:password|passwd|pwd)\s*=\s*["\'][^"\']{3,}["\']', re.IGNORECASE | re.MULTILINE),
     "hardcoded-password", "Hardcoded password in source code", "high"),
    # CORS misconfiguration
    (re.compile(r'Access-Control-Allow-Origin.*\*', re.MULTILINE),
     "cors-wildcard", "CORS wildcard — allows any origin", "medium"),
    (re.compile(r'CORS\s*\(\s*app\s*\)', re.MULTILINE),
     "cors-wildcard", "CORS enabled without origin restrictions", "medium"),
]

JS_PATTERNS = [
    # XSS
    (re.compile(r'\.innerHTML\s*=', re.MULTILINE),
     "xss", "XSS risk — innerHTML assignment with potentially unsafe content", "high"),
    (re.compile(r'document\.write\s*\(', re.MULTILINE),
     "xss", "XSS risk — document.write() with potentially unsafe content", "high"),
    (re.compile(r'dangerouslySetInnerHTML', re.MULTILINE),
     "xss", "XSS risk — dangerouslySetInnerHTML in React", "medium"),
    # eval
    (re.compile(r'\beval\s*\(', re.MULTILINE),
     "code-injection", "Code injection risk — eval() can execute arbitrary code", "high"),
    # SQL injection (Node.js)
    (re.compile(r'\.query\s*\(\s*`', re.MULTILINE),
     "sql-injection", "SQL injection — template literal in database query", "critical"),
    (re.compile(r'\.query\s*\(\s*["\'].*\+', re.MULTILINE),
     "sql-injection", "SQL injection — string concatenation in database query", "high"),
    # CORS
    (re.compile(r'Access-Control-Allow-Origin.*\*', re.MULTILINE),
     "cors-wildcard", "CORS wildcard — allows any origin", "medium"),
    (re.compile(r"origin:\s*['\"]?\*['\"]?", re.MULTILINE),
     "cors-wildcard", "CORS wildcard in configuration", "medium"),
]

# Secret detection in .env files is handled by betterleaks (234 rules).
# codescan only checks the structural issue: .env not in .gitignore.

# File extensions to scan for code patterns (secrets handled by betterleaks)
SCAN_EXTENSIONS = {
    ".py": PYTHON_PATTERNS,
    ".js": JS_PATTERNS,
    ".jsx": JS_PATTERNS,
    ".ts": JS_PATTERNS,
    ".tsx": JS_PATTERNS,
}

# Directories to skip
SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
    ".next", ".nuxt", "vendor", ".cargo", "target",
}


def scan_directory(directory: str | Path) -> list[CodeFinding]:
    """Scan a directory recursively for insecure code patterns."""
    root = Path(directory).resolve()
    findings: list[CodeFinding] = []

    for filepath in root.rglob("*"):
        # Skip directories in SKIP_DIRS
        if any(part in SKIP_DIRS for part in filepath.parts):
            continue

        # Skip symlinks
        if filepath.is_symlink():
            continue

        # Check .env structural issue (content scanning handled by betterleaks)
        if filepath.name == ".env":
            gitignore = root / ".gitignore"
            if gitignore.exists():
                gi_content = gitignore.read_text(errors="ignore")
                if ".env" not in gi_content:
                    findings.append(CodeFinding(
                        file=str(filepath.relative_to(root)),
                        line=0,
                        rule="env-not-gitignored",
                        description=".env file exists but is not in .gitignore — secrets may be committed",
                        severity="critical",
                    ))
            else:
                findings.append(CodeFinding(
                    file=str(filepath.relative_to(root)),
                    line=0,
                    rule="env-no-gitignore",
                    description=".env file exists but no .gitignore found — secrets will be committed",
                    severity="critical",
                ))
            continue

        if filepath.suffix in SCAN_EXTENSIONS:
            patterns = SCAN_EXTENSIONS[filepath.suffix]
        else:
            continue

        if not filepath.is_file():
            continue

        # Size limit
        if filepath.stat().st_size > MAX_SCAN_FILE_SIZE:
            continue

        try:
            content = filepath.read_text(errors="ignore")
        except OSError:
            continue

        for line_num, line_text in enumerate(content.splitlines(), 1):
            for pattern, rule, description, severity in patterns:
                if pattern.search(line_text):
                    findings.append(CodeFinding(
                        file=str(filepath.relative_to(root)),
                        line=line_num,
                        rule=rule,
                        description=description,
                        severity=severity,
                    ))
                    break  # One finding per line

    return findings
