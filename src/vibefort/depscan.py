"""Dependency auditor — scan all project dependencies for issues."""

import hashlib
import re
from pathlib import Path
from dataclasses import dataclass

from vibefort.scanner.tier1 import tier1_scan, is_known_safe
from vibefort.scanner.cve import check_cve_pip, check_cve_npm
from vibefort.allowlist import is_package_allowed


@dataclass
class DepFinding:
    package: str
    version: str
    source: str  # "requirements.txt", "package.json", etc.
    issue: str
    severity: str  # "critical", "high", "medium", "low", "ok"


def parse_requirements_txt(path: Path) -> list[tuple[str, str]]:
    """Parse requirements.txt, return list of (name, version) tuples."""
    deps = []
    for line in path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Handle name==version, name>=version, name
        match = re.match(r'^([a-zA-Z0-9_.-]+)\s*(?:[=!<>~]=?\s*(.+?))?$', line)
        if match:
            name = match.group(1)
            version = match.group(2) or ""
            # Clean version specifiers
            version = version.strip().lstrip("=<>!~")
            deps.append((name, version))
    return deps


def parse_pyproject_toml(path: Path) -> list[tuple[str, str]]:
    """Parse pyproject.toml dependencies."""
    import toml
    try:
        data = toml.load(path)
    except Exception:
        return []

    deps = []
    # PEP 621 dependencies
    for dep_str in data.get("project", {}).get("dependencies", []):
        match = re.match(r'^([a-zA-Z0-9_.-]+)\s*(?:[=!<>~]=?\s*(.+?))?$', dep_str)
        if match:
            deps.append((match.group(1), (match.group(2) or "").strip().lstrip("=<>!~")))
    return deps


def parse_package_json(path: Path) -> list[tuple[str, str]]:
    """Parse package.json dependencies."""
    import json
    try:
        data = json.loads(path.read_text(errors="ignore"))
    except Exception:
        return []

    deps = []
    for section in ["dependencies", "devDependencies"]:
        for name, version in data.get(section, {}).items():
            # Strip version prefixes (^, ~, >=, etc.)
            clean_version = re.sub(r'^[\^~>=<]+', '', version)
            deps.append((name, clean_version))
    return deps


def parse_pipfile(path: Path) -> list[tuple[str, str]]:
    """Parse Pipfile dependencies."""
    import toml
    try:
        data = toml.load(path)
    except Exception:
        return []

    deps = []
    for section in ["packages", "dev-packages"]:
        for name, spec in data.get(section, {}).items():
            version = ""
            if isinstance(spec, str) and spec != "*":
                version = spec.lstrip("=<>!~^")
            deps.append((name, version))
    return deps


# Map file names to parsers and ecosystems
DEP_FILES = {
    "requirements.txt": (parse_requirements_txt, "pip"),
    "requirements-dev.txt": (parse_requirements_txt, "pip"),
    "requirements_dev.txt": (parse_requirements_txt, "pip"),
    "pyproject.toml": (parse_pyproject_toml, "pip"),
    "Pipfile": (parse_pipfile, "pip"),
    "package.json": (parse_package_json, "npm"),
}


def verify_package_lock(path: Path) -> list[DepFinding]:
    """Verify package-lock.json integrity — check that resolved URLs use HTTPS and hashes are present."""
    import json
    findings = []
    try:
        data = json.loads(path.read_text(errors="ignore"))
    except Exception:
        return []

    packages = data.get("packages", {})
    for pkg_path, info in packages.items():
        if not pkg_path:  # Root package
            continue
        name = pkg_path.replace("node_modules/", "")
        resolved = info.get("resolved", "")
        integrity = info.get("integrity", "")

        # Check for HTTP (not HTTPS) registry URLs
        if resolved and resolved.startswith("http://"):
            findings.append(DepFinding(
                package=name,
                version=info.get("version", ""),
                source="package-lock.json",
                issue="Resolved URL uses HTTP instead of HTTPS — vulnerable to MITM",
                severity="high",
            ))

        # Check for missing integrity hash
        if resolved and not integrity:
            findings.append(DepFinding(
                package=name,
                version=info.get("version", ""),
                source="package-lock.json",
                issue="Missing integrity hash — package cannot be verified",
                severity="medium",
            ))

        # Check for non-registry URLs (git, file, etc.)
        if resolved and not resolved.startswith("https://registry.npmjs.org"):
            if resolved.startswith("git") or resolved.startswith("file:"):
                findings.append(DepFinding(
                    package=name,
                    version=info.get("version", ""),
                    source="package-lock.json",
                    issue=f"Non-registry source: {resolved[:80]}",
                    severity="medium",
                ))

    return findings


def verify_poetry_lock(path: Path) -> list[DepFinding]:
    """Verify poetry.lock integrity — check that hashes are present and packages are from PyPI."""
    import toml
    findings = []
    try:
        data = toml.load(path)
    except Exception:
        return []

    for pkg in data.get("package", []):
        name = pkg.get("name", "")
        version = pkg.get("version", "")
        source = pkg.get("source", {})

        # Check for non-PyPI sources
        if source and source.get("type") != "legacy":
            src_url = source.get("url", "")
            if src_url and "pypi.org" not in src_url:
                findings.append(DepFinding(
                    package=name,
                    version=version,
                    source="poetry.lock",
                    issue=f"Non-PyPI source: {src_url[:80]}",
                    severity="medium",
                ))

        # Check for missing file hashes
        files = pkg.get("files", [])
        if not files:
            findings.append(DepFinding(
                package=name,
                version=version,
                source="poetry.lock",
                issue="Missing file hashes — package cannot be verified",
                severity="medium",
            ))

    return findings


def scan_dependencies(directory: str | Path) -> list[DepFinding]:
    """Scan all dependency files in a directory."""
    root = Path(directory).resolve()
    findings: list[DepFinding] = []

    for filename, (parser, ecosystem) in DEP_FILES.items():
        dep_file = root / filename
        if not dep_file.exists():
            continue

        deps = parser(dep_file)

        for name, version in deps:
            if is_package_allowed(name):
                continue

            # Tier 1 checks (typosquat, existence)
            result = tier1_scan(name, manager=ecosystem)
            if not result.safe:
                findings.append(DepFinding(
                    package=name,
                    version=version,
                    source=filename,
                    issue=result.reason,
                    severity="critical",
                ))
                continue

            # CVE check
            if version:
                cve_fn = check_cve_pip if ecosystem == "pip" else check_cve_npm
                try:
                    cves = cve_fn(name, version)
                    for cve in cves:
                        fixed = cve.get("fixed_version", "")
                        fixed_str = f" (fix: upgrade to {fixed})" if fixed else ""
                        findings.append(DepFinding(
                            package=name,
                            version=version,
                            source=filename,
                            issue=f"{cve['id']}: {cve['summary']}{fixed_str}",
                            severity="high",
                        ))
                except Exception:
                    pass

    # Lock file integrity checks
    lock_files = {
        "package-lock.json": verify_package_lock,
        "poetry.lock": verify_poetry_lock,
    }
    for filename, verifier in lock_files.items():
        lock_path = root / filename
        if lock_path.exists():
            findings.extend(verifier(lock_path))

    return findings
