"""Tier 2 deep scan: static analysis of package contents."""

import json
import re
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path

import httpx

from vibefort.scanner import ScanResult

# Suspicious patterns in setup.py
SETUP_PY_PATTERNS = [
    (re.compile(r"\bsubprocess\b.*\b(call|run|Popen|check_output)\b", re.DOTALL), "subprocess execution"),
    (re.compile(r"\bos\.system\b"), "os.system call"),
    (re.compile(r"\bos\.popen\b"), "os.popen call"),
    (re.compile(r"\burllib\.request\.urlopen\b"), "network access in setup"),
    (re.compile(r"\brequests\.(get|post)\b"), "network access in setup"),
    (re.compile(r"\bcurl\b.*\bhttp"), "curl command"),
    (re.compile(r"\bwget\b.*\bhttp"), "wget command"),
    (re.compile(r"\beval\s*\("), "eval usage"),
    (re.compile(r"\bexec\s*\("), "exec usage"),
    (re.compile(r"\b__import__\s*\("), "dynamic import"),
    (re.compile(r"\bcompile\s*\(.*exec", re.DOTALL), "compile/exec"),
    (re.compile(r"socket\.socket"), "raw socket usage"),
]

# Obfuscation patterns
OBFUSCATION_PATTERNS = [
    (re.compile(r"\bbase64\.b64decode\b"), "base64 decoding"),
    (re.compile(r"\bcodecs\.decode\b.*rot_13", re.DOTALL), "ROT13 decoding"),
    (re.compile(r"\bexec\s*\(\s*base64"), "exec with base64"),
    (re.compile(r"\bexec\s*\(\s*codecs"), "exec with codecs"),
    (re.compile(r"\bexec\s*\(\s*bytes"), "exec with bytes"),
    (re.compile(r"\bexec\s*\(\s*compile"), "exec with compile"),
    (re.compile(r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){10,}"), "hex-encoded string"),
    (re.compile(r"\bchr\s*\(\s*\d+\s*\)(\s*\+\s*chr\s*\(\s*\d+\s*\)){5,}"), "chr() concatenation"),
    (re.compile(r"eval\s*\(\s*['\"].*['\"]"), "eval with string literal"),
    (re.compile(r"\blambda\b.*\bexec\b"), "lambda with exec"),
]

# Suspicious .pth file patterns
PTH_SUSPICIOUS = [
    (re.compile(r"\bimport\b"), "import statement in .pth"),
    (re.compile(r"\bexec\b"), "exec in .pth"),
    (re.compile(r"\bos\b"), "os module in .pth"),
    (re.compile(r"\bsubprocess\b"), "subprocess in .pth"),
    (re.compile(r"\bsocket\b"), "socket in .pth"),
    (re.compile(r"\burllib\b"), "urllib in .pth"),
]

# Suspicious npm script patterns
NPM_SCRIPT_PATTERNS = [
    (re.compile(r"\bcurl\b.*\|.*\b(bash|sh)\b"), "curl piped to shell"),
    (re.compile(r"\bwget\b.*\|.*\b(bash|sh)\b"), "wget piped to shell"),
    (re.compile(r"\bnode\b.*-e\b"), "inline node execution"),
    (re.compile(r"\beval\b"), "eval in script"),
    (re.compile(r"\bpowershell\b", re.IGNORECASE), "PowerShell execution"),
    (re.compile(r"\bhttp[s]?://(?!registry\.npmjs|github\.com)"), "non-standard URL"),
    (re.compile(r"\bchmod\b.*\+x"), "chmod +x in script"),
    (re.compile(r"\b/tmp/"), "temp directory access"),
    (re.compile(r"\benv\b.*\bDEBUG\b|\bNODE_ENV\b", re.IGNORECASE), None),  # benign, skip
]


def scan_setup_py(path: Path) -> dict | None:
    """Scan a setup.py file for suspicious patterns."""
    if not path.exists():
        return None

    content = path.read_text(errors="ignore")
    matches = []

    for pattern, description in SETUP_PY_PATTERNS:
        if pattern.search(content):
            matches.append(description)

    if matches:
        return {"file": str(path), "issues": matches}
    return None


def scan_package_json(path: Path) -> dict | None:
    """Scan a package.json for suspicious install scripts."""
    if not path.exists():
        return None

    try:
        data = json.loads(path.read_text(errors="ignore"))
    except json.JSONDecodeError:
        return None

    scripts = data.get("scripts", {})
    suspicious_hooks = ["preinstall", "postinstall", "preuninstall", "postuninstall",
                        "prepublish", "prepare"]

    matches = []
    for hook in suspicious_hooks:
        script_content = scripts.get(hook, "")
        if not script_content:
            continue
        for pattern, description in NPM_SCRIPT_PATTERNS:
            if description is None:
                continue
            if pattern.search(script_content):
                matches.append(f"{hook}: {description}")

    if matches:
        return {"file": str(path), "issues": matches}
    return None


def scan_for_pth_files(directory: Path) -> list[dict]:
    """Find malicious .pth files in a directory."""
    findings = []

    for pth_file in directory.rglob("*.pth"):
        content = pth_file.read_text(errors="ignore")
        matches = []
        for pattern, description in PTH_SUSPICIOUS:
            if pattern.search(content):
                matches.append(description)
        if matches:
            findings.append({"file": str(pth_file), "issues": matches})

    return findings


def scan_for_obfuscation(directory: Path) -> list[dict]:
    """Scan .py and .js files for obfuscated code."""
    findings = []
    extensions = {".py", ".js"}

    for filepath in directory.rglob("*"):
        if filepath.suffix not in extensions:
            continue
        if not filepath.is_file():
            continue

        try:
            content = filepath.read_text(errors="ignore")
        except OSError:
            continue

        matches = []
        for pattern, description in OBFUSCATION_PATTERNS:
            if pattern.search(content):
                matches.append(description)

        if matches:
            findings.append({"file": str(filepath), "issues": matches})

    return findings


def check_package_metadata(package: str, manager: str = "pip") -> dict | None:
    """Check PyPI or npm registry metadata for red flags."""
    try:
        if manager == "npm":
            url = f"https://registry.npmjs.org/{package}"
            resp = httpx.get(url, follow_redirects=True, timeout=15)
            resp.raise_for_status()
            data = resp.json()

            latest_version = data.get("dist-tags", {}).get("latest", "")
            versions = data.get("versions", {})
            version_count = len(versions)
            maintainers = data.get("maintainers", [])

            return {
                "name": package,
                "latest_version": latest_version,
                "version_count": version_count,
                "maintainer_count": len(maintainers),
            }
        else:
            url = f"https://pypi.org/pypi/{package}/json"
            resp = httpx.get(url, follow_redirects=True, timeout=15)
            resp.raise_for_status()
            data = resp.json()

            info = data.get("info", {})
            releases = data.get("releases", {})

            return {
                "name": package,
                "latest_version": info.get("version", ""),
                "version_count": len(releases),
                "author": info.get("author", ""),
                "home_page": info.get("home_page", ""),
                "project_urls": info.get("project_urls", {}),
            }
    except (httpx.HTTPError, json.JSONDecodeError):
        return None


def _extract(archive: Path, dest: Path) -> None:
    """Extract tar.gz, whl, zip, or tgz archive safely (no path traversal)."""
    name = archive.name.lower()

    if name.endswith(".tar.gz") or name.endswith(".tgz"):
        with tarfile.open(archive, "r:gz") as tar:
            # filter='data' prevents path traversal (CVE-2007-4559)
            tar.extractall(dest, filter="data")
    elif name.endswith(".whl") or name.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            # Validate all paths before extracting
            for member in zf.namelist():
                target = (dest / member).resolve()
                if not str(target).startswith(str(dest.resolve())):
                    raise ValueError(f"Zip path traversal detected: {member}")
            zf.extractall(dest)
    else:
        raise ValueError(f"Unsupported archive format: {archive.name}")


def download_and_scan(package: str, version: str | None = None,
                      manager: str = "pip") -> list[dict]:
    """Download a package to a temp directory, extract, and scan."""
    all_findings = []

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        download_dir = tmp_path / "download"
        extract_dir = tmp_path / "extract"
        download_dir.mkdir()
        extract_dir.mkdir()

        try:
            if manager == "npm":
                pkg_spec = f"{package}@{version}" if version else package
                subprocess.run(
                    ["npm", "pack", pkg_spec, "--pack-destination", str(download_dir)],
                    capture_output=True, text=True, check=True, timeout=60,
                )
            else:
                pkg_spec = f"{package}=={version}" if version else package
                subprocess.run(
                    ["pip", "download", "--no-deps", "--no-binary", ":all:",
                     "-d", str(download_dir), pkg_spec],
                    capture_output=True, text=True, check=True, timeout=60,
                )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return []

        # Extract archives
        for archive in download_dir.iterdir():
            try:
                _extract(archive, extract_dir)
            except (ValueError, tarfile.TarError, zipfile.BadZipFile):
                continue

        # Scan for setup.py
        for setup_py in extract_dir.rglob("setup.py"):
            result = scan_setup_py(setup_py)
            if result:
                all_findings.append(result)

        # Scan for package.json
        for pkg_json in extract_dir.rglob("package.json"):
            result = scan_package_json(pkg_json)
            if result:
                all_findings.append(result)

        # Scan for .pth files
        pth_findings = scan_for_pth_files(extract_dir)
        all_findings.extend(pth_findings)

        # Scan for obfuscation
        obfuscation_findings = scan_for_obfuscation(extract_dir)
        all_findings.extend(obfuscation_findings)

    return all_findings


def tier2_scan(package: str, version: str | None = None,
               manager: str = "pip") -> ScanResult:
    """Orchestrate all tier 2 checks."""
    findings = download_and_scan(package, version, manager)

    if findings:
        issues = []
        for f in findings:
            file_name = f.get("file", "unknown")
            file_issues = f.get("issues", [])
            issues.append(f"{file_name}: {', '.join(file_issues)}")

        details = "\n".join(issues)
        return ScanResult(
            safe=False,
            tier=2,
            reason="Suspicious patterns detected in package contents",
            details=details,
            suggestion="Review the flagged files before installing this package",
        )

    return ScanResult(
        safe=True,
        tier=2,
        reason="No suspicious patterns found in package contents",
    )
