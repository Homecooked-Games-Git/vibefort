"""Package install interception — the core scanning flow."""

import subprocess
import sys
import time
from pathlib import Path

from vibefort.config import load_config, save_config
from vibefort.scanner import ScanResult
from vibefort.scanner.tier1 import tier1_scan, is_known_safe
from vibefort.scanner.tier2 import tier2_scan
from vibefort.allowlist import is_package_allowed
from vibefort.display import show_safe, show_blocked

# Map each manager to its registry type for scanning
MANAGER_REGISTRY = {
    "pip": "pip",
    "pipx": "pip",
    "uv": "pip",
    "poetry": "pip",
    "pdm": "pip",
    "npm": "npm",
    "npx": "npm",
    "yarn": "npm",
    "pnpm": "npm",
    "bun": "npm",
    "bunx": "npm",
}


def get_registry(manager: str) -> str:
    """Get the registry type (pip or npm) for a given package manager."""
    return MANAGER_REGISTRY.get(manager, "pip")


def parse_install_args(args: list[str], manager: str = "pip") -> list[tuple[str, str]]:
    """Extract package names and versions from any supported package manager.

    Returns list of (package_name, version) tuples.
    """
    if not args:
        return []

    # --- npx / bunx: no "install" subcommand, first non-flag arg is the package ---
    if manager in ("npx", "bunx"):
        return _parse_exec_args(args)

    # --- uv: handle "uv pip install X" and "uv add X" ---
    if manager == "uv":
        return _parse_uv_args(args)

    # --- pipx: "pipx install X" / "pipx run X" ---
    if manager == "pipx":
        if args[0] not in ("install", "run"):
            return []
        return _parse_pip_packages(args[1:])

    # --- poetry: "poetry add X" ---
    if manager == "poetry":
        if args[0] != "add":
            return []
        return _parse_pip_packages(args[1:])

    # --- pdm: "pdm add X" ---
    if manager == "pdm":
        if args[0] != "add":
            return []
        return _parse_pip_packages(args[1:])

    # --- npm / yarn / pnpm / bun: "install", "add", "i" ---
    if manager in ("npm", "yarn", "pnpm", "bun"):
        install_cmds = {"install", "add", "i"}
        if args[0] not in install_cmds:
            return []
        return _parse_npm_packages(args[1:])

    # --- pip / pip3: "install" ---
    if args[0] != "install":
        return []
    return _parse_pip_packages(args[1:])


def _parse_exec_args(args: list[str]) -> list[tuple[str, str]]:
    """Parse npx/bunx args — first non-flag arg is the package to execute."""
    for arg in args:
        if arg.startswith("-"):
            continue
        # npx create-react-app@5.0.0
        if "@" in arg and not arg.startswith("@"):
            name, version = arg.rsplit("@", 1)
            return [(name.strip(), version.strip())]
        elif arg.startswith("@") and arg.count("@") == 2:
            name, version = arg.rsplit("@", 1)
            return [(name.strip(), version.strip())]
        else:
            return [(arg.strip(), "")]
    return []


def _parse_uv_args(args: list[str]) -> list[tuple[str, str]]:
    """Parse uv args — handles 'uv pip install X' and 'uv add X'."""
    if not args:
        return []

    if args[0] == "pip" and len(args) > 1 and args[1] == "install":
        return _parse_pip_packages(args[2:])
    elif args[0] == "add":
        return _parse_pip_packages(args[1:])
    return []


def _parse_pip_packages(args: list[str]) -> list[tuple[str, str]]:
    """Parse pip-style package arguments."""
    packages = []
    skip_next = False
    skip_flags = {"-r", "--requirement", "-c", "--constraint", "-e", "--editable",
                  "-t", "--target", "--prefix", "-i", "--index-url",
                  "--extra-index-url", "-f", "--find-links"}

    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg in skip_flags:
            skip_next = True
            continue
        if arg.startswith("-"):
            continue
        # Local paths: mark with "local:" prefix so interceptor can scan the directory
        if arg.startswith(".") or arg.startswith("/") or arg.startswith("~"):
            packages.append((f"local:{arg}", ""))
            continue

        if "==" in arg:
            name, version = arg.split("==", 1)
            packages.append((name.strip(), version.strip()))
        elif ">=" in arg or "<=" in arg or "~=" in arg or "!=" in arg:
            name = arg.split(">")[0].split("<")[0].split("~")[0].split("!")[0]
            packages.append((name.strip(), ""))
        else:
            packages.append((arg.strip(), ""))

    return packages


def _parse_npm_packages(args: list[str]) -> list[tuple[str, str]]:
    """Parse npm-style package arguments (npm, yarn, pnpm, bun)."""
    packages = []
    skip_next = False
    skip_flags = {"--registry", "--save-prefix"}

    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg in skip_flags:
            skip_next = True
            continue
        if arg.startswith("-"):
            continue
        if arg.startswith(".") or arg.startswith("/"):
            continue

        if "@" in arg and not arg.startswith("@"):
            name, version = arg.rsplit("@", 1)
            packages.append((name.strip(), version.strip()))
        elif arg.startswith("@") and arg.count("@") == 2:
            name, version = arg.rsplit("@", 1)
            packages.append((name.strip(), version.strip()))
        else:
            packages.append((arg.strip(), ""))

    return packages


ALLOWED_MANAGERS = frozenset(MANAGER_REGISTRY.keys())


def run_intercept(manager: str, args: list[str]) -> int:
    """Main interception flow. Returns exit code (0 = proceed, 1 = blocked)."""
    if manager not in ALLOWED_MANAGERS:
        print(f"vibefort: unknown package manager '{manager}'", file=sys.stderr)
        return 1

    packages = parse_install_args(list(args), manager=manager)
    registry = get_registry(manager)

    if not packages:
        # Not an install command or no packages — pass through
        return _passthrough(manager, args)

    config = load_config()
    blocked = False

    for name, version in packages:
        start = time.time()

        # Local path install — scan directory directly with tier 2
        if name.startswith("local:"):
            local_path = Path(name[6:]).expanduser().resolve()
            display_name = str(local_path)
            if local_path.exists():
                result = _scan_local_path(local_path)
                if not result.safe:
                    show_blocked(display_name, result.reason, result.suggestion, evidence=result.evidence)
                    blocked = True
                    config.packages_blocked += 1
                    continue
            elapsed = f"{time.time() - start:.1f}s"
            show_safe(display_name, "", elapsed)
            continue

        # Allowlisted — skip scanning entirely
        if is_package_allowed(name):
            elapsed = f"{time.time() - start:.1f}s"
            show_safe(name, version, elapsed)
            continue

        # Tier 1: Fast checks
        result = tier1_scan(name, manager=registry)

        if not result.safe:
            # Tier 1 flagged it — block immediately
            show_blocked(name, result.reason, result.suggestion)
            blocked = True
            config.packages_blocked += 1
            continue

        if is_known_safe(name, registry):
            # In the top 10k packages — skip deeper checks
            elapsed = f"{time.time() - start:.1f}s"
            show_safe(name, version, elapsed)
            _check_and_warn_cve(name, version, registry)
            continue

        # Tier 2: Deep scan (only for unknown packages)
        result = tier2_scan(name, version, manager=registry)

        if not result.safe:
            show_blocked(name, result.reason, result.suggestion)
            if result.details:
                from rich.console import Console
                Console().print(f"  [dim]{result.details}[/dim]")
            blocked = True
            config.packages_blocked += 1
            continue

        elapsed = f"{time.time() - start:.1f}s"
        show_safe(name, version, elapsed)
        _check_and_warn_cve(name, version, registry)

    config.packages_scanned += len(packages)
    save_config(config)

    if blocked:
        return 1

    # All clean — run the actual command
    return _passthrough(manager, args)


def _scan_local_path(local_path: Path) -> ScanResult:
    """Scan a local package directory for suspicious patterns."""
    from vibefort.scanner.tier2 import scan_setup_py, scan_package_json, scan_for_pth_files, scan_for_obfuscation

    all_issues = []

    all_evidence = []

    # Scan setup.py
    setup_py = local_path / "setup.py"
    if setup_py.exists():
        result = scan_setup_py(setup_py)
        if result:
            issues = result.get("issues", [])
            all_issues.extend(f"setup.py: {i}" for i in issues)
            all_evidence.extend(result.get("evidence", []))

    # Scan package.json
    pkg_json = local_path / "package.json"
    if pkg_json.exists():
        result = scan_package_json(pkg_json)
        if result:
            issues = result.get("issues", [])
            all_issues.extend(f"package.json: {i}" for i in issues)

    # Scan .pth files
    for finding in scan_for_pth_files(local_path):
        issues = finding.get("issues", [])
        all_issues.extend(f".pth: {i}" for i in issues)
        all_evidence.extend(finding.get("evidence", []))

    # Scan for obfuscated code
    for finding in scan_for_obfuscation(local_path):
        issues = finding.get("issues", [])
        fname = Path(finding.get("file", "")).name
        all_issues.extend(f"{fname}: {i}" for i in issues)
        all_evidence.extend(finding.get("evidence", []))

    if all_issues:
        return ScanResult(
            safe=False,
            tier=2,
            reason="; ".join(all_issues),
            evidence=all_evidence,
        )

    return ScanResult(safe=True, tier=2)




def _check_and_warn_cve(name: str, version: str, registry: str):
    """Check for known CVEs and print warnings (non-blocking)."""
    if not version:
        return
    from vibefort.scanner.cve import check_cve_pip, check_cve_npm
    from rich.console import Console
    from rich.markup import escape

    cve_check = check_cve_pip if registry == "pip" else check_cve_npm
    try:
        cves = cve_check(name, version)
    except Exception:
        return

    if not cves:
        return

    c = Console()
    for cve in cves[:3]:
        cve_id = cve.get("id", "")
        summary = cve.get("summary", "")
        fixed = cve.get("fixed_version", "")
        fixed_str = f" — fixed in {escape(fixed)}" if fixed else ""
        c.print(f"  [yellow]⚠ {escape(cve_id)}[/yellow]: {escape(summary)}{fixed_str}")


def _passthrough(manager: str, args: list[str]) -> int:
    """Execute the original package manager command."""
    cmd = [manager] + list(args)
    result = subprocess.run(cmd)
    return result.returncode
