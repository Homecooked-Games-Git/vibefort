"""Tier 1 fast checks: known-safe lookup, typosquatting detection, existence check."""

from pathlib import Path

import httpx

from vibefort.scanner import ScanResult

ASSETS_DIR = Path(__file__).parent.parent / "assets"

_top_packages_cache: dict[str, set[str]] = {}


def _load_top_packages(manager: str = "pip") -> set[str]:
    if manager in _top_packages_cache:
        return _top_packages_cache[manager]

    filename = "top_pypi_packages.txt" if manager == "pip" else "top_npm_packages.txt"
    filepath = ASSETS_DIR / filename

    packages: set[str] = set()
    if filepath.exists():
        for line in filepath.read_text().splitlines():
            stripped = line.strip().lower()
            if stripped:
                packages.add(stripped)

    _top_packages_cache[manager] = packages
    return packages


def is_known_safe(package: str, manager: str = "pip") -> bool:
    """Check if a package is in the known-safe list."""
    top = _load_top_packages(manager)
    return package.strip().lower() in top


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Compute Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row

    return prev_row[-1]


_SUBSTITUTION_MAP = {
    "0": "o",
    "1": "l",
    "l": "1",
    "o": "0",
    "-": "_",
    "_": "-",
}


def check_typosquatting(package: str, manager: str = "pip") -> dict | None:
    """Check if a package name is suspiciously close to a known-safe package."""
    pkg_lower = package.strip().lower()
    top = _load_top_packages(manager)

    if pkg_lower in top:
        return None

    # Check Levenshtein distance of 1-2 (catches transpositions)
    for known in top:
        if abs(len(known) - len(pkg_lower)) > 2:
            continue
        dist = _levenshtein_distance(pkg_lower, known)
        if dist == 1:
            return {"similar_to": known, "distance": dist, "type": "levenshtein"}
        if dist == 2 and len(pkg_lower) == len(known):
            # Check if it's a character transposition
            diffs = [i for i in range(len(pkg_lower)) if pkg_lower[i] != known[i]]
            if len(diffs) == 2 and pkg_lower[diffs[0]] == known[diffs[1]] and pkg_lower[diffs[1]] == known[diffs[0]]:
                return {"similar_to": known, "distance": dist, "type": "transposition"}

    # Check substitution attacks (e.g., 0 for o, 1 for l, - for _)
    normalized = pkg_lower
    for old, new in _SUBSTITUTION_MAP.items():
        normalized = normalized.replace(old, new)

    if normalized != pkg_lower and normalized in top:
        return {"similar_to": normalized, "distance": 0, "type": "substitution"}

    return None


def check_package_exists(package: str, manager: str = "pip") -> bool:
    """Check if a package exists on the registry."""
    if manager == "npm":
        url = f"https://registry.npmjs.org/{package}"
    else:
        url = f"https://pypi.org/pypi/{package}/json"

    try:
        resp = httpx.head(url, follow_redirects=True, timeout=10)
        return resp.status_code == 200
    except httpx.HTTPError:
        return False


def tier1_scan(package: str, *, manager: str = "pip") -> ScanResult:
    """Run all tier 1 checks and return a ScanResult."""
    pkg_lower = package.strip().lower()

    # Check typosquatting first
    typo = check_typosquatting(pkg_lower, manager)
    if typo:
        return ScanResult(
            safe=False,
            tier=1,
            reason=f"Possible typosquat: similar to '{typo['similar_to']}' ({typo['type']})",
            details=f"Package '{pkg_lower}' is suspiciously similar to known package '{typo['similar_to']}'",
            suggestion=f"Did you mean '{typo['similar_to']}'?",
        )

    # Check if known safe
    if is_known_safe(pkg_lower, manager):
        return ScanResult(
            safe=True,
            tier=1,
            reason="Known safe package",
        )

    # Check if package exists on the registry (slopsquatting detection)
    if not check_package_exists(pkg_lower, manager):
        registry = "npm" if manager == "npm" else "PyPI"
        return ScanResult(
            safe=False,
            tier=1,
            reason=f"Package does not exist on {registry}",
            suggestion="This may be a hallucinated package name from an AI tool (slopsquatting)",
        )

    # Unknown package — passed basic checks, needs tier 2
    return ScanResult(
        safe=True,
        tier=1,
        reason="Package not in known-safe list, but no typosquatting detected",
    )
