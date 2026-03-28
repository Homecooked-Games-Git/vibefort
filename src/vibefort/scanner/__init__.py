"""Package scanning subsystem."""

from dataclasses import dataclass


@dataclass
class ScanResult:
    """Result of a package scan."""
    safe: bool
    tier: int
    reason: str = ""
    details: str = ""
    suggestion: str = ""
