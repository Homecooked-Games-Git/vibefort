"""Package scanning subsystem."""

from dataclasses import dataclass, field


@dataclass
class ScanResult:
    """Result of a package scan."""
    safe: bool
    tier: int
    reason: str = ""
    details: str = ""
    suggestion: str = ""
    evidence: list = field(default_factory=list)  # [{line, text, issue}, ...]
