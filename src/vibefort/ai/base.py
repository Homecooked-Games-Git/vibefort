"""Base AI provider protocol."""

from dataclasses import dataclass
from typing import Protocol


@dataclass
class AnalysisResult:
    """Result from AI analysis."""
    explanation: str
    risk_level: str  # "critical", "high", "medium", "low", "safe"
    remediation: str = ""
    safe_alternative: str = ""


class AIProvider(Protocol):
    """Protocol for AI analysis providers."""

    def is_configured(self) -> bool: ...
    def analyze_package(self, package_name: str, suspicious_code: str, context: str = "") -> AnalysisResult: ...
    def analyze_code(self, code: str, filename: str = "") -> AnalysisResult: ...
