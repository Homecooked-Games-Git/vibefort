"""Tier 3: AI-powered analysis of suspicious code."""

from vibefort.scanner import ScanResult
from vibefort.ai.base import AnalysisResult


def tier3_scan(package: str, suspicious_code: str, *, provider=None, context: str = "") -> ScanResult:
    if provider is None or not provider.is_configured():
        return ScanResult(
            safe=True,
            tier=3,
            reason="AI analysis unavailable — no provider configured",
        )

    try:
        result: AnalysisResult = provider.analyze_package(package, suspicious_code, context)
    except Exception as e:
        return ScanResult(safe=True, tier=3, reason=f"AI analysis failed: {e}")

    is_dangerous = result.risk_level in ("critical", "high")

    return ScanResult(
        safe=not is_dangerous,
        tier=3,
        reason=f"AI risk assessment: {result.risk_level}",
        details=result.explanation,
        suggestion=result.safe_alternative or result.remediation,
    )
