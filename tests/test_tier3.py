from unittest.mock import MagicMock
from vibefort.scanner.tier3 import tier3_scan
from vibefort.ai.base import AnalysisResult


def test_tier3_no_provider():
    result = tier3_scan("evil-pkg", "import os; os.system('bad')", provider=None)
    assert result.tier == 3
    assert result.safe is True


def test_tier3_with_provider():
    mock = MagicMock()
    mock.is_configured.return_value = True
    mock.analyze_package.return_value = AnalysisResult(
        explanation="Downloads and executes a remote payload",
        risk_level="critical",
        remediation="Remove this package",
        safe_alternative="safe-pkg v1.0",
    )

    result = tier3_scan("evil-pkg", "import os; os.system('bad')", provider=mock)
    assert result.safe is False
    assert result.tier == 3
    assert "payload" in result.details.lower()
