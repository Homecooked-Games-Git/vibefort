from pathlib import Path
from unittest.mock import patch
from vibefort.codescan import CodeFinding
from vibefort.autofix import suggest_fixes


def test_autofix_adds_env_to_gitignore(tmp_path):
    gitignore = tmp_path / ".gitignore"
    gitignore.write_text("*.pyc\n")

    findings = [CodeFinding(
        file=".env", line=0, rule="env-not-gitignored",
        description=".env not in .gitignore", severity="critical",
    )]

    with patch("vibefort.autofix.Confirm.ask", return_value=True):
        fixes = suggest_fixes(findings, tmp_path)

    assert fixes == 1
    assert ".env" in gitignore.read_text()


def test_autofix_creates_gitignore(tmp_path):
    findings = [CodeFinding(
        file=".env", line=0, rule="env-no-gitignore",
        description="no .gitignore", severity="critical",
    )]

    with patch("vibefort.autofix.Confirm.ask", return_value=True):
        fixes = suggest_fixes(findings, tmp_path)

    assert fixes == 1
    gitignore = tmp_path / ".gitignore"
    assert gitignore.exists()
    assert ".env" in gitignore.read_text()


def test_autofix_respects_decline(tmp_path):
    gitignore = tmp_path / ".gitignore"
    gitignore.write_text("*.pyc\n")

    findings = [CodeFinding(
        file=".env", line=0, rule="env-not-gitignored",
        description=".env not in .gitignore", severity="critical",
    )]

    with patch("vibefort.autofix.Confirm.ask", return_value=False):
        fixes = suggest_fixes(findings, tmp_path)

    assert fixes == 0
    assert ".env" not in gitignore.read_text()
