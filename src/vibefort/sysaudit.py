"""System audit — check if the machine shows signs of compromise."""

import os
import platform
import subprocess
from pathlib import Path
from dataclasses import dataclass


@dataclass
class AuditFinding:
    category: str  # "malicious-pth", "suspicious-cron", "backdoor-artifact", "compromised-package"
    description: str
    path: str
    severity: str  # "critical", "high", "medium"


def run_audit() -> list[AuditFinding]:
    """Run all system audit checks."""
    findings: list[AuditFinding] = []
    findings.extend(_check_pth_files())
    findings.extend(_check_backdoor_artifacts())
    findings.extend(_check_suspicious_processes())
    if platform.system() == "Darwin":
        findings.extend(_check_launch_agents())
    elif platform.system() == "Linux":
        findings.extend(_check_cron_jobs())
    return findings


def _check_pth_files() -> list[AuditFinding]:
    """Check Python site-packages for malicious .pth files."""
    findings = []

    # Find site-packages directories
    try:
        result = subprocess.run(
            ["python3", "-c", "import site; print('\\n'.join(site.getsitepackages()))"],
            capture_output=True, text=True, timeout=10,
        )
        site_dirs = [d.strip() for d in result.stdout.strip().splitlines() if d.strip()]
    except Exception:
        site_dirs = []

    # Also check user site-packages
    try:
        result = subprocess.run(
            ["python3", "-c", "import site; print(site.getusersitepackages())"],
            capture_output=True, text=True, timeout=10,
        )
        user_site = result.stdout.strip()
        if user_site:
            site_dirs.append(user_site)
    except Exception:
        pass

    suspicious_patterns = ["import ", "exec(", "os.system", "subprocess", "__import__", "eval("]

    for site_dir in site_dirs:
        site_path = Path(site_dir)
        if not site_path.exists():
            continue

        for pth_file in site_path.glob("*.pth"):
            try:
                content = pth_file.read_text(errors="ignore")
            except OSError:
                continue

            for pattern in suspicious_patterns:
                if pattern in content:
                    findings.append(AuditFinding(
                        category="malicious-pth",
                        description=f"Malicious .pth file — contains '{pattern.strip()}' (executes code every time Python starts)",
                        path=str(pth_file),
                        severity="critical",
                    ))
                    break

    return findings


def _check_backdoor_artifacts() -> list[AuditFinding]:
    """Check for known backdoor/malware artifacts on disk."""
    findings = []

    known_artifacts = [
        # Known malware artifacts from real supply chain attacks
        ("/tmp/tpcp.tar.gz", "Known credential-harvesting payload artifact"),
        ("/tmp/tpcp.sh", "Known credential-harvesting script"),
        ("/tmp/session.key", "Known session exfiltration artifact"),
        (os.path.expanduser("~/.config/sysmon"), "Known persistence directory for Python malware"),
        (os.path.expanduser("~/.config/autostart/sysmon.desktop"), "Known persistence autostart entry"),
        ("/tmp/.ICE-unix/.malware", "Known temp directory malware hiding spot"),
    ]

    for artifact_path, description in known_artifacts:
        if os.path.exists(artifact_path):
            findings.append(AuditFinding(
                category="backdoor-artifact",
                description=description,
                path=artifact_path,
                severity="critical",
            ))

    return findings


def _check_suspicious_processes() -> list[AuditFinding]:
    """Check for suspicious running processes."""
    findings = []

    suspicious_names = [
        "cryptominer", "xmrig", "minerd", "kdevtmpfsi",
        "kinsing", "dota", "sysrv",
    ]

    try:
        result = subprocess.run(
            ["ps", "aux"], capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.lower().splitlines():
            for name in suspicious_names:
                if name in line:
                    findings.append(AuditFinding(
                        category="suspicious-process",
                        description=f"Suspicious process running: matches known malware pattern '{name}'",
                        path=line.strip()[:100],
                        severity="high",
                    ))
                    break
    except Exception:
        pass

    return findings


def _check_launch_agents() -> list[AuditFinding]:
    """Check macOS LaunchAgents for suspicious entries."""
    findings = []

    launch_dirs = [
        Path.home() / "Library" / "LaunchAgents",
        Path("/Library/LaunchAgents"),
    ]

    suspicious_indicators = [
        "curl ", "wget ", "python -c", "bash -c", "base64",
        "/tmp/", "hidden", ".crypto", "miner",
    ]

    for launch_dir in launch_dirs:
        if not launch_dir.exists():
            continue
        for plist in launch_dir.glob("*.plist"):
            try:
                content = plist.read_text(errors="ignore").lower()
                for indicator in suspicious_indicators:
                    if indicator in content:
                        findings.append(AuditFinding(
                            category="suspicious-launchagent",
                            description=f"Suspicious LaunchAgent — contains '{indicator.strip()}'",
                            path=str(plist),
                            severity="high",
                        ))
                        break
            except OSError:
                continue

    return findings


def _check_cron_jobs() -> list[AuditFinding]:
    """Check cron jobs for suspicious entries (Linux)."""
    findings = []

    suspicious_indicators = [
        "curl ", "wget ", "python -c", "bash -c", "base64",
        "/tmp/", "cryptominer", "xmrig",
    ]

    try:
        result = subprocess.run(
            ["crontab", "-l"], capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.lower().splitlines():
            if line.startswith("#"):
                continue
            for indicator in suspicious_indicators:
                if indicator in line:
                    findings.append(AuditFinding(
                        category="suspicious-cron",
                        description=f"Suspicious cron job — contains '{indicator.strip()}'",
                        path=line.strip()[:100],
                        severity="high",
                    ))
                    break
    except Exception:
        pass

    return findings
