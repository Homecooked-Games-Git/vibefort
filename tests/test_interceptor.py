from vibefort.interceptor import parse_install_args


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
