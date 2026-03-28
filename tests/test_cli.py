from click.testing import CliRunner
from vibefort.cli import main


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "vibefort" in result.output.lower()


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    from vibefort import __version__
    assert __version__ in result.output


def test_cli_status_before_install(tmp_vibefort_home):
    runner = CliRunner()
    result = runner.invoke(main, ["status"])
    assert result.exit_code == 0
    assert "not installed" in result.output.lower() or "install" in result.output.lower()


def test_cli_scan_clean_project(tmp_path, tmp_vibefort_home, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "app.py").write_text('print("hello")\n')
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "no issues" in result.output.lower() or "0 issue" in result.output.lower()


def test_cli_scan_finds_issues(tmp_path, tmp_vibefort_home, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "app.py").write_text('import pickle\ndata = pickle.loads(user_input)\n')
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path)])
    assert "insecure" in result.output.lower() or "issue" in result.output.lower()


def test_cli_deps_clean(tmp_path, tmp_vibefort_home, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "requirements.txt").write_text("flask==3.1.0\nrequests==2.31.0\n")
    runner = CliRunner()
    result = runner.invoke(main, ["deps", str(tmp_path)])
    assert result.exit_code == 0


def test_cli_deps_finds_typosquat(tmp_path, tmp_vibefort_home, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "requirements.txt").write_text("reqeusts==2.28.0\n")
    runner = CliRunner()
    result = runner.invoke(main, ["deps", str(tmp_path)])
    assert "typosquat" in result.output.lower()


def test_cli_audit(tmp_vibefort_home):
    runner = CliRunner()
    result = runner.invoke(main, ["audit"])
    assert result.exit_code == 0


def test_cli_install_and_uninstall(tmp_vibefort_home, tmp_path, monkeypatch):
    rc_file = tmp_path / ".zshrc"
    rc_file.write_text("")
    monkeypatch.setattr("vibefort.installer.get_shell_rc_path", lambda: rc_file)
    monkeypatch.setattr("vibefort.cli.install_shell_hook", lambda: rc_file)
    monkeypatch.setattr("vibefort.cli.install_git_hook", lambda: None)
    monkeypatch.setattr("vibefort.cli.is_betterleaks_installed", lambda: True)

    runner = CliRunner()
    result = runner.invoke(main, ["install"])
    assert result.exit_code == 0
    assert "protecting" in result.output.lower() or "installed" in result.output.lower()
