from click.testing import CliRunner
from vibefort.cli import main


def test_update_command():
    runner = CliRunner()
    result = runner.invoke(main, ["update"])
    assert result.exit_code == 0
    assert "version" in result.output.lower() or "up to date" in result.output.lower()


def test_config_show_all(tmp_vibefort_home):
    runner = CliRunner()
    result = runner.invoke(main, ["config"])
    assert result.exit_code == 0
    assert "shell_hook_installed" in result.output


def test_config_show_one(tmp_vibefort_home):
    runner = CliRunner()
    result = runner.invoke(main, ["config", "packages_scanned"])
    assert result.exit_code == 0
    assert "0" in result.output


def test_config_set_value(tmp_vibefort_home):
    runner = CliRunner()
    result = runner.invoke(main, ["config", "packages_scanned", "42"])
    assert result.exit_code == 0
    assert "42" in result.output


def test_config_unknown_key(tmp_vibefort_home):
    runner = CliRunner()
    result = runner.invoke(main, ["config", "nonexistent"])
    assert "unknown" in result.output.lower() or "Unknown" in result.output


def test_completions_zsh():
    runner = CliRunner()
    result = runner.invoke(main, ["completions", "zsh"])
    assert result.exit_code == 0
    assert "VIBEFORT_COMPLETE" in result.output


def test_completions_bash():
    runner = CliRunner()
    result = runner.invoke(main, ["completions", "bash"])
    assert result.exit_code == 0
    assert "VIBEFORT_COMPLETE" in result.output
