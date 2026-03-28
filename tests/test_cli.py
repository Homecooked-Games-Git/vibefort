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
