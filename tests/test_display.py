from io import StringIO
from rich.console import Console
from vibefort.display import show_safe, show_blocked, show_status_panel
from vibefort.config import Config


def test_show_safe_outputs_check():
    console = Console(file=StringIO(), force_terminal=True, highlight=False)
    show_safe("flask", "3.1.0", console=console)
    output = console.file.getvalue()
    assert "flask" in output
    assert "3.1.0" in output


def test_show_blocked_outputs_warning():
    console = Console(file=StringIO(), force_terminal=True)
    show_blocked("evil-pkg", "malicious payload detected", console=console)
    output = console.file.getvalue()
    assert "evil-pkg" in output
    assert "BLOCKED" in output


def test_show_status_panel_not_installed():
    console = Console(file=StringIO(), force_terminal=True)
    config = Config()
    show_status_panel(config, console=console)
    output = console.file.getvalue()
    assert "not installed" in output.lower() or "install" in output.lower()
