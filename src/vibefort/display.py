"""Rich terminal output for VibeFort."""

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from vibefort import __version__
from vibefort.config import Config

_default_console = Console()

# Human-readable descriptions for scanner findings
ISSUE_DESCRIPTIONS = {
    # setup.py issues
    "subprocess execution": "Runs system commands during install (can execute anything on your machine)",
    "curl command": "Downloads files from the internet during install",
    "wget command": "Downloads files from the internet during install",
    "os.system call": "Runs shell commands during install",
    "eval() call": "Executes dynamically generated code",
    "exec() call": "Executes dynamically generated code",
    "network request": "Makes network calls during install",
    "cmdclass override": "Overrides the install process with custom code",
    # .pth file issues
    "import statement in .pth": "Runs Python code every time Python starts (persistence backdoor)",
    "os module in .pth": "Executes system commands every time Python starts",
    "subprocess in .pth": "Runs system commands every time Python starts",
    # Obfuscation issues
    "base64 decoding": "Contains hidden base64-encoded code (trying to avoid detection)",
    "exec with base64": "Decodes and executes hidden code (classic malware pattern)",
    "hex decoding": "Contains hidden hex-encoded code",
    "dynamic compilation": "Dynamically compiles and runs code at runtime",
    "heavy hex escaping": "Uses heavy character escaping to hide code",
    # package.json issues
    "curl piped to shell": "Downloads and immediately executes remote code",
    "inline node execution": "Runs arbitrary JavaScript during install",
    "non-standard URL": "Contacts an external server during install",
    "downloads external payload": "Downloads files from the internet during install",
    "PowerShell execution": "Runs PowerShell commands during install",
}

# Risk level icons
RISK_ICONS = {
    "critical": "\U0001f6a8",  # rotating light
    "high": "\u26a0\ufe0f",    # warning
    "medium": "\U0001f50d",    # magnifying glass
}


def _describe_issue(issue: str) -> str:
    """Get a human-readable description for a scanner finding."""
    # Try exact match
    if issue in ISSUE_DESCRIPTIONS:
        return ISSUE_DESCRIPTIONS[issue]
    # Try partial match
    for key, desc in ISSUE_DESCRIPTIONS.items():
        if key in issue.lower():
            return desc
    return issue


def _categorize_issues(reason: str) -> dict[str, list[str]]:
    """Group semicolon-separated issues by source file."""
    categories: dict[str, list[str]] = {}
    for part in reason.split(";"):
        part = part.strip()
        if not part:
            continue
        if ": " in part:
            source, issue = part.split(": ", 1)
            source = source.strip()
        else:
            source = "general"
            issue = part
        categories.setdefault(source, [])
        # Deduplicate
        if issue not in categories[source]:
            categories[source].append(issue)
    return categories


def show_safe(package: str, version: str = "", elapsed: str = "", *, console: Console | None = None):
    """Show a safe package result."""
    c = console or _default_console
    ver = f" {version}" if version else ""
    time_str = f" ({elapsed})" if elapsed else ""
    c.print(f"[green]\u2714[/green] {escape(package)}{escape(ver)} \u2014 clean{time_str}")


def show_blocked(package: str, reason: str, suggestion: str = "", *, console: Console | None = None):
    """Show a blocked package result with clear, readable output."""
    c = console or _default_console

    c.print()
    c.print(f"  [bold red]\u2716 BLOCKED[/bold red] [bold]{escape(package)}[/bold]")
    c.print()

    # Check if this is a simple reason (typosquat, doesn't exist, etc.)
    categories = _categorize_issues(reason)

    if len(categories) <= 1 and ";" not in reason:
        # Simple single-reason block (typosquat, slopsquat, etc.)
        c.print(f"  [red]{escape(reason)}[/red]")
    else:
        # Multi-issue block (tier 2 scan) — show categorized
        for source, issues in categories.items():
            c.print(f"  [bold yellow]{escape(source)}[/bold yellow]")
            for issue in issues:
                desc = _describe_issue(issue)
                c.print(f"    [red]\u2022[/red] {escape(desc)}")
            c.print()

    if suggestion:
        c.print(f"  [dim]{escape(suggestion)}[/dim]")

    c.print()


def show_secret_found(file: str, line: int, description: str, *, console: Console | None = None):
    """Show a detected secret."""
    c = console or _default_console
    c.print(f"  [bold red]\u2716[/bold red] [bold]{escape(file)}[/bold]:{line}")
    c.print(f"    [red]{escape(description)}[/red]")


def show_status_panel(config: Config, *, console: Console | None = None):
    """Show the vibefort status dashboard."""
    c = console or _default_console

    if not config.shell_hook_installed and not config.git_hook_installed:
        c.print(Panel(
            "[dim]VibeFort is not installed.\nRun [bold]vibefort install[/bold] to get started.[/dim]",
            title=f"VibeFort v{__version__}",
            border_style="dim",
        ))
        return

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="dim")
    table.add_column("Value")

    active_str = "Active" if config.shell_hook_installed else "Inactive"

    table.add_row("Status", f"[green]{active_str}[/green]" if config.shell_hook_installed else f"[red]{active_str}[/red]")
    table.add_row("Shell hook", "[green]\u2713[/green]" if config.shell_hook_installed else "[red]\u2717[/red]")
    table.add_row("Git hook", "[green]\u2713[/green]" if config.git_hook_installed else "[red]\u2717[/red]")
    table.add_row("Packages scanned", str(config.packages_scanned))
    table.add_row("Packages blocked", str(config.packages_blocked))
    table.add_row("Commits scanned", str(config.commits_scanned))
    table.add_row("Secrets caught", str(config.secrets_caught))

    c.print(Panel(table, title=f"VibeFort v{__version__}", border_style="green"))
