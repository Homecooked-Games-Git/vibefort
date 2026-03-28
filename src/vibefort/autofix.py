"""Auto-fix suggestions for common security issues."""

import os
from pathlib import Path
from rich.console import Console
from rich.prompt import Confirm

console = Console()


def suggest_fixes(findings: list, project_path: str | Path) -> int:
    """Review findings and offer auto-fixes where possible. Returns number of fixes applied."""
    root = Path(project_path).resolve()
    fixes_applied = 0

    # .env not in .gitignore
    env_findings = [f for f in findings if f.rule in ("env-not-gitignored", "env-no-gitignore")]
    if env_findings:
        gitignore = root / ".gitignore"
        if gitignore.is_symlink():
            console.print("  [yellow].gitignore is a symlink — skipping auto-fix[/yellow]")
        elif Confirm.ask("\n  [yellow].env file found but not in .gitignore.[/yellow] Add it?", default=True):
            if gitignore.exists():
                content = gitignore.read_text()
                if not content.endswith("\n"):
                    content += "\n"
                content += ".env\n.env.*\n"
                gitignore.write_text(content)
            else:
                gitignore.write_text("# Environment variables\n.env\n.env.*\n")
            console.print("  [green]\u2714 Added .env to .gitignore[/green]")
            fixes_applied += 1

    # DEBUG = True
    debug_findings = [f for f in findings if f.rule == "debug-mode"]
    if debug_findings:
        console.print()
        for f in debug_findings:
            console.print(f"  [yellow]DEBUG=True found in {f.file}:{f.line}[/yellow]")
        console.print("  [dim]Suggestion: Use an environment variable instead:[/dim]")
        console.print('  [dim]  DEBUG = os.environ.get("DEBUG", "False").lower() == "true"[/dim]')

    # Hardcoded passwords
    password_findings = [f for f in findings if f.rule == "hardcoded-password"]
    if password_findings:
        console.print()
        for f in password_findings:
            console.print(f"  [yellow]Hardcoded password in {f.file}:{f.line}[/yellow]")
        console.print("  [dim]Suggestion: Move secrets to .env and load with os.environ:[/dim]")
        console.print('  [dim]  PASSWORD = os.environ["DATABASE_PASSWORD"][/dim]')

    # Insecure YAML
    yaml_findings = [f for f in findings if f.rule == "insecure-deserialize" and "yaml" in f.description.lower()]
    if yaml_findings:
        console.print()
        console.print("  [yellow]Insecure yaml.load() found[/yellow]")
        console.print("  [dim]Fix: Replace yaml.load(data) with yaml.safe_load(data)[/dim]")

    # subprocess shell=True
    shell_findings = [f for f in findings if f.rule == "command-injection" and "shell=True" in f.description]
    if shell_findings:
        console.print()
        console.print("  [yellow]subprocess with shell=True found[/yellow]")
        console.print("  [dim]Fix: Use a list instead of a string:[/dim]")
        console.print('  [dim]  subprocess.run(["cmd", "arg1", "arg2"]) instead of subprocess.run("cmd arg1 arg2", shell=True)[/dim]')

    # CORS wildcard
    cors_findings = [f for f in findings if f.rule == "cors-wildcard"]
    if cors_findings:
        console.print()
        console.print("  [yellow]CORS wildcard (*) found[/yellow]")
        console.print("  [dim]Fix: Specify allowed origins explicitly:[/dim]")
        console.print('  [dim]  CORS(app, origins=["https://yourdomain.com"])[/dim]')

    return fixes_applied
