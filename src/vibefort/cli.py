"""VibeFort CLI — Security layer for AI-assisted development."""

import os
import subprocess
import sys

import click
from rich.console import Console
from rich.progress import Progress

from vibefort import __version__
from vibefort.config import load_config, save_config, Config
from vibefort.display import show_status_panel, show_secret_found
from vibefort.installer import (
    install_shell_hook,
    uninstall_shell_hook,
    install_git_hook,
    uninstall_git_hook,
)
from vibefort.secrets import download_betterleaks, is_betterleaks_installed, run_betterleaks_on_files
from vibefort.interceptor import run_intercept
import vibefort.constants as constants

console = Console()


def _get_gitignored_files(path: str) -> set[str]:
    """Get the set of files that are gitignored in the given directory."""
    try:
        result = subprocess.run(
            ["git", "ls-files", "--others", "--ignored", "--exclude-standard", "--directory"],
            capture_output=True, text=True, cwd=path, timeout=10,
        )
        if result.returncode != 0:
            return set()
        return {f.strip().rstrip("/") for f in result.stdout.splitlines() if f.strip()}
    except Exception:
        return set()


SKIP_UPDATE_COMMANDS = {"banner", "completions", "intercept", "scan-secrets",
                        "intercept-docker", "intercept-git", "intercept-chmod",
                        "intercept-sudo", "check-env", "check-paste", "check-config"}


class VibeFortGroup(click.Group):
    """Custom group that checks for updates after every command."""

    def invoke(self, ctx):
        try:
            super().invoke(ctx)
        finally:
            # Skip update check for internal/fast commands
            cmd_name = (sys.argv[1] if len(sys.argv) > 1 else "")
            if cmd_name not in SKIP_UPDATE_COMMANDS:
                _silent_update_check()


def _silent_update_check():
    """Check for updates max once per 24h. Non-blocking."""
    try:
        import json
        from datetime import datetime, timedelta

        # Only check once per 24h
        cache_file = constants.CACHE_DIR / "update_check.json"
        if cache_file.exists():
            data = json.loads(cache_file.read_text())
            checked_at = datetime.fromisoformat(data.get("checked_at", ""))
            if datetime.now() - checked_at < timedelta(hours=24):
                return

        from vibefort.banner import check_for_update_online
        check_for_update_online()
    except Exception:
        pass


@click.group(cls=VibeFortGroup)
@click.version_option(version=__version__, prog_name="vibefort")
def main():
    """Security layer for AI-assisted development. One command, permanent protection."""
    pass


@main.command()
def install():
    """Install VibeFort — shell hooks, git hooks, secret scanning. One command, done."""
    console.print()

    config = load_config()

    # Step 1: Install shell hook
    rc_path = install_shell_hook()
    config.shell_hook_installed = True
    console.print(f"[green]\u2714[/green] Shell hook installed ({rc_path.name})")

    # Step 2: Download betterleaks
    if not is_betterleaks_installed():
        with Progress(console=console, transient=True) as progress:
            task = progress.add_task("Downloading betterleaks...", total=100)

            def on_progress(downloaded, total):
                progress.update(task, completed=int(downloaded / total * 100))

            try:
                download_betterleaks(progress_callback=on_progress)
                console.print("[green]\u2714[/green] Secret scanner installed")
            except Exception as e:
                console.print(f"[yellow]\u26a0[/yellow] Could not download betterleaks: {e}")
                console.print("[dim]  Secret scanning will be limited. Run vibefort install again to retry.[/dim]")
    else:
        console.print("[green]\u2714[/green] Secret scanner ready")

    # Step 3: Install git hook
    try:
        install_git_hook()
        config.git_hook_installed = True
        console.print("[green]\u2714[/green] Git pre-commit hook installed")
    except Exception as e:
        console.print(f"[yellow]\u26a0[/yellow] Could not install git hook: {e}")

    # Initialize config file guard
    from vibefort.configguard import snapshot_config_files
    from vibefort.constants import CONFIG_CHECKSUMS_PATH
    snapshot_config_files(str(CONFIG_CHECKSUMS_PATH))
    console.print("[green]\u2714[/green] Config file guard initialized")

    # Save config
    save_config(config)

    console.print()
    console.print("[bold green]\u2714 VibeFort is now protecting you. Forget about it.[/bold green]")
    console.print()
    console.print("[dim]Open a new terminal for the shell hook to take effect.[/dim]")


@main.command()
def uninstall():
    """Remove all VibeFort hooks and configuration."""
    console.print()

    uninstall_shell_hook()
    console.print("[green]\u2714[/green] Shell hook removed")

    uninstall_git_hook()
    console.print("[green]\u2714[/green] Git hook removed")

    config = load_config()
    config.shell_hook_installed = False
    config.git_hook_installed = False
    save_config(config)

    console.print()
    console.print("[bold]VibeFort has been deactivated.[/bold]")
    console.print("[dim]Your scan history is preserved in ~/.vibefort/[/dim]")
    console.print("[dim]To fully remove: rm -rf ~/.vibefort/[/dim]")


@main.command()
def status():
    """Show VibeFort status and statistics."""
    config = load_config()
    show_status_panel(config, console=console)

    from vibefort.banner import check_for_update_online
    update = check_for_update_online()
    if update:
        console.print(f"\n  [bold yellow]\u2191 {update}[/bold yellow] — run: vibefort update")


@main.command()
@click.option("--title", is_flag=True, hidden=True)
@click.option("--short", is_flag=True, hidden=True)
@click.option("--prompt", is_flag=True, hidden=True)
def banner(title, short, prompt):
    """Internal: print shell status banner."""
    from vibefort.banner import get_banner, get_title, get_short
    if prompt:
        # Combined output for shell hook: short|||title (single process)
        s = get_short()
        t = get_title()
        print(f"{s}|||{t}", end="")
    elif title:
        t = get_title()
        if t:
            print(t, end="")
    elif short:
        s = get_short()
        if s:
            print(s, end="")
    else:
        b = get_banner()
        if b:
            print(b)


@main.command()
@click.argument("path", default=".", type=click.Path(exists=True))
def scan(path):
    """Scan a project for secrets and insecure code patterns."""
    from pathlib import Path
    from vibefort.codescan import scan_directory, CodeFinding
    from vibefort.secrets import is_betterleaks_installed, run_betterleaks_scan
    from rich.markup import escape

    console.print(f"\n[bold]Scanning {escape(path)}...[/bold]\n")

    findings = scan_directory(path)

    # Also run betterleaks on the full directory for secret detection
    if is_betterleaks_installed():
        secret_findings = run_betterleaks_scan(str(Path(path).resolve()))

        # Filter out gitignored files — betterleaks scans everything,
        # but we should respect .gitignore (if .env is ignored, don't report it)
        gitignored = _get_gitignored_files(path)

        for sf in secret_findings:
            if sf["file"] in gitignored:
                continue
            findings.append(CodeFinding(
                file=sf["file"],
                line=sf["line"],
                rule=sf["rule"],
                description=sf["description"],
                severity="critical",
            ))

    # Scan Dockerfiles
    from vibefort.dockerscan import find_dockerfiles, scan_dockerfile as scan_df
    from vibefort.display import show_docker_finding
    dockerfiles = find_dockerfiles(path)
    docker_findings = []
    for df_path in dockerfiles:
        docker_findings.extend(scan_df(df_path))
    if docker_findings:
        console.print(f"  [yellow bold]DOCKERFILE ISSUES ({len(docker_findings)})[/yellow bold]")
        for df in docker_findings:
            show_docker_finding(df, console=console)
        console.print()
        # Add to findings count for summary
        for df in docker_findings:
            findings.append(CodeFinding(
                file=df.file,
                line=df.line,
                rule=df.rule,
                description=df.description,
                severity=df.severity.lower(),
            ))

    # Log scan result to database
    from vibefort.db import log_scan
    scan_target = str(Path(path).resolve())
    log_scan("scan", scan_target, "clean" if not findings else "issues", str(len(findings)))

    if not findings:
        console.print("[green]\u2714 No issues found.[/green]\n")
        return

    # Group by severity
    by_severity = {"critical": [], "high": [], "medium": [], "low": []}
    for f in findings:
        by_severity.get(f.severity, by_severity["low"]).append(f)

    severity_colors = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "dim"}

    for severity in ["critical", "high", "medium", "low"]:
        items = by_severity[severity]
        if not items:
            continue
        color = severity_colors[severity]
        console.print(f"  [{color}]{severity.upper()} ({len(items)})[/{color}]")
        for f in items:
            console.print(f"    {escape(f.file)}:{f.line} \u2014 {escape(f.description)}")
        console.print()

    total = len(findings)
    critical = len(by_severity["critical"])
    console.print(f"  [bold]{total} issue(s) found[/bold]", end="")
    if critical:
        console.print(f" [bold red]({critical} critical)[/bold red]")
    else:
        console.print()
    console.print()

    # Offer auto-fixes
    if findings:
        from vibefort.autofix import suggest_fixes
        fixes = suggest_fixes(findings, path)
        if fixes:
            console.print(f"  [green]{fixes} fix(es) applied.[/green]\n")


@main.command()
@click.argument("path", default=".", type=click.Path(exists=True))
def deps(path):
    """Audit project dependencies for vulnerabilities and typosquatting."""
    from vibefort.depscan import scan_dependencies
    from rich.markup import escape

    console.print(f"\n[bold]Auditing dependencies in {escape(str(path))}...[/bold]\n")

    findings = scan_dependencies(path)

    if not findings:
        console.print("[green]\u2714 All dependencies look clean.[/green]\n")
        return

    for f in findings:
        severity_colors = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "dim"}
        color = severity_colors.get(f.severity, "dim")
        console.print(f"  [{color}]\u2716 {escape(f.package)}{'==' + escape(f.version) if f.version else ''}[/{color}] ({escape(f.source)})")
        console.print(f"    {escape(f.issue)}")
        console.print()

    console.print(f"  [bold]{len(findings)} issue(s) found in project dependencies.[/bold]\n")


@main.command()
def audit():
    """Check if your machine shows signs of compromise."""
    from vibefort.sysaudit import run_audit
    from rich.markup import escape

    console.print("\n[bold]Running system audit...[/bold]\n")

    findings = run_audit()

    if not findings:
        console.print("[green]✔ No signs of compromise detected.[/green]\n")
        return

    for f in findings:
        severity_colors = {"critical": "bold red", "high": "red", "medium": "yellow"}
        color = severity_colors.get(f.severity, "dim")
        console.print(f"  [{color}]✖ {escape(f.description)}[/{color}]")
        console.print(f"    [dim]{escape(f.path)}[/dim]")
        console.print()

    console.print(f"  [bold red]{len(findings)} potential issue(s) found.[/bold red]")
    console.print(f"  [dim]Review each finding carefully. Not all findings are confirmed compromises.[/dim]\n")


@main.command()
def update():
    """Update VibeFort to the latest version."""
    import subprocess as sp
    from vibefort import __version__
    from vibefort.banner import check_for_update_online

    console.print(f"\n  Current version: [bold]{__version__}[/bold]")

    update_msg = check_for_update_online()
    if not update_msg:
        console.print("  [green]✔ Already up to date.[/green]\n")
        return

    console.print(f"  [yellow]↑ {update_msg}[/yellow]\n")

    # Try pipx first, then pip
    for cmd in [["pipx", "upgrade", "vibefort"], ["pip", "install", "-U", "vibefort"]]:
        try:
            result = sp.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode == 0:
                console.print(f"  [green]✔ Updated successfully via {cmd[0]}.[/green]\n")
                # Clear stale update cache
                cache_file = constants.CACHE_DIR / "update_check.json"
                if cache_file.exists():
                    cache_file.unlink()
                return
        except (FileNotFoundError, sp.TimeoutExpired):
            continue

    console.print("  [red]✖ Could not update. Try manually:[/red]")
    console.print("    pipx upgrade vibefort\n")


@main.command()
@click.argument("key", required=False)
@click.argument("value", required=False)
def config(key, value):
    """View or edit VibeFort configuration.

    vibefort config              — show all settings
    vibefort config <key>        — show one setting
    vibefort config <key> <val>  — set a value
    """
    from vibefort.config import load_config, save_config
    from rich.markup import escape

    cfg = load_config()

    if key is None:
        # Show all settings
        console.print("\n[bold]VibeFort Configuration[/bold]\n")
        from dataclasses import fields
        for f in fields(cfg):
            val = getattr(cfg, f.name)
            console.print(f"  [dim]{f.name}[/dim] = {escape(str(val))}")
        console.print(f"\n  [dim]Config file: ~/.vibefort/config.toml[/dim]\n")
        return

    if value is None:
        # Show one setting
        if hasattr(cfg, key):
            console.print(f"  {key} = {escape(str(getattr(cfg, key)))}")
        else:
            console.print(f"  [red]Unknown setting: {escape(key)}[/red]")
        return

    # Set a value
    if not hasattr(cfg, key):
        console.print(f"  [red]Unknown setting: {escape(key)}[/red]")
        return

    # Type coercion
    current = getattr(cfg, key)
    if isinstance(current, bool):
        setattr(cfg, key, value.lower() in ("true", "1", "yes"))
    elif isinstance(current, int):
        setattr(cfg, key, int(value))
    else:
        setattr(cfg, key, value)

    save_config(cfg)
    console.print(f"  [green]✔ {escape(key)} = {escape(str(getattr(cfg, key)))}[/green]")


@main.command()
@click.argument("shell_type", type=click.Choice(["zsh", "bash", "fish"]))
def completions(shell_type):
    """Generate shell completion script.

    Usage:
      vibefort completions zsh >> ~/.zshrc
      vibefort completions bash >> ~/.bashrc
    """
    env_var = "_VIBEFORT_COMPLETE"

    if shell_type == "zsh":
        console.print(f'eval "$({env_var}=zsh_source vibefort)"')
    elif shell_type == "bash":
        console.print(f'eval "$({env_var}=bash_source vibefort)"')
    elif shell_type == "fish":
        console.print(f'{env_var}=fish_source vibefort | source')


@main.command()
@click.argument("manager")
@click.argument("args", nargs=-1)
def intercept(manager, args):
    """Internal: intercept package manager commands (called by shell hook)."""
    exit_code = run_intercept(manager, list(args))
    sys.exit(exit_code)


@main.command(name="scan-secrets")
def scan_secrets():
    """Internal: scan staged files for secrets (called by git pre-commit hook)."""
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        sys.exit(0)

    staged_files = [f.strip() for f in result.stdout.strip().splitlines() if f.strip()]
    if not staged_files:
        sys.exit(0)

    findings = run_betterleaks_on_files(staged_files)

    if not findings:
        config = load_config()
        config.commits_scanned += 1
        save_config(config)
        sys.exit(0)

    console.print()
    console.print(f"[bold red]\u2716 VibeFort blocked this commit \u2014 {len(findings)} secret(s) found[/bold red]")
    console.print()

    for f in findings:
        show_secret_found(f["file"], f["line"], f["description"], console=console)

    console.print()
    console.print("[dim]Fix the issues above and try again.[/dim]")

    config = load_config()
    config.commits_scanned += 1
    config.secrets_caught += len(findings)
    save_config(config)

    sys.exit(1)


@main.command("intercept-docker", hidden=True)
@click.argument("args", nargs=-1)
def intercept_docker(args):
    """Internal: called by shell hook when docker is invoked."""
    from vibefort.dockerscan import scan_dockerfile
    from vibefort.display import show_docker_finding

    args = list(args)

    # Only scan on 'docker build' commands
    if args and args[0] == "build":
        dockerfile = "Dockerfile"
        for i, arg in enumerate(args):
            if arg in ("-f", "--file") and i + 1 < len(args):
                dockerfile = args[i + 1]
                break

        from pathlib import Path
        if Path(dockerfile).exists():
            findings = scan_dockerfile(dockerfile)
            if findings:
                console.print(f"\n[yellow]\U0001f3f0 VibeFort: {len(findings)} issue(s) in {dockerfile}[/yellow]")
                for f in findings:
                    show_docker_finding(f, console=console)
                console.print()

                critical = [f for f in findings if f.severity == "critical"]
                if critical:
                    console.print("[red bold]BLOCKED:[/red bold] Fix critical issues before building")
                    cfg = load_config()
                    cfg.dockerfiles_scanned += 1
                    save_config(cfg)
                    sys.exit(1)

            cfg = load_config()
            cfg.dockerfiles_scanned += 1
            save_config(cfg)

    # Pass through to real docker
    try:
        os.execvp("docker", ["docker"] + args)
    except FileNotFoundError:
        console.print("[red]docker: command not found[/red]")
        sys.exit(127)


@main.command("intercept-git", hidden=True)
@click.argument("args", nargs=-1)
def intercept_git(args):
    """Internal: called by shell hook when git is invoked."""
    args = list(args)

    # Only intercept 'git clone'
    if not args or args[0] != "clone":
        try:
            os.execvp("git", ["git"] + args)
        except FileNotFoundError:
            console.print("[red]git: command not found[/red]")
            sys.exit(127)

    from vibefort.clonescan import check_git_hooks, check_typosquatted_org
    from pathlib import Path

    # Find the URL (first non-flag argument after 'clone')
    clone_url = ""
    dest_dir = ""
    skip_next = False
    positional = []
    for i, arg in enumerate(args[1:], 1):
        if skip_next:
            skip_next = False
            continue
        if arg.startswith("-"):
            if arg in ("-b", "--branch", "--depth", "-o", "--origin", "--reference"):
                skip_next = True
            continue
        positional.append(arg)

    if positional:
        clone_url = positional[0]
        if len(positional) > 1:
            dest_dir = positional[1]

    # Pre-clone check: typosquatted org
    if clone_url:
        findings = check_typosquatted_org(clone_url)
        if findings:
            for f in findings:
                console.print(f"[yellow]\U0001f3f0 VibeFort: {f.description}[/yellow]")
            console.print("[yellow]Proceeding with clone in 5 seconds...[/yellow]")
            import time
            time.sleep(5)

    # Execute the actual clone
    result = subprocess.run(["git"] + args)

    # Post-clone: determine cloned directory
    if result.returncode == 0 and clone_url:
        if not dest_dir:
            dest_dir = clone_url.rstrip("/").rsplit("/", 1)[-1]
            if dest_dir.endswith(".git"):
                dest_dir = dest_dir[:-4]

        if Path(dest_dir).is_dir():
            console.print(f"\n[blue]\U0001f3f0 VibeFort: scanning cloned repository...[/blue]")

            hook_findings = check_git_hooks(dest_dir)
            if hook_findings:
                for f in hook_findings:
                    console.print(f"  [red]{f.severity}[/red] {f.description}")
                    if f.file:
                        console.print(f"    Review: {f.file}", style="dim")

            cfg = load_config()
            cfg.clones_scanned += 1
            save_config(cfg)

    sys.exit(result.returncode)


@main.command("intercept-chmod", hidden=True)
@click.argument("args", nargs=-1)
def intercept_chmod(args):
    """Internal: called by shell hook when chmod is invoked."""
    from vibefort.permguard import check_chmod_args

    args = list(args)
    findings = check_chmod_args(args)
    if findings:
        for f in findings:
            severity_color = "red bold" if f.severity == "critical" else "yellow"
            console.print(f"[{severity_color}]\U0001f3f0 VibeFort: {f.description}[/{severity_color}]")

        critical = [f for f in findings if f.severity == "critical"]
        if critical:
            console.print("[red bold]BLOCKED:[/red bold] Fix the issue above before proceeding")
            cfg = load_config()
            cfg.permissions_blocked += 1
            save_config(cfg)
            sys.exit(1)

    try:
        os.execvp("chmod", ["chmod"] + args)
    except FileNotFoundError:
        console.print("[red]chmod: command not found[/red]")
        sys.exit(127)


@main.command("intercept-sudo", hidden=True)
@click.argument("args", nargs=-1)
def intercept_sudo(args):
    """Internal: called by shell hook when sudo is invoked."""
    from vibefort.permguard import check_sudo_args

    args = list(args)
    findings = check_sudo_args(args)
    if findings:
        for f in findings:
            severity_color = "red bold" if f.severity == "critical" else "yellow"
            console.print(f"[{severity_color}]\U0001f3f0 VibeFort: {f.description}[/{severity_color}]")

        critical = [f for f in findings if f.severity == "critical"]
        if critical:
            console.print("[red bold]BLOCKED:[/red bold] Command blocked for safety")
            cfg = load_config()
            cfg.permissions_blocked += 1
            save_config(cfg)
            sys.exit(1)

    try:
        os.execvp("sudo", ["sudo"] + args)
    except FileNotFoundError:
        console.print("[red]sudo: command not found[/red]")
        sys.exit(127)


@main.command("check-env", hidden=True)
def check_env():
    """Internal: called by precmd hook to check .env files."""
    from vibefort.envscan import check_env_files

    cwd = os.getcwd()
    findings = check_env_files(cwd)
    if findings:
        for f in findings:
            severity_color = "red bold" if f.severity == "critical" else "yellow"
            console.print(f"[{severity_color}]\U0001f3f0 VibeFort: {f.description}[/{severity_color}]")


@main.command("check-paste", hidden=True)
def check_paste():
    """Internal: called by ZSH paste widget to scan pasted content."""
    from vibefort.pastescan import scan_paste

    text = sys.stdin.read()
    findings = scan_paste(text)
    if findings:
        for f in findings:
            severity_color = "red bold" if f.severity == "critical" else "yellow"
            console.print(f"[{severity_color}]\U0001f3f0 VibeFort: {f.description}[/{severity_color}]")
        sys.exit(1)


@main.command("check-config", hidden=True)
def check_config_cmd():
    """Internal: called by precmd hook to check for config file changes."""
    from vibefort.configguard import check_config_changes
    from vibefort.constants import CONFIG_CHECKSUMS_PATH

    alerts = check_config_changes(str(CONFIG_CHECKSUMS_PATH))
    if alerts:
        for a in alerts:
            console.print(f"[red bold]\U0001f3f0 VibeFort: {a.description}[/red bold]")
            console.print(f"    File: {a.file}", style="dim")
        console.print("[yellow]Review these changes \u2014 if unexpected, investigate immediately[/yellow]")
