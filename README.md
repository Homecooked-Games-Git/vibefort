# 🏰 VibeFort

**Security layer for AI-assisted development. One command, permanent protection.**

VibeFort protects vibecoders (Cursor, Bolt, Replit, Claude Code users) from supply chain attacks, leaked secrets, and insecure AI-generated code. Run `vibefort install` once — it silently protects every package install and git commit forever.

## Quick Start

```bash
pipx install vibefort
vibefort install
```

That's it. You never type `vibefort` again.

> **Why pipx?** VibeFort is a system-wide CLI tool, not a project dependency. `pipx` installs it globally in an isolated environment — the standard way to install Python CLI tools. [Install pipx](https://pipx.pypa.io/stable/installation/) if you don't have it: `brew install pipx` (macOS) or `apt install pipx` (Ubuntu).

## What Happens After Install

```bash
# Normal pip usage — VibeFort intercepts silently
$ pip install flask
✔ flask 3.1.0 — clean (0.2s)

$ pip install reqeusts
✖ BLOCKED reqeusts
  Possible typosquat — similar to 'requests'
  Did you mean: requests

$ pip install flask-ai-helper-utils
✖ BLOCKED flask-ai-helper-utils
  Package does not exist on PyPI
  This may be a hallucinated package name from an AI tool (slopsquatting)

# Normal git usage — VibeFort scans staged files
$ git commit -m "add config"
✖ VibeFort blocked this commit — 1 secret(s) found
  config.py:14
    Detected a Generic API Key

# Docker builds are scanned for insecure patterns
$ docker build .
🏰 VibeFort: 3 issue(s) in Dockerfile
  CRITICAL  Piping remote script directly to shell
  HIGH      Base image 'python' has no tag (defaults to :latest)
  HIGH      No USER directive in final stage — container runs as root

# Dangerous chmod/sudo commands are blocked
$ chmod 777 app.py
🏰 VibeFort: World-writable mode 777 allows any user to modify files
BLOCKED: Fix the issue above before proceeding

$ sudo pip install malware
🏰 VibeFort: Running 'pip' with sudo can lead to privilege escalation
```

## Supported Package Managers

VibeFort intercepts **12 package managers** plus `docker`, `git`, `chmod`, and `sudo`:

### Python

| Manager | Commands intercepted |
|---|---|
| `pip` / `pip3` | `pip install flask` |
| `uv` | `uv pip install flask`, `uv add flask` |
| `pipx` | `pipx install black` |
| `poetry` | `poetry add flask` |
| `pdm` | `pdm add flask` |

### Node.js

| Manager | Commands intercepted |
|---|---|
| `npm` | `npm install`, `npm add`, `npm i` |
| `npx` | `npx create-react-app` (scans before execute) |
| `yarn` | `yarn add express` |
| `pnpm` | `pnpm add express` |
| `bun` | `bun add express` |
| `bunx` | `bunx cowsay` (scans before execute) |

> `npx` and `bunx` are especially dangerous — they download AND execute code in one step. VibeFort scans the package before allowing execution.

## Features

### Dockerfile Scanning (automatic, every `docker build`)

VibeFort intercepts `docker build` and scans the Dockerfile for security issues:

- **Unpinned base images** — `FROM python:latest` or `FROM python` (supply chain risk)
- **Running as root** — no `USER` directive in the final stage
- **Remote code execution** — `curl | bash`, `$(curl ...)`, inline Python fetch-and-exec
- **Secrets in ENV/ARG** — API keys, passwords, tokens baked into the image
- **ADD from URL** — unverified remote downloads
- **Privileged RUN** — `--security=insecure` bypass
- **Heredoc detection** — catches `RUN <<EOF ... curl | bash ... EOF`

Critical findings block the build. Dockerfiles in your project are also scanned by `vibefort scan`.

### Git Clone Scanner (automatic, every `git clone`)

VibeFort scans repositories immediately after cloning:

- **Typosquatted orgs** — `git clone github.com/microsft/vscode` warns before cloning
- **Malicious git hooks** — scans `.git/hooks/` for curl|bash, netcat, base64, etc.
- **Dangerous git config** — detects custom `hooksPath`, `fsmonitor`, and malicious filter drivers
- Supports HTTPS, SSH, `git://`, and SSH shorthand URL formats

### Permission Escalation Guard (automatic)

VibeFort intercepts `chmod` and `sudo` to prevent dangerous operations:

- **chmod 777/666** — blocks world-writable permissions (octal and symbolic modes)
- **chmod +s** — blocks setuid/setgid bit (privilege escalation)
- **sudo pip/npm** — warns against running package managers as root
- **sudo rm -rf /** — blocks destructive commands on system paths
- **sudo env/su wrappers** — detects attempts to bypass detection via `sudo env pip` or `sudo su -c "pip install"`

### .env Watchdog (automatic, on directory change)

Monitors `.env` files every time you change directories:

- **Not in .gitignore** — warns if `.env`, `.env.local`, `.env.production` etc. would be committed
- **World-readable** — warns if `.env` has loose permissions
- **Secrets in .env.example** — detects when example files contain real secret values

### Paste Injection Scanner (automatic, ZSH)

Scans clipboard content when you paste into the terminal:

- **Hidden Unicode** — zero-width characters, RTL overrides, homoglyphs (Cyrillic/Greek lookalikes)
- **ANSI attacks** — cursor manipulation, hidden text, terminal hyperlink spoofing
- **OSC/DCS escapes** — terminal control sequences that can execute commands
- **Obfuscated payloads** — base64 in comments, hex escape sequences

Malicious pastes are blocked before reaching the terminal.

### Config File Guard (automatic, every 5 minutes)

Monitors sensitive dotfiles for unauthorized changes:

- Watches: `~/.ssh/config`, `~/.ssh/authorized_keys`, `~/.gitconfig`, `~/.npmrc`, `~/.pypirc`, `~/.aws/credentials`, `~/.aws/config`, `~/.docker/config.json`, `~/.kube/config`
- Detects: new files, modifications, deletions, and symlink replacements
- Alerts on corrupted snapshots (potential tampering)

### Package Scanning (automatic, every install)

Every package install goes through two tiers:

| Tier | What it checks | Speed | When |
|---|---|---|---|
| **Tier 1** | Known-safe cache (10k PyPI + 10k npm), typosquatting, slopsquatting, registry existence, CVE check via [osv.dev](https://osv.dev) | < 500ms | Every install |
| **Tier 2** | Downloads to temp, inspects setup.py/package.json hooks, .pth files, obfuscated code | 3-5s | Unknown packages only |

### Secret Scanning (automatic, every commit)

Git pre-commit hook powered by [betterleaks](https://github.com/betterleaks/betterleaks) (234 detection rules):

- AWS, OpenAI, Anthropic, GitHub, Stripe, Google API keys
- SSH/PGP private keys, JWT tokens
- Database connection strings
- And 220+ more patterns

### Code Scanning (`vibefort scan`)

Scan your project for insecure patterns AI coding tools commonly generate:

```bash
$ vibefort scan .

  CRITICAL (2)
    app.py:12 — SQL injection — f-string in database query
    utils.py:8 — Insecure deserialization — pickle.load can execute arbitrary code

  HIGH (3)
    run.py:5 — Command injection risk — subprocess with shell=True
    settings.py:1 — Debug mode enabled — should be False in production
    app.js:23 — XSS risk — innerHTML assignment

  5 issue(s) found (2 critical)
```

Detects: SQL injection, XSS, insecure deserialization (`pickle`, `yaml.load`), command injection (`shell=True`, `os.system`), debug mode, hardcoded passwords, CORS wildcards, `.env` not in `.gitignore`.

### Dependency Auditing (`vibefort deps`)

Audit all project dependencies at once:

```bash
$ vibefort deps .

  ✖ reqeusts==2.28.0 (requirements.txt)
    Possible typosquat: similar to 'requests'

  ✖ flask==2.0.0 (requirements.txt)
    GHSA-xxxx: Known vulnerability (fix: upgrade to 2.3.2)

  2 issue(s) found in project dependencies.
```

Reads `requirements.txt`, `pyproject.toml`, `package.json`, `Pipfile`, `package-lock.json`, and `poetry.lock`. Checks every dependency against typosquatting, CVE databases, and lock file integrity.

### System Audit (`vibefort audit`)

Check if your machine is already compromised:

```bash
$ vibefort audit

  ✖ Malicious .pth file — contains 'import' (executes code every time Python starts)
    /usr/lib/python3/site-packages/evil.pth

  1 potential issue(s) found.
```

Checks: malicious `.pth` files in Python site-packages, known backdoor artifacts, suspicious processes, cron jobs (Linux), LaunchAgents (macOS).

### Per-Project Allowlist (`.vibefort.toml`)

Whitelist packages, files, or rules to prevent false positives:

```toml
# .vibefort.toml in your project root
[allow-packages]
"my-internal-sdk" = "private registry"

[allow-files]
"tests/fixtures/fake_keys.py" = "test dummy keys"

[allow-rules]
"generic-api-key" = "false positives in test files"
```

### Auto-Fix Suggestions

When `vibefort scan` finds issues, it offers to fix them:

- `.env` not in `.gitignore` → offers to add it
- `DEBUG = True` → suggests using environment variables
- Hardcoded passwords → suggests moving to `.env`
- `yaml.load()` → suggests `yaml.safe_load()`
- `subprocess(shell=True)` → suggests list form

## All Commands

| Command | Description |
|---|---|
| `vibefort install` | One-time setup — hooks + secret scanner |
| `vibefort uninstall` | Clean removal of all hooks |
| `vibefort status` | Dashboard with version, stats, update check |
| `vibefort scan [path]` | Scan project for secrets + insecure code |
| `vibefort deps [path]` | Audit all dependencies for vulnerabilities |
| `vibefort audit` | Check machine for signs of compromise |
| `vibefort update` | Self-update to latest version |
| `vibefort config` | View or edit settings |
| `vibefort completions zsh` | Generate shell completions |

## How Install Works

`vibefort install` does three things that persist forever:

1. **Shell hook** — Adds function wrappers to `~/.zshrc` or `~/.bashrc` that intercept 16 commands (12 package managers + `docker`, `git`, `chmod`, `sudo`). Also installs `.env` watchdog, config file guard, and paste scanner. Loads every time a terminal opens.

2. **Git hook** — Sets a global pre-commit hook via `git config --global core.hooksPath`. Applies to every repo.

3. **Config guard** — Takes an initial snapshot of sensitive dotfiles (`~/.ssh/*`, `~/.gitconfig`, `~/.aws/*`, etc.) for change detection.

A 🏰 icon appears in your terminal prompt and window title when VibeFort is active, showing scan stats.

`vibefort uninstall` cleanly removes both.

## Security

VibeFort is a security tool — we take our own security seriously:

- 12 security audits completed (shell injection, path traversal, symlink attacks, TOCTOU races, re-entrancy, regex bypass, system-level interactions)
- All subprocess calls use list form (no `shell=True`)
- Manager arguments validated against whitelist
- Downloaded binaries verified with SHA256 checksums (fail-closed)
- Atomic file writes for config and checksum files (temp + rename)
- Re-entrancy guard prevents infinite recursion in command wrappers
- `~/.vibefort/` directory set to `0700`, config to `0600`
- Secret values from scans are never stored or logged
- Scanning uses `--ignore-scripts` (npm) and prefers wheels (pip) to prevent code execution during analysis
- File scanning has 10MB size limit and skips symlinks
- Shell wrappers degrade gracefully if VibeFort is unavailable
- Compatible with `set -u` strict shell mode
- See [SECURITY.md](SECURITY.md) for vulnerability reporting

## Privacy

VibeFort is local-first. No accounts, no telemetry, no data collection.

Network calls made:
- **PyPI/npm registries** — to check if packages exist and for metadata (same as pip/npm themselves)
- **osv.dev** — to check for known CVEs (package name + version only)
- **GitHub** — to download the betterleaks binary (one-time, on install)
- **PyPI** — to check for VibeFort updates (only when you run `vibefort status`)

No source code, secrets, or project data ever leaves your machine.

## License

MIT — see [LICENSE](LICENSE).

Secret scanning powered by [betterleaks](https://github.com/betterleaks/betterleaks) (MIT). See [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).
