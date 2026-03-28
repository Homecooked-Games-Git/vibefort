# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in VibeFort, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, email: **security@vibefort.dev**

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if you have one)

We will acknowledge your report within 48 hours and aim to release a fix within 7 days for critical issues.

## Scope

VibeFort is a security tool that:
- Modifies shell configuration files (`~/.zshrc`, `~/.bashrc`)
- Sets global git hooks (`core.hooksPath`)
- Downloads and executes a third-party binary (betterleaks)
- Intercepts package manager commands (pip, npm, yarn, etc.)
- Scans downloaded package contents in temporary directories

All of these are high-trust operations. We take security seriously.

## What We Consider Vulnerabilities

- Shell injection via package names or manager arguments
- Path traversal in archive extraction
- Execution of malicious code during package scanning
- Secret values (API keys, tokens) being logged or stored
- Symlink attacks on `~/.vibefort/`
- Bypass of scanning that allows malicious packages through
- Tampering with the betterleaks binary after download

## What We Don't Consider Vulnerabilities

- `git commit --no-verify` bypassing the pre-commit hook (this is a git feature, not a bug)
- Users with root/sudo access modifying VibeFort's files (if they have root, they don't need VibeFort to do damage)
- Packages that are malicious but not detectable by static analysis (we can't catch everything)
- False positives in typosquatting detection

## Security Design Decisions

- All subprocess calls use list form (no `shell=True`)
- Manager arguments are validated against a whitelist before execution
- Downloaded binaries are verified with SHA256 checksums (fail-closed)
- `~/.vibefort/` is set to `0700`, config to `0600`
- Secret values from betterleaks are never stored or logged
- File scanning has a 10MB size limit and skips symlinks
- Rich markup in user-controlled strings is escaped
- `pip download` prefers wheels to avoid setup.py execution
- `npm pack` uses `--ignore-scripts` to prevent script execution during scan

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |

## Acknowledgments

We appreciate responsible disclosure. Security researchers who report valid vulnerabilities will be credited here (with permission).
