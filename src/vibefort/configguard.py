"""Config guard — monitors sensitive dotfile changes."""

import hashlib
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import toml


@dataclass
class ConfigAlert:
    rule: str
    description: str
    severity: str
    file: str


# Watched files relative to $HOME
WATCHED_FILES = [
    ".ssh/config",
    ".ssh/authorized_keys",
    ".ssh/known_hosts",
    ".gitconfig",
    ".git-credentials",
    ".npmrc",
    ".pypirc",
    ".docker/config.json",
    ".kube/config",
    ".aws/credentials",
    ".aws/config",
]

# Human-readable descriptions for alert messages
FILE_DESCRIPTIONS: dict[str, str] = {
    ".ssh/config": "SSH config",
    ".ssh/authorized_keys": "SSH authorized keys",
    ".ssh/known_hosts": "SSH known hosts",
    ".gitconfig": "Git config",
    ".git-credentials": "Git credentials",
    ".npmrc": "npm config (may contain tokens)",
    ".pypirc": "PyPI config (may contain tokens)",
    ".docker/config.json": "Docker config (may contain tokens)",
    ".kube/config": "Kubernetes config",
    ".aws/credentials": "AWS credentials",
    ".aws/config": "AWS config (may contain credential_process)",
}


def _sha256_file(path: Path) -> str:
    """Return hex SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _get_home(home: Optional[str] = None) -> Path:
    """Return home directory as Path."""
    if home is not None:
        return Path(home)
    return Path.home()


def snapshot_config_files(checksums_path: str, home: Optional[str] = None) -> dict[str, str]:
    """SHA-256 hash each watched file that exists and save snapshot to TOML."""
    home_path = _get_home(home)
    checksums: dict[str, str] = {}

    for rel in WATCHED_FILES:
        full = home_path / rel
        if full.is_file():
            try:
                checksums[str(full)] = _sha256_file(full)
            except OSError:
                pass  # Skip files that become unreadable

    # Write snapshot atomically (temp file + rename)
    out = Path(checksums_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(out.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            toml.dump({"checksums": checksums}, f)
        os.replace(tmp, str(out))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

    return checksums


def check_config_changes(
    checksums_path: str, home: Optional[str] = None
) -> List[ConfigAlert]:
    """Compare current file hashes against previous snapshot and return alerts."""
    snap_path = Path(checksums_path)
    home_path = _get_home(home)

    # If no previous snapshot, take one and return empty
    if not snap_path.is_file():
        snapshot_config_files(checksums_path, home=home)
        return []

    # Load previous snapshot
    try:
        with open(snap_path) as f:
            data = toml.load(f)
        old_checksums: dict[str, str] = data.get("checksums", {})
    except (toml.TomlDecodeError, ValueError, OSError):
        # Corrupted snapshot — warn and re-create baseline
        snapshot_config_files(checksums_path, home=home)
        return [ConfigAlert(
            rule="config-snapshot-corrupted",
            description="Config guard snapshot was corrupted — re-creating baseline. Review watched files.",
            severity="high",
            file=str(snap_path),
        )]

    # Compute current checksums
    current: dict[str, str] = {}
    alerts_pre: List[ConfigAlert] = []
    for rel in WATCHED_FILES:
        full = home_path / rel
        if full.is_file():
            try:
                current[str(full)] = _sha256_file(full)
            except OSError:
                pass  # Skip files that become unreadable
        # Check if watched file is a symlink (security concern)
        if full.is_symlink():
            desc_name = FILE_DESCRIPTIONS.get(rel, rel)
            alerts_pre.append(ConfigAlert(
                rule="config-symlink",
                description=f"{desc_name} is a symlink — may point to unexpected location",
                severity="high",
                file=str(full),
            ))

    alerts: List[ConfigAlert] = list(alerts_pre)

    for filepath, new_hash in current.items():
        # Determine relative path for description lookup
        try:
            rel = str(Path(filepath).relative_to(home_path))
        except ValueError:
            rel = filepath
        desc_name = FILE_DESCRIPTIONS.get(rel, rel)

        if filepath not in old_checksums:
            alerts.append(ConfigAlert(
                rule="config-new-file",
                description=f"{desc_name} appeared",
                severity="high",
                file=filepath,
            ))
        elif old_checksums[filepath] != new_hash:
            alerts.append(ConfigAlert(
                rule="config-modified",
                description=f"{desc_name} modified",
                severity="high",
                file=filepath,
            ))

    # Check for deleted files
    for filepath in old_checksums:
        if filepath not in current:
            try:
                rel = str(Path(filepath).relative_to(home_path))
            except ValueError:
                rel = filepath
            desc_name = FILE_DESCRIPTIONS.get(rel, rel)
            alerts.append(ConfigAlert(
                rule="config-deleted",
                description=f"{desc_name} was deleted",
                severity="high",
                file=filepath,
            ))

    # Update snapshot
    snapshot_config_files(checksums_path, home=home)

    return alerts
