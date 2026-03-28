"""Betterleaks binary management and secret scanning."""

import hashlib
import json
import os
import stat
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path

import httpx

import vibefort.constants as constants

# SHA256 checksums for betterleaks v1.1.1 release binaries
# Source: https://github.com/betterleaks/betterleaks/releases/tag/v1.1.1
BETTERLEAKS_CHECKSUMS = {
    "betterleaks_1.1.1_darwin_arm64.tar.gz": "81eb78a8328f9159421855f282a03ad40c2cfeaa7c7a79f4c42308d705be31c4",
    "betterleaks_1.1.1_darwin_x64.tar.gz": "9462919fc8b625cc86f5ca216a0ca8366b1492c795f2a52710338e38875078f4",
    "betterleaks_1.1.1_linux_arm64.tar.gz": "97b774367630846a5f2298f7f3e3f8096f0567d3fc0275b1b63c0e1e16f856f1",
    "betterleaks_1.1.1_linux_x64.tar.gz": "d590d5f051e49f6769c61dc8cebbce947b20a4042e2915ee234760f81a01c8c4",
    "betterleaks_1.1.1_windows_arm64.zip": "27897dbe70defaa8ce5e2d0cbbcdbe49708376def2e8ec91ea48d39aa44b6440",
    "betterleaks_1.1.1_windows_x64.zip": "df3078b80fe0ec9144b10e34b1e29779f1e0e4ad5cbba430eea240b6a3894d70",
}


def _verify_checksum(file_path: Path, expected_hash: str) -> bool:
    """Verify SHA256 checksum of a downloaded file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest() == expected_hash


def is_betterleaks_installed() -> bool:
    return constants.BETTERLEAKS_PATH.exists() and os.access(constants.BETTERLEAKS_PATH, os.X_OK)


def download_betterleaks(*, progress_callback=None) -> Path:
    url = constants.get_betterleaks_download_url()
    constants.ensure_home_dir()
    constants.BIN_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(constants.BIN_DIR, stat.S_IRWXU)  # 0700 — owner only

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        archive_name = url.split("/")[-1]
        archive_path = tmp_path / archive_name

        with httpx.stream("GET", url, follow_redirects=True, timeout=120) as response:
            response.raise_for_status()
            total = int(response.headers.get("content-length", 0))
            downloaded = 0
            with open(archive_path, "wb") as f:
                for chunk in response.iter_bytes(chunk_size=8192):
                    f.write(chunk)
                    downloaded += len(chunk)
                    if progress_callback and total:
                        progress_callback(downloaded, total)

        # Verify checksum before extracting (fail-closed: reject unknown archives)
        expected = BETTERLEAKS_CHECKSUMS.get(archive_name)
        if not expected:
            raise RuntimeError(
                f"No known checksum for {archive_name}. "
                "Cannot verify integrity — refusing to install."
            )
        if not _verify_checksum(archive_path, expected):
            raise RuntimeError(
                f"Checksum verification failed for {archive_name}. "
                "The download may be corrupted or tampered with."
            )

        if archive_name.endswith(".tar.gz"):
            with tarfile.open(archive_path, "r:gz") as tar:
                for member in tar.getmembers():
                    if member.name == "betterleaks" or member.name.endswith("/betterleaks"):
                        member.name = "betterleaks"
                        tar.extract(member, constants.BIN_DIR, filter="data")
                        break
        elif archive_name.endswith(".zip"):
            with zipfile.ZipFile(archive_path) as zf:
                for name in zf.namelist():
                    if "betterleaks" in name.lower():
                        data = zf.read(name)
                        constants.BETTERLEAKS_PATH.write_bytes(data)
                        break

        # Owner-only executable (0700)
        constants.BETTERLEAKS_PATH.chmod(stat.S_IRWXU)

    return constants.BETTERLEAKS_PATH


def run_betterleaks_on_files(file_paths: list[str]) -> list[dict]:
    if not is_betterleaks_installed() or not file_paths:
        return []

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp) / "scan"
        tmp_path.mkdir()

        # Map temp filenames back to original paths
        name_to_original: dict[str, str] = {}
        for fp in file_paths:
            src = Path(fp)
            if src.exists():
                dest = tmp_path / src.name
                dest.write_bytes(src.read_bytes())
                name_to_original[src.name] = fp

        report_path = Path(tmp) / "report.json"

        cmd = [
            str(constants.BETTERLEAKS_PATH), "dir",
            "--report-format", "json",
            "--report-path", str(report_path),
            "--no-banner",
            str(tmp_path),
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            return []

        # Read findings from report file
        raw = ""
        if report_path.exists():
            raw = report_path.read_text()
        else:
            raw = result.stdout

        findings = parse_betterleaks_output(raw)

        # Filter out allowed files and rules
        from vibefort.allowlist import is_file_allowed, is_rule_allowed
        findings = [f for f in findings if not is_file_allowed(f["file"]) and not is_rule_allowed(f["rule"])]

        # Replace temp paths with original filenames
        for f in findings:
            temp_name = Path(f["file"]).name
            if temp_name in name_to_original:
                f["file"] = name_to_original[temp_name]

        return findings


def parse_betterleaks_output(raw: str) -> list[dict]:
    if not raw or not raw.strip():
        return []

    try:
        entries = json.loads(raw)
    except json.JSONDecodeError:
        return []

    findings = []
    for entry in entries:
        findings.append({
            "file": entry.get("File", "unknown"),
            "line": entry.get("StartLine", 0),
            "rule": entry.get("RuleID", "unknown"),
            "description": entry.get("Description", "Secret detected"),
            # Intentionally NOT including "Match" — never store actual secret values
        })

    return findings
