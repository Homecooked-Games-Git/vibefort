"""Betterleaks binary management and secret scanning."""

import json
import os
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path

import httpx

import vibefort.constants as constants


def is_betterleaks_installed() -> bool:
    return constants.BETTERLEAKS_PATH.exists() and os.access(constants.BETTERLEAKS_PATH, os.X_OK)


def download_betterleaks(*, progress_callback=None) -> Path:
    url = constants.get_betterleaks_download_url()
    constants.BIN_DIR.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        archive_name = url.split("/")[-1]
        archive_path = tmp_path / archive_name

        with httpx.stream("GET", url, follow_redirects=True) as response:
            response.raise_for_status()
            total = int(response.headers.get("content-length", 0))
            downloaded = 0
            with open(archive_path, "wb") as f:
                for chunk in response.iter_bytes(chunk_size=8192):
                    f.write(chunk)
                    downloaded += len(chunk)
                    if progress_callback and total:
                        progress_callback(downloaded, total)

        if archive_name.endswith(".tar.gz"):
            with tarfile.open(archive_path, "r:gz") as tar:
                for member in tar.getmembers():
                    if member.name == "betterleaks" or member.name.endswith("/betterleaks"):
                        member.name = "betterleaks"
                        tar.extract(member, constants.BIN_DIR)
                        break
        elif archive_name.endswith(".zip"):
            with zipfile.ZipFile(archive_path) as zf:
                for name in zf.namelist():
                    if "betterleaks" in name.lower():
                        data = zf.read(name)
                        constants.BETTERLEAKS_PATH.write_bytes(data)
                        break

        constants.BETTERLEAKS_PATH.chmod(constants.BETTERLEAKS_PATH.stat().st_mode | 0o755)

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
            "match": entry.get("Match", ""),
        })

    return findings
