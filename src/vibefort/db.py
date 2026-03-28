"""SQLite database for scan history and stats."""

import os
import stat
import sqlite3
from datetime import datetime

import vibefort.constants as constants


def _get_conn() -> sqlite3.Connection:
    constants.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    # Set restrictive umask before creating DB file
    old_umask = os.umask(0o077)
    try:
        conn = sqlite3.connect(str(constants.DB_PATH))
    finally:
        os.umask(old_umask)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            target TEXT NOT NULL,
            result TEXT NOT NULL,
            details TEXT
        )
    """)
    conn.commit()
    return conn


def log_scan(scan_type: str, target: str, result: str, details: str = ""):
    """Log a scan result."""
    conn = _get_conn()
    conn.execute(
        "INSERT INTO scan_log (timestamp, scan_type, target, result, details) VALUES (?, ?, ?, ?, ?)",
        (datetime.now().isoformat(), scan_type, target, result, details),
    )
    conn.commit()
    conn.close()


def get_last_scan() -> dict | None:
    """Get the most recent scan entry."""
    conn = _get_conn()
    row = conn.execute(
        "SELECT timestamp, scan_type, target, result FROM scan_log ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()
    if row:
        return {"timestamp": row[0], "type": row[1], "target": row[2], "result": row[3]}
    return None
