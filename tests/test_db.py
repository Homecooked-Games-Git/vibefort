from vibefort.db import log_scan, get_last_scan


def test_log_and_get_scan(tmp_vibefort_home):
    log_scan("scan", "/tmp/project", "clean", "0")
    last = get_last_scan()
    assert last is not None
    assert last["target"] == "/tmp/project"
    assert last["result"] == "clean"


def test_get_last_scan_empty(tmp_vibefort_home):
    last = get_last_scan()
    assert last is None


def test_log_multiple_scans(tmp_vibefort_home):
    log_scan("scan", "/tmp/a", "clean", "0")
    log_scan("scan", "/tmp/b", "issues", "3")
    last = get_last_scan()
    assert last["target"] == "/tmp/b"
    assert last["result"] == "issues"
