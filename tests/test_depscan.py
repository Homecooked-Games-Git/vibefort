from pathlib import Path
from vibefort.depscan import (
    parse_requirements_txt,
    parse_package_json,
    parse_pyproject_toml,
    scan_dependencies,
    verify_package_lock,
    verify_poetry_lock,
)


def test_parse_requirements_txt(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("flask==3.1.0\nrequests>=2.28\nnumpy\n# comment\n-r other.txt\n")
    deps = parse_requirements_txt(req)
    assert ("flask", "3.1.0") in deps
    assert ("numpy", "") in deps
    assert len(deps) == 3


def test_parse_package_json(tmp_path):
    pkg = tmp_path / "package.json"
    pkg.write_text('{"dependencies": {"express": "^4.18.0"}, "devDependencies": {"jest": "~29.0.0"}}')
    deps = parse_package_json(pkg)
    assert ("express", "4.18.0") in deps
    assert ("jest", "29.0.0") in deps


def test_parse_pyproject_toml(tmp_path):
    pyp = tmp_path / "pyproject.toml"
    pyp.write_text('[project]\ndependencies = ["flask>=3.0", "click"]\n')
    deps = parse_pyproject_toml(pyp)
    assert len(deps) == 2


def test_scan_detects_typosquat(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("reqeusts==2.28.0\n")
    findings = scan_dependencies(tmp_path)
    assert any("typosquat" in f.issue.lower() for f in findings)


def test_scan_clean_deps(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("flask==3.1.0\nrequests==2.31.0\n")
    findings = scan_dependencies(tmp_path)
    # Should have no typosquat findings (CVE findings depend on live API)
    assert not any("typosquat" in f.issue.lower() for f in findings)


def test_package_lock_http_url(tmp_path):
    lock = tmp_path / "package-lock.json"
    lock.write_text('{"packages": {"node_modules/evil": {"version": "1.0.0", "resolved": "http://registry.npmjs.org/evil/-/evil-1.0.0.tgz"}}}')
    findings = verify_package_lock(lock)
    assert any("HTTP" in f.issue for f in findings)


def test_package_lock_missing_integrity(tmp_path):
    lock = tmp_path / "package-lock.json"
    lock.write_text('{"packages": {"node_modules/pkg": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz"}}}')
    findings = verify_package_lock(lock)
    assert any("Missing integrity" in f.issue for f in findings)


def test_package_lock_clean(tmp_path):
    lock = tmp_path / "package-lock.json"
    lock.write_text('{"packages": {"node_modules/pkg": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz", "integrity": "sha512-abc123"}}}')
    findings = verify_package_lock(lock)
    assert len(findings) == 0


def test_poetry_lock_missing_hashes(tmp_path):
    lock = tmp_path / "poetry.lock"
    lock.write_text('[[package]]\nname = "flask"\nversion = "3.1.0"\n')
    findings = verify_poetry_lock(lock)
    assert any("Missing file hashes" in f.issue for f in findings)
