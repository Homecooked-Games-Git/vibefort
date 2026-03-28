from pathlib import Path
from vibefort.codescan import scan_directory


def test_detects_sql_injection(tmp_path):
    (tmp_path / "app.py").write_text('cursor.execute(f"SELECT * FROM users WHERE id={user_id}")\n')
    findings = scan_directory(tmp_path)
    assert any(f.rule == "sql-injection" for f in findings)


def test_detects_pickle_load(tmp_path):
    (tmp_path / "utils.py").write_text('data = pickle.loads(user_input)\n')
    findings = scan_directory(tmp_path)
    assert any(f.rule == "insecure-deserialize" for f in findings)


def test_detects_shell_true(tmp_path):
    (tmp_path / "run.py").write_text('subprocess.run(cmd, shell=True)\n')
    findings = scan_directory(tmp_path)
    assert any(f.rule == "command-injection" for f in findings)


def test_detects_debug_mode(tmp_path):
    (tmp_path / "settings.py").write_text('DEBUG = True\n')
    findings = scan_directory(tmp_path)
    assert any(f.rule == "debug-mode" for f in findings)


def test_detects_xss_innerhtml(tmp_path):
    (tmp_path / "app.js").write_text('element.innerHTML = userInput;\n')
    findings = scan_directory(tmp_path)
    assert any(f.rule == "xss" for f in findings)


def test_detects_env_not_gitignored(tmp_path):
    (tmp_path / ".env").write_text('SECRET_KEY=abc123\n')
    (tmp_path / ".gitignore").write_text('*.pyc\n')
    findings = scan_directory(tmp_path)
    assert any(f.rule == "env-not-gitignored" for f in findings)


def test_clean_project(tmp_path):
    (tmp_path / "app.py").write_text('print("hello world")\n')
    findings = scan_directory(tmp_path)
    assert len(findings) == 0


def test_skips_node_modules(tmp_path):
    nm = tmp_path / "node_modules" / "evil"
    nm.mkdir(parents=True)
    (nm / "index.js").write_text('eval(user_input)\n')
    findings = scan_directory(tmp_path)
    assert len(findings) == 0
