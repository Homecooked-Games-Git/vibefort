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


def test_detects_hardcoded_password(tmp_path):
    (tmp_path / "config.py").write_text('password = "mysecretpassword123"\n')
    findings = scan_directory(tmp_path)
    assert any(f.rule == "hardcoded-password" for f in findings)


def test_detects_cors_wildcard(tmp_path):
    (tmp_path / "app.py").write_text('response.headers["Access-Control-Allow-Origin"] = "*"\n')
    findings = scan_directory(tmp_path)
    assert any(f.rule == "cors-wildcard" for f in findings)


def test_detects_eval_on_input(tmp_path):
    (tmp_path / "app.py").write_text('result = eval(input("Enter expression: "))\n')
    findings = scan_directory(tmp_path)
    assert any(f.rule == "code-injection" for f in findings)


def test_detects_os_system(tmp_path):
    (tmp_path / "app.py").write_text('os.system(user_input)\n')
    findings = scan_directory(tmp_path)
    assert any(f.rule == "command-injection" for f in findings)


def test_detects_js_eval(tmp_path):
    (tmp_path / "app.js").write_text('var result = eval(userInput);\n')
    findings = scan_directory(tmp_path)
    assert any(f.rule == "code-injection" for f in findings)


def test_detects_js_sql_injection(tmp_path):
    (tmp_path / "db.js").write_text('db.query(`SELECT * FROM users WHERE id=${userId}`);\n')
    findings = scan_directory(tmp_path)
    assert any(f.rule == "sql-injection" for f in findings)


def test_skips_venv_directory(tmp_path):
    venv = tmp_path / ".venv" / "lib"
    venv.mkdir(parents=True)
    (venv / "evil.py").write_text('eval(input())\n')
    findings = scan_directory(tmp_path)
    assert len(findings) == 0


def test_skips_symlinks(tmp_path):
    real = tmp_path / "real.py"
    real.write_text('print("safe")\n')
    link = tmp_path / "link.py"
    link.symlink_to(real)
    findings = scan_directory(tmp_path)
    assert len(findings) == 0  # The real file is safe, symlink is skipped


def test_env_not_in_gitignore(tmp_path):
    (tmp_path / ".env").write_text("SECRET=abc\n")
    (tmp_path / ".gitignore").write_text("*.pyc\n")
    findings = scan_directory(tmp_path)
    assert any(f.rule == "env-not-gitignored" for f in findings)


def test_env_in_gitignore_ok(tmp_path):
    (tmp_path / ".env").write_text("SECRET=abc\n")
    (tmp_path / ".gitignore").write_text(".env\n")
    findings = scan_directory(tmp_path)
    assert not any(f.rule == "env-not-gitignored" for f in findings)


def test_scans_typescript(tmp_path):
    (tmp_path / "app.ts").write_text('element.innerHTML = userInput;\n')
    findings = scan_directory(tmp_path)
    assert any(f.rule == "xss" for f in findings)


def test_large_file_skipped(tmp_path):
    large = tmp_path / "big.py"
    large.write_text('eval(input())\n' * 1000000)  # ~15MB
    findings = scan_directory(tmp_path)
    assert len(findings) == 0  # Skipped due to size
