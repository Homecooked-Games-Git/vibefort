from pathlib import Path
from vibefort.allowlist import is_package_allowed, is_file_allowed, is_rule_allowed


def test_package_allowed(tmp_path, monkeypatch):
    config = tmp_path / ".vibefort.toml"
    config.write_text('[allow-packages]\n"my-internal-pkg" = "private registry"\n')
    monkeypatch.chdir(tmp_path)
    assert is_package_allowed("my-internal-pkg") is True
    assert is_package_allowed("unknown-pkg") is False


def test_file_allowed(tmp_path, monkeypatch):
    config = tmp_path / ".vibefort.toml"
    config.write_text('[allow-files]\n"tests/fake_keys.py" = "test dummy keys"\n')
    monkeypatch.chdir(tmp_path)
    assert is_file_allowed("tests/fake_keys.py") is True
    assert is_file_allowed("src/real_config.py") is False


def test_rule_allowed(tmp_path, monkeypatch):
    config = tmp_path / ".vibefort.toml"
    config.write_text('[allow-rules]\n"generic-api-key" = "too many false positives"\n')
    monkeypatch.chdir(tmp_path)
    assert is_rule_allowed("generic-api-key") is True
    assert is_rule_allowed("aws-access-key") is False


def test_no_config_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert is_package_allowed("anything") is False
    assert is_file_allowed("anything") is False
    assert is_rule_allowed("anything") is False


def test_malformed_config(tmp_path, monkeypatch):
    config = tmp_path / ".vibefort.toml"
    config.write_text("this is not valid toml {{{{")
    monkeypatch.chdir(tmp_path)
    assert is_package_allowed("anything") is False
