from vibefort.scanner.tier1 import is_known_safe, check_typosquatting, tier1_scan


def test_known_safe_package():
    assert is_known_safe("flask") is True
    assert is_known_safe("numpy") is True
    assert is_known_safe("requests") is True


def test_known_safe_npm():
    assert is_known_safe("express", "npm") is True
    assert is_known_safe("react", "npm") is True
    assert is_known_safe("lodash", "npm") is True


def test_unknown_package_not_safe():
    assert is_known_safe("xyzzy-not-a-real-package-12345") is False


def test_typosquatting_detects_close_names():
    result = check_typosquatting("reqeusts")
    assert result is not None
    assert result["similar_to"] == "requests"


def test_typosquatting_clean_for_legit():
    result = check_typosquatting("flask")
    assert result is None


def test_tier1_scan_safe_package():
    result = tier1_scan("flask")
    assert result.safe is True
    assert result.tier == 1


def test_tier1_scan_typosquat():
    result = tier1_scan("reqeusts")
    assert result.safe is False
    assert "typosquat" in result.reason.lower() or "similar" in result.reason.lower()
