from vibefort.scanner.cve import check_cve, check_cve_pip, check_cve_npm


def test_check_cve_returns_list():
    """Basic smoke test — should return a list (may be empty)."""
    result = check_cve("doesnt-exist-pkg-xyz", ecosystem="PyPI")
    assert isinstance(result, list)


def test_check_cve_pip_wrapper():
    result = check_cve_pip("doesnt-exist-pkg-xyz")
    assert isinstance(result, list)


def test_check_cve_npm_wrapper():
    result = check_cve_npm("doesnt-exist-pkg-xyz")
    assert isinstance(result, list)
