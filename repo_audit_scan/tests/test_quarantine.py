import pytest
from repo_audit_scan.quarantine import validate_github_source


def test_quarantine_rejects_non_github_and_credentials():
    with pytest.raises(ValueError):
        validate_github_source("https://example.com/a/b")
    with pytest.raises(ValueError):
        validate_github_source("https://user:pass@github.com/a/b")


def test_quarantine_accepts_github_https():
    validate_github_source("https://github.com/org/repo")
