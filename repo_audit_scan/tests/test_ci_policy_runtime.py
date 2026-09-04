import pytest

from repo_audit_scan.ci_policy import enforce_disposition


@pytest.mark.parametrize("disposition", ["block", "needs_human_review"])
def test_ci_policy_fails_closed(disposition):
    with pytest.raises(RuntimeError):
        enforce_disposition(disposition)


def test_ci_policy_allows_only_reviewable_results():
    enforce_disposition("allow_review")
    enforce_disposition(None)
