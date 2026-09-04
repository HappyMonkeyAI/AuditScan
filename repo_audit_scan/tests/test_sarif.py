import pytest
from repo_audit_scan.sarif import validate_sarif


def test_sarif_validator_accepts_minimal_valid_payload():
    validate_sarif({"version":"2.1.0", "runs":[{"tool":{"driver":{"name":"repo-audit-scan", "rules":[]}}, "results":[]}]})


def test_sarif_validator_rejects_unlinked_result():
    with pytest.raises(ValueError):
        validate_sarif({"version":"2.1.0", "runs":[{"tool":{"driver":{"name":"repo-audit-scan", "rules":[]}}, "results":[{"ruleId":"unknown", "message":{"text":"x"}}]}]})
