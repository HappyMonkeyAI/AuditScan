import pytest
from repo_audit_scan.semantic_review import ReviewCandidate, validate_review_response
from repo_audit_scan.mcp_probe_runner import run_fixed_probe


def test_semantic_review_rejects_ungrounded_and_commands():
    candidate = ReviewCandidate("ecg-001", "README.md", 1, 2, "candidate")
    with pytest.raises(ValueError):
        validate_review_response({"findings": [{"rule_id": "unknown", "file_path": "x", "start_line": 1, "end_line": 1}]}, [candidate])
    with pytest.raises(ValueError):
        validate_review_response({"findings": [{"rule_id": "ecg-001", "file_path": "README.md", "start_line": 1, "end_line": 2, "command": "rm -rf"}]}, [candidate])


def test_fixed_probe_is_allowlisted_and_degrades_when_unavailable():
    result = run_fixed_probe("local-target", "controlled_injection")
    assert result.status == "unavailable"
    with pytest.raises(ValueError):
        run_fixed_probe("local-target", "arbitrary_shell")
