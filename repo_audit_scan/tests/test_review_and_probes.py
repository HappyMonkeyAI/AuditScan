import pytest
import sys
from repo_audit_scan.semantic_review import ReviewCandidate, validate_review_response
from repo_audit_scan.mcp_probe_runner import PROBES, run_fixed_probe


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


def test_trusted_fixture_runs_all_fixed_probes(monkeypatch):
    fixture = __import__("pathlib").Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "mcp_targets" / "trusted_inert_server.py"
    monkeypatch.setenv("AUDITSCAN_TRUSTED_MCP_COMMAND", f"{sys.executable} {fixture}")
    results = [run_fixed_probe("trusted", probe) for probe in PROBES]
    assert [result.status for result in results] == ["completed"] * 4
