from pathlib import Path

from repo_audit_scan.mcp_server import MCPServer


def test_quarantine_tool_rejects_prohibited_source_without_checkout():
    result = MCPServer().execute_tool("quarantine_and_scan_repository", source="http://example.com/repo")
    assert result["ok"] is False


def test_quarantine_tool_rewrites_assessment_provenance_and_cleanup(monkeypatch, tmp_path):
    staged = tmp_path / "staged"
    staged.mkdir()
    metadata = {"origin": "https://github.com/org/repo", "resolved_ref": "a" * 40, "content_digest": "b" * 64, "staging_root": str(tmp_path)}
    monkeypatch.setattr("repo_audit_scan.mcp_server.quarantine_repository", lambda *args, **kwargs: (staged, metadata))
    monkeypatch.setattr("repo_audit_scan.mcp_server.run_isolated_scan", lambda *args, **kwargs: {
        "assessment": {"target": {}, "checks": {"completed": []}, "check_details": []}, "findings": 0
    })
    result = MCPServer().quarantine_and_scan_repository("https://github.com/org/repo")
    assert result["assessment"]["target"]["resolved_ref"] == "a" * 40
    assert "quarantine_cleanup" in result["assessment"]["checks"]["completed"]
