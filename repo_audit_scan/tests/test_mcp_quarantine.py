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


def test_quarantine_mcp_handoff_preserves_block_and_redaction(monkeypatch, tmp_path):
    staged = tmp_path / "staged"
    staged.mkdir()
    metadata = {
        "origin": "https://github.com/org/repo",
        "resolved_ref": "c" * 40,
        "content_digest": "d" * 64,
        "staging_root": str(tmp_path),
    }
    worker_result = {
        "assessment": {
            "status": "blocked",
            "disposition": "block",
            "target": {},
            "checks": {"completed": ["deterministic_rules", "repo_security_scan"]},
            "check_details": [],
            "policy": {"read_source": True, "install": False, "execute": False, "register_mcp": False, "write_memory": False},
        },
        "findings": [{"rule_id": "external-secret-scan", "evidence": [{"code_snippet": "[REDACTED]"}]}],
    }
    monkeypatch.setattr("repo_audit_scan.mcp_server.quarantine_repository", lambda *args, **kwargs: (staged, metadata))
    monkeypatch.setattr("repo_audit_scan.mcp_server.run_isolated_scan", lambda *args, **kwargs: worker_result)
    result = MCPServer().quarantine_and_scan_repository("https://github.com/org/repo")
    assessment = result["assessment"]
    assert assessment["status"] == "blocked"
    assert assessment["disposition"] == "block"
    assert assessment["target"]["resolved_ref"] == "c" * 40
    assert assessment["target"]["content_digest"] == "d" * 64
    assert "quarantine_cleanup" in assessment["checks"]["completed"]
    assert result["findings"][0]["evidence"][0]["code_snippet"] == "[REDACTED]"
