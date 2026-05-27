"""Tests for MCP server tool handlers."""

from __future__ import annotations

from pathlib import Path

from repo_audit_scan.mcp_server import MCPServer


def test_mcp_server_registers_default_tools():
    """Default MCP tool surface should be available."""
    server = MCPServer()
    tools = server.list_tools()

    assert "scan_repository" in tools
    assert "server.get_info" in tools
    assert "server.get_health" in tools
    assert "server.get_status" in tools
    assert "list_rules" in tools
    assert "get_finding" in tools
    assert "triage_report" in tools
    assert "verify_fix" in tools
    assert "get_latest_report" in tools
    assert "diagnostics.validate_config" in tools
    assert "diagnostics.run_self_check" in tools
    assert "reports.list_reports" in tools


def test_scan_and_triage_and_verify_flow(tmp_path):
    """MCP flow should produce reports, triage files, and verification output."""
    server = MCPServer()
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.js").write_text("panel.innerHTML = userInput;\n", encoding="utf-8")
    output_root = tmp_path / "reports"

    scan = server.scan_repository(
        path=str(repo),
        write_reports=True,
        mirror_to_target_repo=False,
        output_root=str(output_root),
    )
    report_id = scan["report_id"]
    report_json = Path(scan["workspace_paths"]["json"])
    assert report_json.exists()

    # Triage should consume the written report and emit artifacts.
    triage = server.triage_report(
        report=str(report_json),
        limit=1,
        output_dir=str(tmp_path / "triage"),
        pilot_name="mcp-pilot",
        review_notes=["pilot note"],
    )
    assert Path(triage["triage"]).exists()
    assert Path(triage["review"]).exists()

    # Fix file then verify.
    (repo / "app.js").write_text("panel.textContent = userInput;\n", encoding="utf-8")
    latest = server.get_latest_report(output_root=str(output_root))
    first_finding_id = latest["report"]["findings"][0]["finding_id"]
    verify = server.verify_fix(
        report=str(report_json),
        finding_id=first_finding_id,
    )
    assert verify["resolved"] is True
    assert verify["remaining_locations"] == []

    # get_finding should return the finding payload.
    found = server.get_finding(str(report_json), first_finding_id)
    assert found["report_id"] == report_id
    assert found["finding"]["finding_id"] == first_finding_id


def test_scan_repository_respects_workspace_only_default(tmp_path):
    """MCP scan should avoid target-repo mirroring unless explicitly requested."""
    server = MCPServer()
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text('api_key = "sk-test-1234"\n', encoding="utf-8")
    output_root = tmp_path / "reports"

    result = server.scan_repository(
        path=str(repo),
        write_reports=True,
        mirror_to_target_repo=False,
        output_root=str(output_root),
    )
    assert "workspace_paths" in result
    assert "mirror_paths" not in result


def test_operational_handlers_return_expected_shapes(tmp_path):
    """Operational handlers should expose info, health, status, diagnostics, and reports list."""
    server = MCPServer()
    info = server.get_info()
    assert info["name"] == "repo-audit-scan"
    assert "tools" in info

    health = server.get_health()
    assert health["status"] in {"ok", "degraded"}
    assert isinstance(health["uptime_seconds"], int)

    status = server.get_status()
    assert status["status"] == "ready"
    assert status["tool_count"] >= 1

    validate = server.validate_config(output_root=str(tmp_path / "reports"))
    assert "valid" in validate
    assert "checks" in validate

    self_check = server.run_self_check(output_root=str(tmp_path / "reports"))
    assert "ok" in self_check
    assert "diagnostics" in self_check

    listed = server.list_reports(output_root=str(tmp_path / "reports"))
    assert listed["count"] == 0
    assert listed["reports"] == []
