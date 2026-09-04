import sys
from pathlib import Path
from repo_audit_scan.mcp_server import MCPServer


def test_configured_mcp_target_is_degraded_without_operator_command(monkeypatch):
    monkeypatch.delenv("AUDITSCAN_TRUSTED_MCP_COMMAND", raising=False)
    result = MCPServer().assess_configured_mcp_target()
    assert result["status"] == "degraded"
    assert result["disposition"] == "needs_human_review"
    assert len(result["probes"]) == 4


def test_configured_mcp_target_runs_trusted_fixture(monkeypatch):
    fixture = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "mcp_targets" / "trusted_inert_server.py"
    monkeypatch.setenv("AUDITSCAN_TRUSTED_MCP_COMMAND", f"{sys.executable} {fixture}")
    result = MCPServer().assess_configured_mcp_target()
    assert result["status"] == "complete"
    assert result["disposition"] == "allow_review"
