---
type: episodic
tags: [mcp, diagnostics, operational, tests, t-015]
created: 2026-05-27
related: [repo_audit_scan/mcp_server.py, repo_audit_scan/tests/test_mcp_server.py, TASKS.md, PROGRESS.md]
blast_radius: [mcp, diagnostics, status-surface, task-tracking]
confidence: high
---

# T-015 Operational Walkthrough

Extended `repo_audit_scan/mcp_server.py` with operational handlers for runtime observability and readiness: `server.get_info`, `server.get_health`, `server.get_status`, `diagnostics.validate_config`, `diagnostics.run_self_check`, and `reports.list_reports`.

Added uptime and last-scan tracking so status and health report useful server context during agent workflows. Kept output JSON-serializable and consistent with the MCP command wrappers already in place.

Expanded `repo_audit_scan/tests/test_mcp_server.py` to cover operational tool registration and handler response shapes. Verification: `uv run --extra dev python -m pytest -q` -> 94 passed.
