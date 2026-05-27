---
type: episodic
tags: [verification, cli, mcp, dependency, parity]
created: 2026-05-28
related: [SPEC.md, TASKS.md, PROGRESS.md]
blast_radius: [repo_audit_scan/cli.py, repo_audit_scan/tests/test_cli.py, repo_audit_scan/tests/test_mcp_server.py]
confidence: high
---

# T-017 Walkthrough — verify_fix parity hardening

## Outcome
Hardened verify behavior for CLI and MCP so non-adapter findings (especially dependency lockfile findings) are re-checked correctly.

## Changed Files
- `repo_audit_scan/cli.py`
- `repo_audit_scan/tests/test_cli.py`
- `repo_audit_scan/tests/test_mcp_server.py`
- `TASKS.md`
- `PROGRESS.md`

## Verification
- Ran:
  - `.venv/bin/python -m pytest -q repo_audit_scan/tests/test_cli.py repo_audit_scan/tests/test_mcp_server.py`
- Result:
  - `12 passed`

## Notes
- Adapter-backed rule verification remains unchanged.
- Added fallback snippet recheck when no adapter path applies, preventing false-positive resolution status.
