---
type: episodic
tags: [dependency, enrichment, mcp, cli, testing]
created: 2026-05-28
related: [SPEC.md, TASKS.md, PROGRESS.md]
blast_radius: [repo_audit_scan/cli.py, repo_audit_scan/mcp_server.py, repo_audit_scan/dependency_enrichment.py]
confidence: high
---

# T-016 Walkthrough — Dependency enrichment

## Outcome
Implemented lockfile-based dependency findings by default, plus opt-in OSV enrichment gated by env/config intent with fail-open behavior.

## Changed Files
- `repo_audit_scan/dependency_enrichment.py`
- `repo_audit_scan/cli.py`
- `repo_audit_scan/mcp_server.py`
- `repo_audit_scan/tests/test_dependency_enrichment.py`
- `repo_audit_scan/tests/test_cli.py`
- `repo_audit_scan/tests/test_mcp_server.py`
- `TASKS.md`
- `PROGRESS.md`

## Verification
- Ran:
  - `.venv/bin/python -m pytest -q repo_audit_scan/tests/test_dependency_enrichment.py repo_audit_scan/tests/test_cli.py repo_audit_scan/tests/test_mcp_server.py`
- Result:
  - `12 passed`

## Notes
- Enrichment is intentionally opt-in and additionally gated by `REPO_AUDIT_DEP_ENRICHMENT=true`.
- On enrichment failures, scan remains successful by default (`fail_open`), preserving lockfile-only findings.
