---
type: episodic
tags: [triage, reporting, scan-review, tests, t-012]
created: 2026-05-27
related: [repo_audit_scan/triage.py, repo_audit_scan/tests/test_triage.py, TASKS.md, PROGRESS.md]
blast_radius: [triage, reporting, tests, task-tracking]
confidence: high
---

# T-012 Triage Walkthrough

Implemented `repo_audit_scan/triage.py` with `TriageMarkdownWriter`, `ScanReviewMarkdownWriter`, and `TriageArtifactWriter`. Triage output selects findings by IAN order, optional limit, and optional minimum score; it emits ticket-ready Markdown with hypothesis status, remediation, acceptance criteria, verification steps, redacted evidence, and no external ticket side effects.

Added the pilot feedback loop as Markdown-only scan review output. Review journals list verdict options (`true_positive`, `false_positive`, `misclassified`, `needs_manual_review`) and provide rule-improvement/suppression notes for each finding so real scans can improve the scanner without deleting audit history.

Exported T-012 writers from `repo_audit_scan.__init__`. Verification: `uv run --extra dev python -m pytest -q` -> 86 passed.
