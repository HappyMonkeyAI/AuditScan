---
type: episodic
tags: [walkthrough, fixtures, integration-test, end-to-end, T-019, mvp-complete]
created: 2026-05-30
related: [README.md, tests/fixtures/README.md]
blast_radius: [tests, fixtures]
confidence: high
---

# T-019 — Fixture repositories + end-to-end scan integration (walkthrough)

## What was built
Repo-shaped fixtures and an integration test that drives the real
`_scan_repository` pipeline (inventory -> adapter resolution -> rules -> IAN
scoring -> Report) over directories, not isolated ScanContexts.

- `tests/fixtures/generic_clean_repo/` — clean polyglot repo (Python, JS, pinned
  workflow) that yields ZERO findings (SPEC §16 #1).
- `tests/fixtures/mixed_vulnerable_repo/` — vulnerabilities across all MVP
  adapters with correct paths: `.github/workflows/insecure.yml`,
  `wp-content/plugins/demo/plugin.php`, `app.py`, `server.js`.
- `repo_audit_scan/tests/test_scan_integration.py` — 4 tests.
- `tests/fixtures/README.md` — fixture set + SPEC §16 mapping.

## Key catch
Isolated adapter unit tests passed an explicit `file_path=".github/workflows/.."`
to the CI/CD adapter. A real directory scan resolves adapters by walking paths,
so the integration test is the first to prove the CI/CD adapter's path-based
`detect_language` actually fires through `FilesystemWalker`. Result: workflow
under `.github/workflows/` detected end-to-end; all 6 cicd rules fire.

## Verification
clean repo => 0 findings; mixed vulnerable repo => 14 findings across
php/python/js/ci-cd (categories: ci-cd, injection, access-control, api-security,
configuration), every finding with a positive IAN score. 133 passed across the
broader suite. Purely additive test scaffolding (no product logic change), so
the end-to-end pipeline run served as verification in place of dual Trident
auditors.

## Status
**MVP complete: 21/21.** Remaining work is roadmap (C#/.NET + Docker adapters,
Living Documentation Feedback Loop) and tracked follow-ups (regex per-pattern
timeout, broader rule coverage). Suggested next step: run the scanner end-to-end
against a real target repository.
