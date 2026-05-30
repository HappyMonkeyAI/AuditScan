---
type: episodic
tags: [walkthrough, adapter, ci-cd, github-actions, T-010]
created: 2026-05-30
related: [.agents/memories/patterns_and_lessons.md, .agents/memories/history/walkthroughs/20260530_123000_T-007_php_wordpress_adapter_walkthrough.md]
blast_radius: [adapters, rules]
confidence: high
---

# T-010 — CI/CD adapter (walkthrough)

## What was built
`CICDAdapter` (`repo_audit_scan/adapters_final.py`). Unlike language adapters,
detection is path/filename-based: `.github/workflows/*.yml|yaml`,
`.gitlab-ci.yml`, `.circleci/config.yml`, `azure-pipelines.yml`,
`.travis.yml`, `Jenkinsfile[.env]`. `language` = `ci-cd`. `supports_rule`
scoped to `ci-cd`/`cicd`/`ci-`/`supply-chain` rules. `scan` delegates to the
shared `_scan_regex_checks`. Registered as the 6th builtin adapter and
re-exported from `adapters.py`. Plain `.yml`/`.yaml` is left unclaimed, so
existing language resolution is unchanged.

## Rules (sample_rules.json -> 112)
`cicd-001` pull_request_target; `cicd-002` `permissions: write-all`;
`cicd-003` unpinned action (regex with negative lookahead flags mutable refs
but not a 40-char SHA); `cicd-004` script injection via `${{ github.event.* }}`;
`cicd-005` secret echoed to logs; `cicd-006` hardcoded secret literal (AKIA +
keyword:literal, excludes `${{ secrets.* }}` via negative lookahead).

## Audit outcome
Both auditors APPROVE-WITH-CONDITIONS. Both flagged that scoping out
`secrets`-category rules left hardcoded secrets in pipelines uncaught — closed
by purpose-built `cicd-006` (avoids importing noisy `docker-001` which fires on
any KEY/SECRET line). Documented limitations in the docstring: granular
over-permissions not flagged (write-all only); `cicd-004` is `github.event`-only
and context-insensitive (flags the env-var mitigation too); composite/
`docker://` actions not analysed; input bounded by the 10MB inventory cap.

## Verification
30 standalone logic checks; all 6 detectors fire on `vulnerable.yml`,
`safe.yml` clean; 129 pass across the rest of the suite. Real `pytest -q`
~124. Fixtures: `tests/fixtures/cicd_github_actions/{vulnerable,safe}.yml`;
9 `TestCICDAdapter` tests.

## Gotcha
Sandbox mount again served truncated copies of edited files (L-002):
`vulnerable.yml` lost its tail in the mount, dropping `cicd-005`. Verified the
real file via Grep and validated against authoritative content written into
/tmp.
