# Test fixtures

Fixture repositories and rule data used by the test suite. Per-adapter fixtures
pair a `vulnerable` and a `safe` variant so detectors can be checked for both
true positives and the absence of false positives. The repo-shaped fixtures
(`generic_clean_repo`, `mixed_vulnerable_repo`) are scanned through the full
`_scan_repository` pipeline by `repo_audit_scan/tests/test_scan_integration.py`.

| Fixture | Purpose | SPEC §16 scenario |
|---------|---------|-------------------|
| `generic_clean_repo/` | Clean polyglot repo (Python, JS, pinned workflow) — full scan yields zero findings. | #1 (clean repo) |
| `mixed_vulnerable_repo/` | Polyglot repo with correctly-pathed vulnerabilities across all MVP adapters: `.github/workflows/insecure.yml`, `wp-content/plugins/demo/plugin.php`, `app.py`, `server.js`. Exercises path-based CI/CD detection end-to-end. | #2–#5 combined |
| `php_wordpress_ajax_no_capability/` | WordPress AJAX handler missing nonce/capability ({vulnerable,safe}). | #2 |
| `python_app/` | Python sinks: subprocess/eval/pickle/CORS/path-traversal ({vulnerable,safe}). | #4 |
| `js_app/` | JS/TS sinks: exec/SSRF/eval/proto/localStorage/XSS ({vulnerable,safe}). | #5 |
| `cicd_github_actions/` | GitHub Actions detectors, unit-level ({vulnerable,safe}). | — |
| `mixed_language_repo/` | Inventory/walker fixture: language & framework detection, excludes, binary, size. | — |
| `rules/sample_rules.json` | The bundled rule set (133 rules / 25 categories). | — |
| `external_content/` | Hostile external-content surfaces plus benign Three.js documentation; read-only fixture baseline for ECG-002. | ECG-002 |

Notes:
- A "safe" fixture must never name a banned token in a comment — a bare-substring
  rule would match the comment (see `.agents/memories/patterns_and_lessons.md`
  L-001). Detectors are written as usage forms to avoid this.
- The CI/CD adapter matches by path, so end-to-end CI/CD coverage requires the
  workflow to live under `.github/workflows/` (as in `mixed_vulnerable_repo`).
- SPEC scenario #6 (.NET auth gap) is roadmap: C#/.NET is loadable seed-only and
  not MVP-complete, so no dedicated fixture is shipped yet.
