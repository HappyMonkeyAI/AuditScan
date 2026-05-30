---
type: episodic
tags: [walkthrough, adapter, php, wordpress, T-007]
created: 2026-05-30
related: [.agents/memories/patterns_and_lessons.md]
blast_radius: [adapters, rules, reporting]
confidence: high
---

# T-007 — PHP/WordPress adapter (walkthrough)

## What was built
`PhpAdapter` (`repo_audit_scan/adapters_final.py`) implementing the
`LanguageAdapter` contract: detects `.php/.phtml/.php3-5`; frameworks
wordpress, laravel, symfony, drupal, codeigniter; `supports_rule` excludes
other-language rules. `scan()` delegates ordinary `regex` checks to the new
shared `_scan_regex_checks` helper and branches to a WordPress-aware
`wp_ajax_missing_guard` check for AC-001.

## WordPress AJAX guard heuristic
`_scan_wp_ajax_guard` finds `add_action('wp_ajax[_nopriv]_*', 'cb')`
registrations, scopes to the callback body via `_function_body`, and flags
handlers where `_has_guard` finds no nonce/capability **call**. `_has_guard`
strips comments and matches `token\s*\(` (post-audit hardening) to avoid
false negatives from commented or substring tokens. Findings emit at MEDIUM
confidence. File-level fallback when the callback body is not in-file.

## Rules / fixtures / tests
- `sample_rules.json` → 106 rules: `wp-ajax-001`, `php-004` (unserialize),
  `php-005` (eval), `php-006` (LFI). `php-002` already covers AC-002 SQLi.
- Fixtures: `tests/fixtures/php_wordpress_ajax_no_capability/{vulnerable,safe}-plugin.php`.
- `TestPhpAdapter` (13 tests) incl. comment-mask and substring-identifier
  regressions.

## Wiring
Registered in `AdapterRegistry` builtins + `supported_extensions` (`.php*`);
re-exported from `adapters.py`. Added `'php'` to `PythonAdapter` markers for
symmetric exclusion.

## Verification
25 standalone logic checks pass; 129 pass across the rest of the suite. Real
`pytest -q` → 113 (102 baseline + 11). Trident: both APPROVE-WITH-CONDITIONS;
guard hardening done; follow-ups logged (file-size cap; array/closure/
`Class::method` callbacks; word-boundary language markers).

## Gotcha
Sandbox bash mount served truncated copies of edited files — see L-002.
Verified against a reconstructed `/tmp` copy instead.
