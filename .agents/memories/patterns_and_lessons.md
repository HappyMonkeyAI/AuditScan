---
type: procedural
tags: [patterns, lessons, postmortems]
created: 2026-05-26
related: []
blast_radius: [all]
confidence: high
---

# Patterns & Lessons

Procedural memory for this project. Contains two streams:

1. **Patterns that worked** — repeatable approaches we want future sessions
   to reach for first.
2. **"Never again" lessons** — failures and the corrective rule that came
   out of them.

Both streams are **synthesised, not appended**. When a new entry would
duplicate an existing one, fold it in and update the abstraction. Memory is
context-independent: an entry should read correctly six months from now
without surrounding chatter.

---

## Patterns

### P-001 — Spec-driven, AGENTS-driven loop

When kicking off implementation work, Claude reads `SPEC.md` and `AGENTS.md`
before writing any code. The spec is the contract; AGENTS.md is the
operating rules. Plans and PRs that deviate from either must call out the
deviation explicitly.

**Source:** AI Accelerator Day 1 workflow.
**Confirmed on:** 2026-05-30 (T-007).

### P-002 — Adding a language adapter

To add a stack adapter: subclass `LanguageAdapter` in
`repo_audit_scan/adapters_final.py` (implement `language`,
`supported_frameworks`, `detect_language`, `supports_rule`, `scan`); reuse the
shared `_scan_regex_checks(self, ctx, rule)` helper for ordinary `regex`
checks, and add a dedicated check-type branch in `scan()` only for richer,
stateful detectors (e.g. PHP's `wp_ajax_missing_guard`). Wire it in three
places: `AdapterRegistry._load_builtin_adapters`, `supported_extensions`, and
the `adapters.py` re-export. Add matching rules to
`tests/fixtures/rules/sample_rules.json` — descriptions should name the
language so `supports_rule` cross-adapter exclusion stays clean (keep every
adapter's language-marker list symmetric; when adding a language, add its
marker to the *other* adapters too).

Adapters need not be extension-based: a `detect_language` may match on
path/filename instead (T-010 `CICDAdapter` matches `.github/workflows/*.yml`,
`Jenkinsfile`, `.gitlab-ci.yml`, etc.). `resolve_adapter` receives the full
path and returns the first adapter whose `detect_language` matches; register
path-based adapters so they only claim genuine matches (never bare `.yml`).
For non-language adapters, scope `supports_rule` to the relevant rule
categories (e.g. `ci-cd`) and add purpose-built rules for cross-cutting
concerns (CI secret exposure via `cicd-005/006`) rather than importing noisy
language-tagged rules from other categories.

**Confirmed on:** 2026-05-30 (T-007 PHP/WordPress, T-010 CI/CD).

---

## "Never Again" Lessons

### L-001 — Security heuristics: match call-expressions, not substrings

A guard/sink heuristic must strip comments first and require the token to be a
*call* (`token\s*\(`), never a bare substring. Bare substring matching lets a
token in a `// comment`, a string, or an unrelated identifier
(`current_user_can_view`) mask a real vulnerability — a false negative, the
worst failure mode for a security scanner. Emit such heuristic findings at
MEDIUM confidence and document the limitation. Surfaced reviewing T-007's
`PhpAdapter._has_guard`. Corollary (T-009): a bare-substring rule like
`dangerouslySetInnerHTML` matches prose, so (a) write detectors as usage forms
(`dangerouslySetInnerHTML\s*=`) and (b) never let a "safe" fixture mention a
banned token in a comment — it will trip the very rule it claims to be clean
of.

### L-003 — Unanchored alternation rules + default-allow scoping cause false positives

Surfaced dogfooding on a real repo (LLM-Codex-Reference-Vault): `docker-001`'s
pattern `ENV.*PASSWORD|SECRET|KEY` parses (precedence) as
`(ENV.*PASSWORD) | SECRET | KEY`, so it matched the substring `KEY` in
`DEVTO_API_KEY = os.getenv(...)` — a *secure* env read. Two compounding causes:
(1) unanchored alternation without grouping; always group alternations and
anchor to a real assignment/usage form. (2) The rule is Docker-scoped but ran on
a `.py` file because `LanguageAdapter.supports_rule` is default-allow (only
excludes rules naming *another* language). Fix applied: anchor the pattern to a
Dockerfile `ENV/ARG <SECRET_NAME>=<literal>` assignment (exclude `${...}` and
bare declarations). Open follow-up: move `supports_rule` toward default-deny so
stack-tagged rules only run on their stack's files.

### L-002 — The sandbox mount serves stale/truncated copies of edited files

Files written via the Edit/Write tools land correctly in the real working
tree (the Read tool is authoritative) but the `mcp__workspace__bash` mount can
serve a truncated or intermediate snapshot — causing phantom `SyntaxError`s
and pytest collecting stale counts. Do **not** trust in-sandbox `pytest` on
freshly edited files. Verify by reconstructing a clean copy under `/tmp`
(copy the package, overwrite the edited files with authoritative content) and
run there, or validate logic with a standalone import harness. Cost ~30 min on
T-007 before the divergence was diagnosed.

---

## How to Add an Entry

1. Decide which stream it belongs in (Pattern or Lesson).
2. Search existing entries for the same idea. If one exists, **edit it**,
   don't append. Bump its date.
3. Keep entries terse. Two paragraphs maximum. No play-by-play.
4. Tag the relevant memory file in the frontmatter `related` list so the
   pre-task enrichment step can pull this in alongside the related context.
