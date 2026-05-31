# Architecture

`repo-audit-scan` is a local, read-only security audit scanner exposed through
both a CLI and an MCP server. This document describes how the pieces fit
together. For the product contract and acceptance criteria, see
[SPEC.md](SPEC.md).

## Pipeline

A scan is a linear pipeline. Each stage produces evidence the next stage
consumes.

```text
repository path
      │
      ▼
┌──────────────┐   inventory.py
│  Inventory   │   walk filesystem, detect languages/frameworks, Git metadata,
│              │   apply excludes + 10 MB size cap + binary/symlink guards
└──────┬───────┘
       │ files
       ▼
┌──────────────┐   adapter_registry.py + adapters_final.py
│  Adapters    │   resolve an adapter per file (by extension, or by path for
│  + Rules     │   CI/CD); run each supported rule's checks against content
└──────┬───────┘   rules.py: registry, dedupe, manual-confirmation
       │ RuleResults
       ▼
┌──────────────┐   scoring.py
│ IAN scoring  │   Impact/Accessibility/Necessity → composite; compromise-mode
│              │   classification; chain detection across related findings
└──────┬───────┘
       │ Findings
       ▼
┌──────────────┐   reporting.py + triage.py
│  Reporting   │   JSON + Markdown reports (redaction, provenance, prompt-
│  + Triage    │   injection markers); ticket-ready triage + scan-review
└──────┬───────┘
       │
       ▼  surfaced through cli.py (scan/rules/triage/verify)
         and mcp_server.py (12 tools)
```

Dependency findings are produced in parallel by `dependency_enrichment.py`
(lockfile parsing by default; opt-in OSV advisory enrichment) and merged into
the result set before scoring.

## Components

| Module | Responsibility |
|--------|----------------|
| `inventory.py` | `FilesystemWalker` + `RepositoryInventory`: directory walk with `.gitignore`-style excludes, 10 MB per-file cap, symlink guards; language detection by extension; framework detection by marker files. `git_utils.py` adds Git metadata with graceful degradation. |
| `rules.py` | `Rule` dataclass, `RuleRegistry` (load/get/list by id and category), `DuplicationHandler` (aggregate repeated matches into one finding with an evidence array), `ManualConfirmation` (confirmed/dismissed/deferred without deleting findings). |
| `scoring.py` | `IANScorer` (severity→impact, confidence→accessibility, category→necessity; composite = 0.40·I + 0.35·A + 0.25·N), `CompromiseModeClassifier`, `ChainDetector`. |
| `adapters_final.py` | `LanguageAdapter` ABC + `ScanContext`; six adapters (Python, JavaScript/TS, Java, C#, PHP/WordPress, CI/CD); shared `_scan_regex_checks` helper; `extract_evidence` for line/column/snippet. |
| `adapter_registry.py` | `AdapterRegistry` — builtin loading, `resolve_adapter`/`resolve_language`, custom registration, extension map. |
| `reporting.py` | JSON + Markdown writers; stable metadata, severity counts, IAN-ordered findings, redacted evidence, provenance + prompt-injection warnings. |
| `triage.py` | Ticket-ready triage Markdown (findings framed as hypotheses, IAN ordering, acceptance criteria, verification steps) + scan-review journal. |
| `dependency_enrichment.py` | Lockfile parsers (`requirements.txt`, `package-lock.json`, `composer.lock`); opt-in OSV query gated by flag + env; fails open. |
| `cli.py` | `scan` / `rules` / `triage` / `verify`; report mirroring defaults. |
| `mcp_server.py` | MCP tool handlers; uptime/last-scan state; workspace-only mirroring default. |
| `models.py` | `Finding`, `Report`, `RuleResult`, `Evidence`, `ScanMetadata`, `Severity`, `Confidence`. |
| `redaction.py` | `SecretRedactor` applied to evidence before output. |

## The adapter contract

An adapter implements five members:

- `language` — identifier (e.g. `"python"`, `"ci-cd"`).
- `supported_frameworks` — list of recognized frameworks.
- `detect_language(file_path)` — claim a file. Language adapters match by
  extension; the CI/CD adapter matches by path/filename so it only claims
  genuine pipeline files and never bare `.yml`.
- `supports_rule(rule)` — decide whether a rule applies. Language adapters use
  description language-markers for cross-language exclusion (a rule whose
  description names another language is skipped). The CI/CD adapter scopes to
  CI/CD-category rules.
- `scan(context, rule)` — run the rule's checks against file content, returning
  `RuleResult`s. Most checks are `type: regex`; adapters may add richer check
  types (e.g. PHP's `wp_ajax_missing_guard`, which scopes to a handler body and
  flags AJAX handlers lacking a nonce/capability guard).

Adapters are registered as builtins in `AdapterRegistry._load_builtin_adapters`
and re-exported from `adapters.py`. `resolve_adapter(path)` returns the first
adapter whose `detect_language` matches.

## Data model

A rule's `checks` produce `Evidence` (file, line, column, snippet, context),
aggregated into a `RuleResult`, scored into a `Finding` (adds IAN score,
compromise mode, prioritization rationale, affected-file count). A `Report`
bundles `ScanMetadata` with the prioritized findings and is serialized to JSON
and Markdown.

## CLI vs MCP

Both surfaces drive the same pipeline; they differ in report-mirroring
defaults. The **CLI** mirrors reports into the target repo's `audits/` folder
by default (the accelerator workflow). The **MCP server** writes to the tool
workspace only and never touches the target worktree unless the caller opts in
with `write_reports: true` and `mirror_to_target_repo: true` — so an
MCP-driven agent cannot surprise the user by dirtying their repo.

## Safety model

Repository content is untrusted input. The scanner redacts likely secrets in
evidence, labels untrusted-content provenance, marks prompt-injection-sensitive
text, contains evidence paths to the repository root during `verify`, and keeps
network egress opt-in and environment-gated. See [SPEC.md](SPEC.md) §9 (MCP
safety) and §10 (IAN profile) for the full posture.

## Known limitations

Detection is regex/heuristic for MVP. Notable documented gaps: the PHP WordPress
guard check only inspects string-literal callbacks; CI/CD broad-permission
detection flags `write-all` only; injection detectors cover common sinks but
not every variant (e.g. `os.popen`, `request.` vs `req.`, `constructor.prototype`,
`docker://` action refs). Regex execution has no per-pattern timeout yet — files
are bounded by the inventory's 10 MB cap. These are tracked as follow-ups in
[PROGRESS.md](PROGRESS.md).
