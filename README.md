# repo-audit-scan

Security-focused repository audit scanner for code vulnerabilities and misconfiguration risks, with CLI and MCP workflows. It scans a local repository, produces evidence-backed findings, prioritizes them with the IAN (Impact / Accessibility / Necessity) risk model, generates ticket-ready triage, and verifies whether a specific finding has been fixed.

## What it does

The tool automates the audit-to-triage loop so a developer or AI agent can:

1. Point it at a local repository.
2. Detect repository shape (languages, frameworks, dependency manifests, CI/CD files).
3. Run a universal rule set plus matching stack adapters.
4. Produce structured findings with file, line, evidence, category, severity, confidence, and IAN priority.
5. Emit human-readable (Markdown) and machine-readable (JSON) reports.
6. Triage the highest-risk findings into ticket-ready Markdown.
7. Verify that a specific finding no longer appears after a fix.

It is read-only against the target repository unless explicitly asked to write report artifacts, and it does not modify application code.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e .[dev]

# Scan a repository
repo-audit-scan scan /path/to/repo --format json

# List the rule set
repo-audit-scan rules

# Triage a prior report, then verify a fix
repo-audit-scan triage <report-or-report-id> --limit 10
repo-audit-scan verify <report-or-report-id> <finding-id>
```

## Coverage

**Adapters (8):** Python, JavaScript/TypeScript, PHP/WordPress, CI/CD (GitHub Actions and common pipelines), Docker, and external-content are supported; Java and C#/.NET are loadable per the adapter contract with seed-level rules. Language adapters are matched by file extension; the CI/CD adapter is matched by path/filename (`.github/workflows/*.yml`, `Jenkinsfile`, `.gitlab-ci.yml`, `.circleci/config.yml`, `azure-pipelines.yml`, `.travis.yml`).

**Rules:** 139 rules across 26 categories — including secrets, injection, external-content, access-control, authentication, cryptography, deserialization, api-security, xss, configuration, file-operations, ci-cd, dependency, and more. Findings are deduplicated and can be manually confirmed or dismissed without losing the audit trail.

**Scoring:** Each finding is scored on Impact, Accessibility, and Necessity (weighted 0.40 / 0.35 / 0.25), classified into a compromise mode (cover / triage / assume-breach), and eligible for chain detection that can raise an attacker path above isolated findings.

## CLI

```bash
repo-audit-scan scan <repo-path> [--format text|json]
                                 [--write-reports | --no-write-reports]
                                 [--output-root DIR]
                                 [--enrich-dependencies] [--fail-closed-enrichment]
repo-audit-scan rules [--format text|json]
repo-audit-scan triage <report-or-report-id> [--limit N] [--min-ian-score F]
                                             [--output-dir PATH] [--pilot-name NAME]
                                             [--review-note NOTE]
repo-audit-scan verify <report-or-report-id> <finding-id> [--repo-path PATH]
```

Global flags: `--version`, `-v/--verbose`, `--rules PATH` (use a custom rules JSON file instead of the bundled rule set).

**Report mirroring:** the CLI writes reports to both the tool workspace and the target repository under `audits/YYYY-MM-DD/repo-audit-scan/` by default (matching the accelerator workflow). Use `--no-write-reports` to suppress, or `--output-root` to relocate the workspace copy.

**Dependency enrichment:** local lockfile parsing runs by default with no network access. Network advisory enrichment (OSV) is opt-in and double-gated — pass `--enrich-dependencies` *and* set `REPO_AUDIT_DEP_ENRICHMENT=true`. Enrichment fails open (the scan keeps lockfile findings) unless `--fail-closed-enrichment` is set.

```bash
REPO_AUDIT_DEP_ENRICHMENT=true repo-audit-scan scan <repo-path> --enrich-dependencies
```

## MCP surface

The MCP server exposes tools that are safe for an AI agent to call during audit and fix workflows:

- `scan_repository`, `list_rules`, `get_finding`, `triage_report`, `verify_fix`, `get_latest_report`
- Operational: `server.get_info`, `server.get_health`, `server.get_status`
- Diagnostics: `diagnostics.validate_config`, `diagnostics.run_self_check`, `reports.list_reports`

The MCP server defaults to writing reports to the tool workspace only and never mirrors into the target repository unless the caller explicitly opts in (`write_reports: true` and `mirror_to_target_repo: true`).

## Project structure

```text
repo_audit_scan/         # Core package
  inventory.py           # Filesystem walk, language/framework detection, Git metadata
  rules.py               # Rule registry, dedupe, manual-confirmation
  scoring.py             # IAN scoring, compromise mode, chain detection
  adapters_final.py      # LanguageAdapter contract + 6 adapters
  adapter_registry.py    # Adapter loading/resolution
  reporting.py           # JSON + Markdown report writers (redaction, provenance)
  triage.py              # Ticket-ready triage + scan-review writers
  dependency_enrichment.py  # Lockfile parsing + opt-in OSV enrichment
  cli.py                 # CLI entrypoints
  mcp_server.py          # MCP server + tool handlers
  tests/                 # Package test suite
tests/                   # Additional fixtures and tests
SPEC.md  PLAN.md  TASKS.md  PROGRESS.md  ARCHITECTURE.md  TROUBLESHOOTING.md
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the pipeline and component design, and [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for common issues.

## Development

Requires Python 3.10+.

```bash
pip install -e .[dev]
pytest -q
```

## Safety model

- Read-only against the target repo unless report artifacts are explicitly requested.
- Evidence snippets are redacted for likely secrets before output.
- Untrusted repository content is treated as hostile and provenance-labeled.
- Evidence paths are contained to the repository root during verification.
- Network advisory enrichment is opt-in and environment-gated.

## License

MIT
