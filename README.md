# repo-audit-scan

Security-focused repository audit scanner for code vulnerabilities and misconfiguration risks, with CLI and MCP workflows.

## Quick Start

```bash
# Clone
git clone <repo-url>
cd AuditScan

# Create and activate virtual environment (Linux/macOS example)
python3 -m venv .venv
source .venv/bin/activate

# Install
pip install -e .[dev]

# Run a scan
repo-audit-scan scan /path/to/repo --format json
```

## Project Structure

```text
repo_audit_scan/        # Core package (CLI, MCP server, rules, reporting, scoring)
repo_audit_scan/tests/  # Package test suite
tests/                  # Additional fixtures and test assets
.agents/memories/       # Project memory, walkthroughs, and ADR-style artifacts
SPEC.md                 # Product and acceptance specification
PLAN.md                 # High-level implementation plan
TASKS.md                # Execution task breakdown
PROGRESS.md             # Delivery progress tracker
README.md
```

## Documentation

- [SPEC](SPEC.md)
- [PLAN](PLAN.md)
- [TASKS](TASKS.md)
- [PROGRESS](PROGRESS.md)
- [AGENTS](AGENTS.md)

## Development

### Prerequisites

- Python 3.10+
- `pip`
- A local Git repository path to scan

### Building

```bash
pip install -e .[dev]
```

### Testing

```bash
pytest -q repo_audit_scan/tests
```

## CLI Usage

```bash
repo-audit-scan scan <repo-path> [--format text|json] [--write-reports|--no-write-reports]
repo-audit-scan rules [--format text|json]
repo-audit-scan triage <report-or-report-id> [--limit N] [--output-dir PATH]
repo-audit-scan verify <report-or-report-id> <finding-id> [--repo-path PATH]
```

Dependency enrichment controls:

```bash
REPO_AUDIT_DEP_ENRICHMENT=true repo-audit-scan scan <repo-path> --enrich-dependencies
repo-audit-scan scan <repo-path> --enrich-dependencies --fail-closed-enrichment
```

Notes:
- Default behavior is local lockfile dependency analysis (no network).
- Network advisory enrichment is opt-in and additionally gated by `REPO_AUDIT_DEP_ENRICHMENT=true`.
- CLI mirrors reports to workspace and target repo audit folder by default.

## MCP Surface

Current MCP tool handlers include:

- `scan_repository`
- `list_rules`
- `get_finding`
- `triage_report`
- `verify_fix`
- `get_latest_report`
- `server.get_info`
- `server.get_health`
- `server.get_status`
- `diagnostics.validate_config`
- `diagnostics.run_self_check`
- `reports.list_reports`

## Contributing

1. Create a feature branch.
2. Implement a scoped change aligned to `SPEC.md`.
3. Run tests.
4. Update `TASKS.md`/`PROGRESS.md` when relevant.
5. Open a pull request with verification evidence.

## License

MIT
