# Troubleshooting

Common issues when installing and running `repo-audit-scan`, with the cause and
the fix. See [ARCHITECTURE.md](ARCHITECTURE.md) for how the pieces fit together.

## Install / environment

**`repo-audit-scan: command not found` after install.**
The console script is installed into the active environment's `bin`/`Scripts`.
Activate the virtualenv first, or run the module form:

```bash
python -m repo_audit_scan --version
```

**`pip install -e .[dev]` fails on an externally managed environment.**
Use a virtualenv (recommended) or, only if you must install system-wide, add
your platform's override flag. A clean venv avoids this entirely:

```bash
python3 -m venv .venv && source .venv/bin/activate && pip install -e .[dev]
```

**Tests can't find `pytest`.** Install the dev extras (`pip install -e .[dev]`)
and run `pytest -q` from the repo root. The default test path is
`repo_audit_scan/tests`.

## Scanning

**A scan returns no findings on a repo I expect to be risky.**
Check, in order:

1. The files are being walked. Files over 10 MB, binary files, and paths under
   excluded directories (`.git/`, `node_modules/`, `__pycache__/`, build
   outputs) are skipped. `scanned_files_count` / `skipped_files_count` in the
   report metadata show the split.
2. An adapter claims the file. Language adapters match by extension; the CI/CD
   adapter matches by path (e.g. a workflow must live under
   `.github/workflows/`). A file no adapter claims is not scanned.
3. The rule applies to that language. Rules are scoped by description
   language-markers; a Python rule will not run on a `.js` file and vice-versa.

**A CI/CD workflow isn't being scanned.**
The CI/CD adapter only claims recognized pipeline paths/filenames:
`.github/workflows/*.yml|yaml`, `Jenkinsfile`, `.gitlab-ci.yml`,
`.circleci/config.yml`, `azure-pipelines.yml`, `.travis.yml`. A generic
`config.yml` elsewhere is intentionally not treated as CI/CD.

**Too many findings / low-precision noise.**
Some detectors are intentionally broad (e.g. `eval(`, `DEBUG = True`,
`dangerouslySetInnerHTML=`). Use `triage --min-ian-score` to focus on the
highest-priority findings, and `ManualConfirmation` to dismiss false positives
without losing the audit trail.

## Dependency enrichment

**Advisory enrichment isn't running even with `--enrich-dependencies`.**
Network enrichment is double-gated. You must pass `--enrich-dependencies` *and*
set the environment variable:

```bash
REPO_AUDIT_DEP_ENRICHMENT=true repo-audit-scan scan <repo> --enrich-dependencies
```

Without the env var, the scan still produces lockfile-only dependency findings
with no network calls.

**A scan fails during enrichment.** Enrichment fails open by default — the scan
continues and keeps lockfile findings. If you passed `--fail-closed-enrichment`,
remove it to tolerate transient network/advisory errors.

## Verify

**`verify` reports a finding as still present after I fixed it.**
`verify` re-runs the finding's rule against the evidence files. Confirm you
fixed the same file/line the finding references, and that the change actually
removes the matched pattern. For dependency findings, `verify` falls back to a
content-snippet recheck against the manifest.

**`verify` reports `:blocked_path`.**
Evidence paths are contained to the repository root. Absolute paths or `..`
traversal in evidence are blocked by design. Pass `--repo-path` to point at the
correct repository root if the report metadata path is stale.

## MCP server

**MCP scans don't write reports into my repository.**
That is the default. The MCP server writes to the tool workspace only. To mirror
into the target repo, the caller must pass both `write_reports: true` and
`mirror_to_target_repo: true`.

**Checking server health.** Use the operational tools `server.get_health`,
`server.get_status`, and `diagnostics.run_self_check`; `reports.list_reports`
lists prior workspace reports.

## Reports

**Where are my reports?**
The CLI writes to the workspace report root (`--output-root`, default
`scan-reports/`) and mirrors into `<repo>/audits/YYYY-MM-DD/repo-audit-scan/`
unless `--no-write-reports` is set. `triage`/`verify` accept either a report
path or a report id under the workspace root.
