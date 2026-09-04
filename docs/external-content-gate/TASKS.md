# External Content Gate — Tasks

Status: proposed; documentation is complete, implementation is not started
Source: `SPEC.md` v0.1

## Rules

- Each task has one owner branch/worktree and evidence-bearing handoff.
- No task is complete on an agent self-report alone. Owner reruns its listed verification.
- A partial/degraded scan result is a product result to test, not an implementation detail to suppress.
- Do not begin a task whose dependencies are incomplete.
- Commit each coherent, independently verified slice. Do not push without explicit instruction.

## Phase 0 — Contract and fixture foundation

### ECG-001 — Establish external-content report and policy data models

Status: complete (2026-09-04)
Depends on: none
Files likely to change:
- `repo_audit_scan/models.py`
- `repo_audit_scan/reporting.py`
- `repo_audit_scan/tests/test_reporting.py`
- `repo_audit_scan/tests/test_external_content_models.py` (new)

Deliver:
- Assessment status, disposition, check-status inventory, source provenance, and agent policy models.
- JSON and Markdown output that cannot represent incomplete analysis as clean.

Done when:
- Focused model/report tests cover all three dispositions and every policy denial.
- Existing report tests still pass.

### ECG-002 — Add hostile and benign repository fixtures

Status: complete (2026-09-04)
Depends on: ECG-001
Files likely to change:
- `tests/fixtures/external_content/` (new)
- `tests/fixtures/mcp_targets/` (new)
- `repo_audit_scan/tests/test_external_content_fixtures.py` (new)

Deliver:
- Fixtures for instruction overrides, fake system tags, memory poisoning, encoded indicators, malicious lifecycle scripts, risky MCP manifests, benign Three.js documentation, and a clean MCP target.

Done when:
- Fixture README documents the intended findings and non-findings.
- Tests establish stable baseline assertions without executing fixture code.

### ECG-003 — Record threat model and integration ADRs

Status: complete (2026-09-04)
Depends on: ECG-001
Files likely to change:
- `docs/adr/` (new or existing project convention)
- `docs/external-content-gate/`

Deliver:
- ADRs for quarantine boundary, semantic-review constraint, and execution policy.

Done when:
- ADRs name the owner, decision, alternatives rejected, and rollback/expiry trigger.

## Phase 1 — Deterministic staged-path scanning

### ECG-010 — Implement deterministic external-content rule family

Status: complete (2026-09-04)
Depends on: ECG-001, ECG-002
Files likely to change:
- `repo_audit_scan/rules.py`
- `tests/fixtures/rules/sample_rules.json` or new versioned rule source
- `repo_audit_scan/adapters_final.py`
- `repo_audit_scan/tests/test_rules.py`
- `repo_audit_scan/tests/test_external_content_rules.py` (new)

Deliver:
- Rule IDs for instruction override, fake authority messages, secret/approval/tool-registration requests, memory-poisoning language, obfuscation indicators, lifecycle scripts, and MCP-surface hazards.

Done when:
- Each malicious fixture produces its intended candidate.
- Benign fixture cases remain clean for the relevant rules.
- Rules do not decode or execute content.

### ECG-011 — Add `external_repo` staged-path profile

Status: complete (2026-09-04)
Depends on: ECG-001, ECG-010
Files likely to change:
- `repo_audit_scan/cli.py`
- `repo_audit_scan/mcp_server.py`
- `repo_audit_scan/mcp_stdio.py`
- `repo_audit_scan/tests/test_cli.py`
- `repo_audit_scan/tests/test_mcp_server.py`

Deliver:
- Explicit profile selection for existing staged paths and report disposition/policy handoff.
- Read-only default with workspace-only report writing.

Done when:
- MCP and CLI scan fixture repos without changing them.
- A `block` result denies install/execution/registration/memory-write in returned policy.
- Native `hermes mcp test auditscan` still discovers expected tools.

### ECG-012 — Integrate repo-security-scan as a bounded engine

Status: proposed
Depends on: ECG-011
Files likely to change:
- `repo_audit_scan/external_content.py` (new)
- `repo_audit_scan/config.py`
- `repo_audit_scan/tests/test_external_content_integration.py` (new)

Deliver:
- Configured invocation/adaptation of secret findings into the external-content report without making repo-security-scan an exposed MCP server.

Done when:
- Secret fixture produces a redacted finding.
- Missing scanner dependency becomes explicit `unavailable`/`needs_human_review`, not clean.

## Phase 2 — Safe remote intake

### ECG-020 — Implement URL network-policy module

Status: proposed
Depends on: ECG-001, ECG-002
Files likely to change:
- `repo_audit_scan/external_fetch.py` (new)
- `repo_audit_scan/tests/test_external_fetch.py` (new)

Deliver:
- HTTPS-only parsing, URL-credential rejection, per-hop redirect and DNS/IP validation, response caps, MIME policy, and text-only extraction.

Done when:
- Tests reject loopback/private/link-local targets, DNS-rebinding simulation, invalid schemes, oversized payloads, and unsupported MIME types.
- Tests prove no browser/JavaScript execution path is used.

### ECG-021 — Add `inspect_external_link` MCP tool

Status: proposed
Depends on: ECG-010, ECG-020
Files likely to change:
- `repo_audit_scan/mcp_server.py`
- `repo_audit_scan/mcp_stdio.py`
- `repo_audit_scan/tests/test_mcp_server.py`

Deliver:
- Agent-facing URL inspection using the policy module and deterministic content rules.

Done when:
- Native MCP test discovers the new tool.
- A harmless HTTPS fixture returns a provenance-labelled report.
- Redirect/private-address fixture returns `block` before body retrieval.

### ECG-022 — Build quarantined GitHub checkout worker

Status: proposed
Depends on: ECG-011, ECG-020
Files likely to change:
- `repo_audit_scan/quarantine.py` (new)
- worker/container definition (new)
- `repo_audit_scan/tests/test_quarantine.py` (new)

Deliver:
- GitHub HTTPS-only checkout to a disposable staging root; commit pinning; no submodule/LFS/hooks/installation; report artifacts outside target.

Done when:
- Integration fixture proves resolved SHA recorded and target source read-only.
- Audit proves no submodule/LFS/install process was started.
- Worker cleanup succeeds on normal, failure, and timeout paths.

### ECG-023 — Add `quarantine_and_scan_repository` MCP tool

Status: proposed
Depends on: ECG-012, ECG-022
Files likely to change:
- `repo_audit_scan/mcp_server.py`
- `repo_audit_scan/tests/test_mcp_server.py`
- `repo_audit_scan/tests/test_external_content_integration.py`

Deliver:
- Agent-facing remote/repository intake orchestration with staged report and policy response.

Done when:
- A GitHub fixture/safe controlled repository scan produces a pinned target record and policy result.
- A prohibited source URL is blocked without checkout.

## Phase 3 — Constrained review and CI

### ECG-030 — Implement constrained semantic-review adapter

Status: proposed
Depends on: ECG-010, ECG-011
Files likely to change:
- `repo_audit_scan/semantic_review.py` (new)
- versioned schema under `repo_audit_scan/schemas/` (new)
- `repo_audit_scan/tests/test_semantic_review.py` (new)

Deliver:
- Redacted/capped candidates-only review, schema validation, rule/range validation, replay mode, and explicit degraded behaviour.

Done when:
- Unknown rules, nonexistent ranges, free-form commands, and attempted probe code are rejected.
- Review outage yields `needs_human_review` and a visible check failure.

### ECG-031 — Add SARIF writer and validator

Status: proposed
Depends on: ECG-001, ECG-010
Files likely to change:
- `repo_audit_scan/sarif.py` (new)
- `repo_audit_scan/tests/test_sarif.py` (new)

Deliver:
- SARIF 2.1.0 output preserving provenance, location, severity, and check status.

Done when:
- Valid and invalid fixture reports are checked by an independent validator.
- Degraded state is represented and cannot be confused with clean analysis.

### ECG-032 — Create immutable GitHub Action workflow

Status: proposed
Depends on: ECG-030, ECG-031
Files likely to change:
- `.github/workflows/external-content-gate.yml` (new)
- workflow integration tests/docs

Deliver:
- Configurable threshold, artifact upload, fork-safe no-secret behaviour, and SARIF upload only after validation.

Done when:
- Simulated fork and non-fork tests verify the credential boundary.
- Workflow action references are pinned to immutable SHAs.

## Phase 4 — Bounded dynamic MCP confirmation

### ECG-040 — Define fixed probe contract and isolated runner

Status: proposed
Depends on: ECG-002, ECG-022, ECG-030
Files likely to change:
- `repo_audit_scan/mcp_probe_runner.py` (new)
- Docker sandbox assets (new)
- `repo_audit_scan/tests/test_mcp_probe_runner.py` (new)

Deliver:
- Four inert templates with fixed semantics, argument bounds, resource policy, and cleanup contract.

Done when:
- Vulnerable and hardened local Python MCP fixtures demonstrate expected differences.
- Target runtime has no network, source is read-only, and cleanup is independently verified.

### ECG-041 — Expose bounded MCP-target assessment

Status: proposed
Depends on: ECG-040
Files likely to change:
- `repo_audit_scan/mcp_server.py`
- `repo_audit_scan/tests/test_mcp_server.py`
- `README.md`, `ARCHITECTURE.md`, `TROUBLESHOOTING.md`

Deliver:
- A narrowly parameterized MCP-target scan/profile, not arbitrary command execution.

Done when:
- Tool schema cannot pass a shell command, host path, network override, or model-authored payload.
- V0–V4 evidence is recorded and owner acceptance passes.

## Release gate

Before any external-content capability is enabled for routine agent use:

- Full repository test suite passes in the project's dev environment.
- Native AuditScan MCP connection and tool discovery pass.
- Owner has run hostile/benign fixture acceptance and quarantine cleanup checks.
- Secret scan confirms no credentials/report secrets entered the working tree.
- Documentation accurately lists supported targets, prohibited operations, degraded states, and known limitations.