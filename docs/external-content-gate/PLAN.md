# External Content Gate — Project Plan

Status: proposed documentation packet; no implementation started
Parent project: AuditScan (`repo-audit-scan`)
Created: 2026-09-04

## Goal

Extend AuditScan so an AI agent can safely assess an external URL or repository before using its instructions, registering an MCP server, installing dependencies, or copying code into a HappyMonkeyAI environment.

## Thesis

Treat third-party links, repository text, skills, manifests, MCP tool descriptions, and source code as untrusted data. Inspection happens in a restricted staging area; deterministic rules create evidence-backed candidates; optional semantic review is constrained to those candidates; only fixed, inert probes may run in a sandbox; and the final disposition gates downstream agent behaviour.

## It is

- An AuditScan capability, exposed through two small MCP tools and reusable CLI/service modules.
- A pre-ingestion and pre-registration guard for external repositories, URLs, and MCP packages.
- A reporting and policy decision system: `allow_review`, `needs_human_review`, or `block`.
- A complement to `repo-security-scan`, which remains the specialist secret scanner.

## It is not

- A proof that a repository is harmless.
- A general malware-analysis platform or arbitrary-code execution service.
- Permission for an agent to run package installers, builds, submodules, Git hooks, or generated code while assessing an external project.
- A replacement for normal dependency provenance, code review, sandboxing, approvals, or runtime least privilege.

## Proposed architecture

```text
external URL / repository URL / local staged path
                    |
                    v
        input and network policy gate
                    |
                    v
       text-only URL fetch or quarantined checkout
                    |
                    v
   inventory + repo-security-scan + AuditScan rules
                    |
                    v
optional constrained semantic review of rule candidates
                    |
                    v
fixed inert sandbox probes (MCP-target profile only)
                    |
                    v
redacted report + provenance + disposition + policy decision
```

The quarantine worker is a separate, low-privilege process/container. AuditScan remains the orchestration, evidence, scoring, and reporting owner. The target source is read-only to analysis and has no runtime network access.

## Target surfaces

1. `inspect_external_link(url)`
   - Text-only retrieval; no page JavaScript.
   - Strict redirect, allowed-scheme, size, MIME, timeout, DNS-rebinding, SSRF/private-address, and content-decompression limits.
   - Inspects text, links, and declared download/MCP setup instructions.

2. `quarantine_and_scan_repository(source, ref=None, profile="external_repo")`
   - Initially accepts allowlisted GitHub HTTPS repository URLs and already-staged local paths.
   - Pins the resolved commit SHA and records origin, ref, and content digest.
   - Clones without submodules, LFS, hooks, install steps, or target execution.
   - Runs secret, code/security, content-injection, workflow, dependency, and MCP-manifest checks.

3. `probe_mcp_target(staged_path, approved_profile)`
   - Deferred to the MCP-target profile after static assessment.
   - Runs only fixed templates in a Docker-isolated environment: out-of-scope tool access, oversized arguments, injection payload handling, and malformed schema input.
   - Never accepts model-authored executable probe code.

## Trust and policy model

- Every scanned snippet is emitted as `untrusted_content` with origin and exact location.
- Semantic review may corroborate, reject, or request review only for deterministic candidates. It must return versioned structured output, reference existing file/line ranges, and cannot create a rule-less finding.
- Missing review, Semgrep, Docker, report validation, or dependency-scanner capability produces an explicit degraded result. It never becomes a clean pass.
- `block`: no agent may execute, install, register, or promote the target without a human decision.
- `needs_human_review`: source can be read, but the same execution/registration prohibition applies pending explicit approval.
- `allow_review`: permits ordinary source review only; it is not an execution approval.

## Delivery phases

- Phase 0: documentation, threat model, fixtures, and policy contracts.
- Phase 1: deterministic external-content and MCP-surface rules; safe local staged-path scanning; redacted report/disposition.
- Phase 2: quarantined GitHub checkout and safe text-only URL inspection.
- Phase 3: constrained semantic review, SARIF, and GitHub Action integration.
- Phase 4: Docker-isolated fixed probe harness for local Python MCP targets; broaden only after measured fixture coverage.

## Pre-mortem

| Failure mode | Earliest warning | Mitigation |
|---|---|---|
| Scanner executes target code while scanning | install/build commands appear in a worker trace | Separate readonly staging from all execution; deny network at runtime; test the negative path. |
| LLM review becomes an unbounded attack surface | reviewers cite files/ranges that do not exist or return free-form commands | Strict schema, host-side range validation, caps/redaction, candidates-only review. |
| Clean result is returned during a partial outage | Docker/Semgrep/review failure is absent from summary | Distinct degraded status and fail-on eligibility; contract tests for every dependency failure. |
| URL scan becomes SSRF | resolver returns private/link-local addresses or redirects to one | Resolve and validate every hop, reject private ranges, pin connection policy, test DNS rebinding. |
| False positives make agents bypass the gate | broad rule categories produce mostly `needs_human_review` | Versioned fixtures, suppression workflow with rationale, calibrated severity, report quality metrics. |

## Source inputs

- AuditScan current source, rule registry, MCP transport, reporting/provenance safeguards, and existing CI/CD checks.
- `repo-security-scan`: https://github.com/HappyMonkeyAI/repo-security-scan
- AuditScan: https://github.com/HappyMonkeyAI/AuditScan
- MCP Sentinel: https://github.com/BashaarJavaid/MCP-Sentinel
- Sentinel project write-up: https://devpost.com/software/sentinel-way5bd
- OpenAI Build Week winner write-up: https://developers.openai.com/blog/build-week-winners

## Exit criteria for planning

The packet is complete when CONTEXT, SPEC, and TASKS define a bounded Phase 1. Code begins only after an explicit implementation instruction.