# External Content Gate — Context

Status: planning only
Parent: AuditScan
Canonical implementation location: `C:\Users\steph\happymonkey\AuditScan`
Packet: `docs/external-content-gate/`

## Current verified state

- AuditScan is a Python scanner with a working stdio MCP server on this desktop. A native MCP test discovered 23 tools and its self-check passed.
- The current rule registry contains 133 rules across source, configuration, dependency, Docker, and CI/CD categories.
- AuditScan already redacts secret-like evidence and labels report evidence as untrusted scanner input. Its prompt-injection-like heuristic currently operates during reporting; it is not a dedicated external-content rule family.
- `scan_repository` resolves and scans an existing path. It does not yet restrict requests to a quarantine root or fetch remote repositories.
- `repo-security-scan` is a separate secret scanner. It should be invoked as an engine, not exposed as a second always-on MCP surface.
- Hermes on this desktop has effective secret redaction enabled and smart command approvals. These are defence-in-depth controls, not a substitute for untrusted-content assessment.

## Product boundary

This work is an AuditScan extension, not a new standalone application. It must retain AuditScan's evidence-first reports, IAN prioritization, rule registry, CLI/MCP interfaces, and existing write-report defaults.

The extension must not change normal local repository scanning behaviour. New remote/quarantine behaviour must be opt-in through explicit tools/profiles.

## Security invariants

1. External content is data, never instructions.
2. No external target code executes during URL/repository intake or static scanning.
3. No package manager, build command, submodule checkout, Git LFS fetch, hook, or generated script may run in Phase 1 or Phase 2.
4. A target is read-only inside any sandbox. Sandboxed target runtime network is disabled by default.
5. Every output snippet has source provenance, path/URL, line/offset where available, and `untrusted_content=true`.
6. A partial scan is never represented as clean. Tool/dependency/model/sandbox failures are explicit.
7. Model review cannot add findings, author probe code, make external calls, or cite unavailable ranges.
8. Only an explicit human decision may override `block` or `needs_human_review` for execution, installation, MCP registration, or promotion.
9. No credentials, target secrets, or raw confidential source are placed in committed reports, prompts, or semantic-review telemetry.

## Architecture decisions already made

- Use two primary agent-facing tools: `inspect_external_link` and `quarantine_and_scan_repository`.
- Keep a potential dynamic `probe_mcp_target` private/deferred until Phase 4 rather than exposing arbitrary execution at first.
- Prefer a separate low-privilege quarantine worker/container rather than expanding the long-lived AuditScan MCP process privileges.
- Begin GitHub-only and HTTPS-only for remote repositories. Broader Git hosts require a separate threat-model and test slice.
- Treat SARIF as a Phase 3 integration format, preserving the existing JSON and Markdown reports.
- Use constrained semantic review after deterministic checks, never in front of them.

## Required MCP routing

| Intent | Preferred capability | State |
|---|---|---|
| Scan a staged repository | `auditscan.scan_repository` / future external-content tools | Available locally; extension planned |
| List AuditScan rules and health | `auditscan.list_rules`, `auditscan.server_get_health` | Available locally |
| Find source/research references | `article_research` or browser/web extraction | Available locally |
| Check resource capacity before sandbox work | `resource_sentinel` | Available locally |
| Locate/register project and worker resources | `launcher_registry`, `agent_communication` | Available locally |
| Sandbox container lifecycle | Docker MCP or controlled worker | Discovery and contract required before Phase 4 |

Listed capability is not proof of a working integration. Each implementation slice must independently exercise transport, tool discovery, and one harmless representative call.

## Explicit non-goals

- Classifying all Tor/dark-web references as malicious.
- Automatically trusting a repository based only on a scan score.
- Scanning private repositories by injecting credentials into an untrusted worker.
- Remote live probing of arbitrary public MCP endpoints.
- Automatic changes to Hermes global memory, skill installations, or MCP registrations.
- Replacing GitHub Advanced Security, CodeQL, Semgrep, OSV, antivirus, or human code review.

## Operator workflow

1. User or agent supplies an external link/repository.
2. Agent calls the appropriate inspection tool before using its content operationally.
3. Report returns a disposition and exact reasons, with hostile content labelled as data.
4. For `block` or `needs_human_review`, agent stops before installation/execution/registration and requests a human decision.
5. For `allow_review`, agent may read the source and propose a further review; it still must not execute it without the normal approval path.

## Verification ladder

- V0: formatter/linter/type checker and focused unit tests.
- V1: deterministic fixture tests for every rule and all error/degraded states.
- V2: owner adversarial acceptance against hostile URL/repository fixtures.
- V3: isolated worker/container integration proof, including no-network and no-execution assertions.
- V4: CI/SARIF integration and report readback.

Worker self-reports are evidence, not completion. The owner reruns the relevant V-level check before marking a task done.