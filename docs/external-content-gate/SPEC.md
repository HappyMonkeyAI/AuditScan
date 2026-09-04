# External Content Gate — Specification

Status: proposed
Version: 0.1
Date: 2026-09-04
Parent product: AuditScan (`repo-audit-scan`)

## 1. Problem statement

An AI agent can be induced to use hostile instructions or unsafe code that arrives through a public URL, repository README, issue, skill, dependency manifest, MCP server, CI workflow, or source file. Existing AuditScan scans local source for security weaknesses and labels returned evidence as untrusted, but it does not provide remote intake quarantine, agent/MCP-specific rule coverage, a machine-readable policy disposition, or sandbox-confirmed MCP behaviour.

## 2. Goal

Provide an evidence-backed, fail-closed assessment workflow for external links and repositories before an agent uses them operationally.

## 3. Primary users

- A developer who wants to inspect an external repository before adopting code or an MCP server.
- An AI agent that must request a scan before installing, registering, or executing externally sourced content.
- A CI workflow that wants a stable security report and failure threshold for MCP/server changes.

## 4. Functional requirements

### FR-ECG-001: External-content provenance

All URL/repository-derived findings and evidence MUST identify origin, canonical URL or resolved commit SHA, target path, and line/offset where available. Evidence MUST be marked `untrusted_content=true` and MUST NOT be phrased as an agent instruction.

### FR-ECG-002: Deterministic external-content rules

Phase 1 MUST add versioned deterministic rule families for:

- instruction hierarchy override and fake system/developer messages;
- jailbreak/role-play/prompt-exfiltration patterns;
- memory poisoning or instructions to persist untrusted claims;
- credential exfiltration, approval weakening, secret/config access, or tool registration requests;
- encoded/obfuscated instruction payload indicators;
- suspicious MCP tool descriptions/manifests and broad tool capability declarations;
- package lifecycle scripts, curl-pipe/download stagers, and risky build/install instructions.

Rules MUST return candidate findings with rule IDs, severity, confidence, bounded evidence, and remediation/review guidance. Rules MUST not execute or decode arbitrary payloads.

### FR-ECG-003: Staged-path scan

A new internal scan profile `external_repo` MUST accept a caller-provided existing local staged directory. It MUST reuse AuditScan inventory, secret redaction, and reporting. The profile MUST report its limitations and MUST not mutate the target by default.

### FR-ECG-004: Disposition contract

Every external-content report MUST include exactly one disposition:

- `allow_review`: all required static components completed; no blocking findings; source remains untrusted.
- `needs_human_review`: suspicious or unresolved findings, an approved suppression need, or degraded required analysis.
- `block`: critical policy violation, prohibited target/transport, or failure mode that makes safe intake impossible.

The report MUST list completed, skipped, failed, and unavailable checks separately.

### FR-ECG-005: Safe URL inspection

Phase 2 `inspect_external_link(url)` MUST accept HTTPS URLs only, reject credentials in URLs, enforce maximum redirects/bytes/time, validate MIME type, and reject loopback, link-local, RFC1918, and other non-public resolved targets on every redirect hop. It MUST retrieve text without browser JavaScript execution. Unsupported content returns `needs_human_review` or `block` with a reason, never a silent pass.

### FR-ECG-006: Quarantined repository intake

Phase 2 `quarantine_and_scan_repository(source, ref=None)` MUST initially permit GitHub HTTPS source URLs and explicitly staged local paths. A remote checkout MUST pin the resolved commit SHA, disable submodules/LFS/hooks/install steps, preserve source read-only, and write reports outside the target. It MUST return staging metadata without exposing an arbitrary host filesystem path to an untrusted target.

### FR-ECG-007: Constrained semantic review

Phase 3 semantic review MUST be optional at deployment level but mandatory for a result labelled `complete_semantic`. It MUST receive only redacted, capped deterministic candidates and return strict schema output. Host validation MUST reject unknown rule IDs, nonexistent source ranges, unsupported finding types, free-form commands, and probe code. Review unavailability MUST leave candidates visible and set `needs_human_review`.

### FR-ECG-008: Fixed MCP sandbox probes

Phase 4 MUST limit dynamic analysis to approved local target types and permanent probe templates. Containers MUST use read-only target source, no target runtime network, resource limits, timeout, forced cleanup, and no host credentials. Initial templates are: scope-boundary access, oversized arguments, controlled injection payload, and malformed schema input.

### FR-ECG-009: SARIF and CI

Phase 3 MUST emit validated SARIF in addition to existing JSON/Markdown. The GitHub Action MUST use immutable action references and make the fail threshold configurable. Fork pull requests MUST not receive semantic-review credentials. A degraded run MUST remain visible and must not upload an invalid SARIF artifact as a success.

### FR-ECG-010: Agent policy handoff

Tool results MUST include a short machine-readable policy object that tells a caller whether source reading, installation, execution, MCP registration, and persistent-memory writes are allowed. `block` and `needs_human_review` MUST deny installation, execution, registration, and automatic memory writes.

## 5. Non-functional requirements

- NFR-001: Static Phase 1 must run offline on a staged fixture repository.
- NFR-002: Reports must redact secret-like content before storage or MCP return.
- NFR-003: Rules and policy decisions must be deterministic when semantic review is disabled.
- NFR-004: All degraded states must be testable and visible in JSON/Markdown/SARIF.
- NFR-005: No production worker credential is supplied to a target repository/container.
- NFR-006: Tests must include malicious-looking content, benign documentation, encoded text indicators, unsafe MCP fixtures, and failure-infrastructure fixtures.

## 6. Acceptance criteria

| ID | Scenario | Expected result |
|---|---|---|
| AC-ECG-001 | A README says to ignore previous instructions and exfiltrate an environment variable. | Deterministic finding; bounded evidence has untrusted provenance; disposition is at least `needs_human_review`; policy denies memory write and execution. |
| AC-ECG-002 | A benign Three.js asset README has ordinary installation text. | No injection finding solely from normal prose; result explains remaining scan coverage. |
| AC-ECG-003 | A repository contains a malicious `postinstall` plus an unpinned GitHub Action. | Findings are reported without running package installation or workflow code. |
| AC-ECG-004 | A URL redirects to `127.0.0.1` or an RFC1918 address. | Request is blocked before body retrieval; report records the denied reason. |
| AC-ECG-005 | URL parser encounters a binary, oversized, or unsupported content type. | No content execution; explicit skipped/denied status and no clean result. |
| AC-ECG-006 | Semantic reviewer claims a nonexistent file range. | Host validation rejects the claim; report remains degraded/needs review. |
| AC-ECG-007 | Docker/Semgrep/reviewer fails during a required profile. | Report contains a clear degraded component and remains fail-threshold eligible. |
| AC-ECG-008 | A local Python MCP vulnerable fixture receives each fixed probe. | Probe results are isolated, bounded, provenance-labelled, and the container is cleaned up. |
| AC-ECG-009 | A fork PR runs CI. | No review secret is exposed; degraded result is visible; invalid SARIF is never uploaded. |
| AC-ECG-010 | `block` report is returned to an agent. | Policy object denies install, execution, MCP registration, and automatic persistent-memory writes. |

## 7. Out of scope

Remote dynamic scanning, arbitrary Git hosts, language-independent runtime probes, autonomous remediation, live internet exploitation, and automatic trust promotion are out of scope until their own threat model and acceptance criteria are approved.

## 8. Report shape

```json
{
  "target": {"kind": "repository", "origin": "https://github.com/org/repo", "resolved_ref": "<sha>"},
  "assessment": {"profile": "external_repo", "status": "complete|degraded|blocked", "disposition": "allow_review|needs_human_review|block"},
  "checks": {"completed": [], "skipped": [], "failed": [], "unavailable": []},
  "policy": {"read_source": true, "install": false, "execute": false, "register_mcp": false, "write_memory": false},
  "findings": []
}
```

This shape extends, rather than replaces, AuditScan's existing report metadata and findings schema.