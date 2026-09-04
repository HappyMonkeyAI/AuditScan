# ADR-ECG-003: Execution and promotion policy

- Status: accepted for implementation planning
- Date: 2026-09-04
- Owner: Stephen Phillips
- Scope: AuditScan external-content gate

## Context

A scan result is advisory unless downstream agent actions are explicitly constrained. A repository that contains malicious instructions can still be dangerous after a successful static scan, and a partial scan must not be mistaken for approval to install, execute, register an MCP server, or persist memory.

## Decision

Every external-content assessment returns a policy handoff alongside findings:

- `allow_review`: source may be read and reviewed; operational actions remain denied.
- `needs_human_review`: source may be inspected as untrusted data; installation, execution, MCP registration, promotion, and automatic memory writes are denied.
- `block`: the same actions are denied, and the target is treated as prohibited until a human explicitly overrides the decision.

The policy is fail-closed for installation, execution, registration, and persistent-memory writes. A human override must be a separate, auditable action; it is not encoded by altering the scan result. Normal Hermes command approvals, secret redaction, MCP sampling settings, and runtime sandboxing remain defence in depth.

## Alternatives rejected

- Treating `allow_review` as an install approval: conflates inspection with trust.
- Letting an agent override its own disposition: removes the human boundary.
- Blocking every suspicious phrase automatically: produces unusable false positives and encourages bypasses.
- Relying only on Hermes command approval: command approval cannot identify hostile text before it becomes an agent plan or prevent unsafe MCP registration.

## Consequences

- Callers must understand and honour the policy object; reports must make denials prominent.
- Persistent-memory and MCP-registration integrations need explicit future adapters rather than implicit side effects.
- Security operations retain a human decision point for ambiguous findings.

## Rollback and expiry

If policy enforcement is not wired through a caller, keep the gate advisory and do not advertise it as a prevention control. Revisit this ADR if Hermes gains a native external-content trust boundary, if memory/skill registration semantics change, or if an audited override workflow is introduced.
