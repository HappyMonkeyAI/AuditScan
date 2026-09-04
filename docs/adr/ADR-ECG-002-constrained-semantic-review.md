# ADR-ECG-002: Constrained semantic review

- Status: accepted for implementation planning
- Date: 2026-09-04
- Owner: Stephen Phillips
- Scope: AuditScan external-content gate

## Context

An LLM can reduce false positives and prioritize security candidates, but giving it authority to discover arbitrary vulnerabilities, write probes, or emit operational instructions would reproduce the trust problem the scanner is intended to reduce. Scanned source and documentation may itself contain prompt injection.

## Decision

Semantic review is a bounded second layer after deterministic rules. It receives only redacted, size-capped candidate findings and their source context. It must return a versioned structured schema containing an existing rule ID, disposition, confidence, rationale, and source ranges. Host code validates that the rule exists, ranges exist in the staged source, and no free-form commands or executable probe code are present.

The reviewer may corroborate, mark false positive, order, or request human review. It may not create a rule-less finding, alter policy directly, fetch content, call tools, write files, or author executable probes. Review unavailability produces an explicit degraded result with candidates still visible and eligible for the configured failure threshold. Replay fixtures use the production parser and validators.

## Alternatives rejected

- LLM-only scanning: non-reproducible and vulnerable to hostile context.
- Free-form LLM explanations as policy: difficult to validate and easy to treat as instructions.
- Optional review that silently falls back to clean: creates false confidence.
- Model-authored exploit/probe code: turns the reviewer into an execution-capable author.

## Consequences

- Deterministic rule quality and fixture coverage remain the foundation.
- Source-range validation and schema versioning are mandatory maintenance costs.
- A degraded result can fail CI even when no deterministic finding is confirmed.
- Semantic review must be treated as an untrusted classifier, not an authority.

## Rollback and expiry

Disable semantic review while retaining deterministic findings and mark all affected assessments degraded/needs-review. Revisit this ADR when the schema, range validator, replay corpus, or data-redaction contract changes, or when model capabilities materially change.
