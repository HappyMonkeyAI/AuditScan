# ADR-ECG-001: Quarantine boundary for external content

- Status: accepted for implementation planning
- Date: 2026-09-04
- Owner: Stephen Phillips
- Scope: AuditScan external-content gate

## Context

A repository or URL can contain source, documentation, manifests, workflows, skills, or MCP metadata that attempts to influence an agent. Static inspection must not become a path to running that content. AuditScan currently accepts local repository paths, while the proposed gate must support remote intake without allowing arbitrary target code to execute.

## Decision

External repositories are first represented in a disposable, low-privilege staging area. Remote intake is initially HTTPS GitHub only and records the resolved commit SHA and content digest. Static scanning reads the staged tree without installing dependencies, running builds, invoking hooks, initializing submodules, fetching LFS objects, or executing generated scripts. Reports are written outside the target tree by default.

The staging worker must apply explicit resource, filesystem, and network policy. Any later runtime probe is a separate profile and process boundary, with read-only source, no target runtime network, bounded resources, timeout, and forced cleanup.

## Alternatives rejected

- Scanning directly in the caller's working tree: risks mutation and mixes trust boundaries.
- Running `npm install`, `pip install`, or project build commands during intake: lifecycle/build scripts are part of the threat surface.
- Recursive submodule/LFS checkout: expands unreviewed code and network scope.
- Browser-rendering arbitrary URLs: adds JavaScript and browser attack surface to a text inspection task.

## Consequences

- Remote repository scanning needs a worker/container and cleanup telemetry.
- Some projects will be incomplete without generated files or dependencies; this is reported as coverage, not silently repaired by execution.
- Dynamic MCP tests require a separate approved profile and cannot be inferred from a static pass.

## Rollback and expiry

Rollback by disabling remote/quarantine tools and retaining local static scanning. Revisit this ADR if the worker cannot prove no-execution/no-network behaviour, if a broader Git host is requested, or if a target needs credentials or runtime network to be meaningfully assessed.
