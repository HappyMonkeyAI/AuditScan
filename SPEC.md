# repo-audit-scan Specification

**Status:** Ready for implementation handoff (MVP scope)  
**Owner:** Stephen Phillips  
**Created:** 2026-05-26  
**Last Updated:** 2026-05-26  
**Version:** 1.0

## 1. Spec Practices Applied

This specification is intended to be the source of truth for a future coding agent. It focuses on what the tool must do, why it exists, the workflow it automates, and how success will be verified. Implementation details are included only where they constrain the product shape enough to help a future agent avoid drift.

Practical spec-driven development practices applied here:

- Keep the spec as a versioned, living artifact that drives plans, tasks, implementation, and verification.
- Define user workflows and acceptance criteria before implementation details.
- Write measurable requirements with clear inputs, outputs, and success checks.
- Use human checkpoints around security judgment, ticket creation, and code changes.
- Keep tasks and future implementation slices small enough that a coding agent can build and verify them incrementally.
- Prefer explicit assumptions over hidden decisions.
- Treat generated code as a manifestation of the spec, not the other way around.

References reviewed:

- https://github.com/GKAYED/hybrid-spec-framework/blob/main/SPEC-KIT-BEST-PRACTICES.md
- https://github.blog/ai-and-ml/generative-ai/spec-driven-development-using-markdown-as-a-programming-language-when-building-with-ai/
- https://medium.com/@visrow/comprehensive-guide-to-spec-driven-development-kiro-github-spec-kit-and-bmad-method-5d28ff61b9b1
- https://www.nosam.com/spec-driven-development-openspec-vs-spec-kit-vs-bmad-which-ones-actually-worth-your-time/
- https://kiro.dev/
- Local accelerator resources under `C:\Users\Stephen.phillips\Downloads\Ai Accelerator\London_Dev_Track_Resources\Dev day 1 & 2 resources`
- Local lab brief `C:\Users\Stephen.phillips\Downloads\Ai Accelerator\Developer Track - Labs.pdf`
- Existing project plan `PLAN.md`
- Public repository metadata from `https://github.com/SPhillips1337/`

## Assumptions

- The working project name is `repo-audit-scan`.
- The first implementation will use Python and FastMCP to stay aligned with `repo-security-scan`.
- The first-class target is a local repository path, not remote GitHub scanning.
- The MVP is read-only against the target repository unless the caller explicitly asks it to write report artifacts.
- The tool helps an AI agent scan, triage, and verify fixes, but it does not directly modify application code in the MVP.
- The rule system should be language-agnostic at the core and stack-aware through adapters. No single language or framework should be treated as the default center of gravity.
- "IAN profile" means a risk interpretation model inspired by the Ian security audit interpreter: prioritize realistic attacker paths, blast radius, exploitability, exposure, detection gaps, deploy gaps, ownership, and compromise mode. It is not a requirement to reproduce Ian's voice in machine output.

## Resolved Decisions

- Ticket-system integration is controlled by environment/config. The default provider is `none`, which means the tool produces ticket-ready Markdown and lets the AI agent or user manage issue creation.
- Git blame attribution is opt-in only. Commit SHA, file, and line evidence are sufficient by default.
- The first public release is not .NET-first or Node-first. It audits any repository through a universal audit core plus language/framework adapters.
- **MVP adapter coverage** is PHP/WordPress, Python, JavaScript/TypeScript, and CI/CD, on top of the universal rule set. C#/.NET and Docker are supported by adapter design (loadable, tested at the seam) but are not required to ship MVP-complete and are not the dominant calibration target.
- **Dependency vulnerability enrichment** uses local lockfile parsing by default in the MVP, with no network calls. Network-backed enrichment against OSV and the GitHub Advisory Database is supported as an opt-in mode, gated by an explicit config flag and environment variable. When enrichment is off, dependency findings are still produced from manifest/lockfile signals; CVE-level context is added only when the opt-in mode is active.
- **Report mirroring** has different defaults for CLI and MCP. The CLI defaults to writing reports to both the tool workspace and the target repository under `audits/YYYY-MM-DD/repo-audit-scan/`, matching the accelerator workflow. The MCP server defaults to writing reports to the tool workspace only and never mirrors into the target repository unless the caller explicitly opts in by passing `write_reports: true` and `mirror_to_target_repo: true` (or equivalent). This prevents an MCP-driven agent from surprising the user by dirtying the target worktree.

## Remaining Open Questions

None blocking MVP. Future decisions tracked in the Living Documentation Feedback Loop (Section 18) and Definition of Done sections.

## Repository Landscape Used for Calibration

The public repositories under `SPhillips1337` show a broad stack mix. The scanner should therefore be built around common security questions first, then stack-specific detectors.

Observed public repo patterns:

- PHP and WordPress plugins/sites, including invoice management, SSO, upload, redirect, crypto/chart, media, and older filesystem-backed apps.
- JavaScript and TypeScript web applications, browser games, dashboards, VS Code extensions, schema tools, and API bridges.
- Python tools, FastAPI-style services, MCP servers, agent orchestrators, local automation, and AI workflow utilities.
- Mixed repositories with Dockerfiles, shell scripts, PowerShell scripts, SQL/PLpgSQL, CSS/HTML, and generated assets.
- Smaller C# surface area for desktop/game-mod style code.

This means the MVP must not rely on one framework's conventions. It must first identify repository shape, entry points, dependency manifests, data flows, auth surfaces, external integrations, and execution/deployment surfaces, then apply the strongest available adapter rules.

## 2. Problem Statement

Security audit workflows from the AI Accelerator are powerful but manual. A developer or AI agent can create living documentation, run a code audit, interpret findings, triage tickets, and implement a fix, but those steps currently depend on prompts, local templates, ad hoc agent behavior, and manual coordination.

The result is hard to repeat across repositories. Findings may be inconsistent, difficult to compare, weakly prioritized, or too vague for another developer or agent to fix safely. Existing `repo-security-scan` covers hardcoded secrets and API keys; this project covers the broader code-audit class of risk: authorization gaps, injection paths, insecure configuration, weak crypto, missing validation, dependency risk, logging and detection gaps, and related security posture issues.

The problem to solve is not just "find risky code." The problem is to automate the full audit-to-triage loop in a way that produces evidence-backed findings an AI agent can use to prioritize and verify fixes.

## 3. Goal

Build a local CLI and MCP server that can scan a repository in any common language or framework, produce evidence-backed security findings, score and prioritize them using the IAN risk profile, generate ticket-ready triage output, and verify whether a specific finding has been fixed.

The tool should let a user or AI agent run this workflow:

1. Point the tool at a local repository.
2. Detect repository shape, languages, frameworks, dependency manifests, entry points, deployment files, and security-relevant files.
3. Run a curated set of universal rules plus any matching stack-specific adapters.
4. Produce structured findings with file, line, evidence, category, stack context, confidence, severity, and IAN priority score.
5. Generate a human-readable audit report and a machine-readable JSON report.
6. Triage the highest-risk findings into ticket-ready Markdown.
7. Let an AI agent implement a fix outside this tool.
8. Verify that the specific finding no longer appears.

## 4. Non-goals

- Do not build a general-purpose SAST replacement for CodeQL, Semgrep, Snyk, or commercial scanners.
- Do not scan hardcoded secrets as a primary feature; that remains the responsibility of `repo-security-scan`.
- Do not automatically change application code in the MVP.
- Do not guarantee absence of vulnerabilities.
- Do not perform live exploitation, penetration testing, credential stuffing, or network attacks.
- Do not upload source code to remote services by default.
- Do not require a ticketing system integration for the MVP.
- Do not require a UI for the MVP.
- Do not attempt to fully implement every accelerator audit template in the first release.
- Do not attempt exhaustive language-specific coverage for every programming language in the MVP; the MVP should provide a strong universal workflow and high-value adapters for common stacks.

## 5. Target User

Primary users:

- Developers using AI agents to audit and fix security issues in repositories they own.
- Security-minded engineering leads who want a repeatable local audit workflow.
- AI agents connected over MCP that need structured repository-risk context before fixing code.

Secondary users:

- Teams adopting spec-driven development and living documentation.
- Reviewers who need evidence-backed security tickets and verification steps.
- Trainers or facilitators running the AI Accelerator Day 1 workflow again.

## 6. Real-world Workflow Being Automated

The tool automates the Day 1 AI Accelerator flow:

1. **Living documentation context:** A repo is documented using the living document skeleton so humans and agents can understand purpose, interfaces, dependencies, conventions, and gotchas.
2. **Code audit:** An agent runs security and infrastructure audit prompts against a brownfield repository and writes reports under `audits/YYYY-MM-DD/`.
3. **IAN interpretation:** High-risk findings are re-read through an attacker-path lens. Severity is treated as a starting point, not the final verdict.
4. **Ticket triage:** The top findings are converted into enriched tickets with file references, suspected root cause, affected flows, acceptance criteria, and verification guidance.
5. **Fix workflow:** A developer or AI agent picks one finding, confirms the root cause, implements the smallest correct fix, validates it, opens a PR, and documents verification.

This product compresses steps 2, 3, and the first half of step 4 into a reusable tool. It also supports step 5 by exposing `verify_fix` so an agent can confirm a fix before writing a PR description.

## 7. Inputs

### Required Inputs

- `path`: Absolute or relative path to a local repository.

### Optional Inputs

- `profile`: Framework or repository profile override. Supported values include `auto`, `generic`, `php`, `wordpress`, `laravel`, `python`, `fastapi`, `javascript`, `typescript`, `node`, `react`, `csharp`, `dotnet`, and future adapter names.
- `ticket_provider`: Optional issue integration provider. Values: `none`, `github`, `jira`, `azure_devops`. Default: `none`.
- `min_severity`: Minimum severity to report. Values: `Info`, `Low`, `Medium`, `High`, `Critical`.
- `min_ian_score`: Minimum IAN priority score to report.
- `include_git_blame`: Boolean. When true, findings include commit attribution where available.
- `include_generated_reports`: Boolean. When true, write report files to disk. Synonym: `write_reports`.
- `mirror_to_target_repo`: Boolean. When true, mirror written reports into the target repository under `audits/YYYY-MM-DD/repo-audit-scan/`. Default: `true` for CLI, `false` for MCP.
- `enrich_dependencies`: Boolean. Per-invocation override for dependency enrichment. Honoured only when the server is permitted to enrich via config/env.
- `output_dir`: Optional report output directory.
- `config_file`: Optional audit configuration file.
- `exclude_paths`: Additional paths to exclude.
- `max_file_size`: Maximum source file size to scan.
- `max_files`: Optional scan cap for very large repositories.
- `report_id`: Existing report identifier for triage or verification operations.
- `finding_id`: Existing finding identifier for fix verification.

### Configuration Inputs

The tool should support a project-level config file named `repo-audit-scan.yml` or `.repo-audit-scan.yml`.

Minimum config fields:

```yaml
profile: auto
min_severity: Low
min_ian_score: 0
include_git_blame: false
ticketing:
  provider: ${REPO_AUDIT_TICKET_PROVIDER:-none}
  create_issues: false
  project: ${REPO_AUDIT_TICKET_PROJECT:-}
  default_labels:
    - security
    - audit
exclude_paths:
  - .git
  - node_modules
  - vendor
  - dist
  - build
  - bin
  - obj
  - __pycache__
output:
  write_reports: true
  # CLI defaults to both destinations; MCP defaults to tool_workspace only
  # unless the caller explicitly opts in to target_repo mirroring.
  destinations:
    cli:
      - tool_workspace
      - target_repo
    mcp:
      - tool_workspace
  target_repo_dir: audits/YYYY-MM-DD
  tool_workspace_dir: scan-reports
  format:
    - json
    - markdown
dependencies:
  enrichment:
    enabled: ${REPO_AUDIT_DEP_ENRICHMENT:-false}
    sources:
      - osv
      - ghsa
    timeout_seconds: 10
    fail_open: true   # if enrichment errors, scan still completes with lockfile-only findings
rules:
  enabled_categories:
    - repository_inventory
    - auth
    - access_control
    - injection
    - crypto
    - config
    - validation
    - logging
    - dependency
    - ci_cd
    - file_upload
    - ssrf
    - deserialization
    - path_traversal
    - supply_chain
```

## 8. Outputs

### Machine-readable Report

The primary output is JSON. It must be stable enough for AI agents and future integrations to parse.

Minimum top-level fields:

```json
{
  "report_id": "2026-05-26T18-30-00Z_repo-name",
  "schema_version": "1.0",
  "tool_version": "0.1.0",
  "repository": {
    "path": "C:/path/to/repo",
    "name": "repo-name",
    "git_remote": "https://github.com/example/repo.git",
    "branch": "main",
    "commit": "abc123"
  },
  "scan": {
    "started_at": "2026-05-26T18:30:00Z",
    "completed_at": "2026-05-26T18:30:12Z",
    "profile": "polyglot",
    "detected_profiles": ["php", "wordpress", "javascript"],
    "files_scanned": 120,
    "files_skipped": 42,
    "loc_scanned": 18000
  },
  "summary": {
    "critical": 1,
    "high": 3,
    "medium": 8,
    "low": 4,
    "info": 2,
    "ian_mode": "TRIAGE",
    "highest_ian_score": 91
  },
  "findings": []
}
```

Minimum finding fields:

```json
{
  "finding_id": "AUTH-001-001",
  "rule_id": "AUTH-001",
  "title": "Authorization policy references an unseeded role",
  "category": "auth",
  "severity": "Critical",
  "confidence": "High",
  "ian_score": 91,
  "ian_mode": "TRIAGE",
  "chain_summary": "A protected route depends on a role that is referenced in policy but not reliably provisioned for a fresh deployment.",
  "location": {
    "file": "src/Auth/AuthorizationConfig.cs",
    "line": 42,
    "end_line": 42
  },
  "evidence": {
    "snippet": "policy.RequireRole(\"TenderManager\")",
    "redacted": false
  },
  "impact": "Users who should have access may be locked out, or teams may work around the policy incorrectly.",
  "recommendation": "Use a single role source of truth and verify the role is seeded during clean deployment.",
  "verification": "Re-run verify_fix for AUTH-001 and confirm no unresolved policy-to-role mismatch remains."
}
```

### Human-readable Reports

When report writing is enabled, generate:

- Tool workspace copy:
  - `scan-reports/<report_id>/report.json`
  - `scan-reports/<report_id>/report.md`
  - `scan-reports/<report_id>/triage.md`
  - `scan-reports/<report_id>/metadata.json`
- Target repository copy:
  - `audits/YYYY-MM-DD/repo-audit-scan/report.json`
  - `audits/YYYY-MM-DD/repo-audit-scan/report.md`
  - `audits/YYYY-MM-DD/repo-audit-scan/triage.md`
  - `audits/YYYY-MM-DD/repo-audit-scan/metadata.json`

Both destinations should contain the same report content. The target repository copy is for accelerator-style audit continuity; the tool workspace copy is for cross-repo history and MCP resource lookup.

The Markdown report must include:

- Executive summary.
- IAN mode and top risk chain.
- Findings grouped by priority, not only by category.
- File and line evidence.
- Recommended next action.
- Verification guidance.
- Skipped paths and scan coverage.

### Ticket-ready Markdown

The triage output should produce one section per selected finding using the accelerator `bug.md` spirit:

- Title.
- Summary.
- Environment or repository context.
- Reproducibility or verification status.
- Steps to confirm.
- Expected vs actual.
- Suspected root cause and affected files.
- Acceptance criteria.
- Fix verification command or MCP call.

## Stack-agnostic Audit Plan

The scanner should audit any repository through a layered workflow. Each layer produces evidence that later layers use for prioritization and triage.

### Phase 1: Repository Inventory

Detect and record:

- Languages by extension and manifest.
- Frameworks and platforms such as WordPress, Laravel, FastAPI, Flask, Express, React, Vite, Next.js, Phaser, VS Code extensions, .NET, Docker, and static sites.
- Package managers and lockfiles such as `composer.json`, `package.json`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `requirements.txt`, `pyproject.toml`, `Pipfile.lock`, `poetry.lock`, `.csproj`, `packages.lock.json`, and `go.mod`.
- Entry points such as web roots, controllers, route files, CLI entry points, worker scripts, MCP servers, API servers, plugin bootstrap files, and scheduled jobs.
- Deployment and runtime files such as Dockerfiles, compose files, GitHub Actions workflows, shell scripts, PowerShell scripts, Procfiles, and environment templates.
- Data stores and data flows suggested by SQL files, ORM models, database clients, migrations, filesystem persistence, and external APIs.

### Phase 2: Universal Security Pass

Run rules that apply across most stacks:

- Authentication and session handling.
- Authorization and access control.
- Injection risk: SQL, shell, template, command, LDAP, XPath, prompt/tool injection where applicable.
- Input validation and output encoding.
- File upload, file read/write, path traversal, and archive extraction.
- SSRF and unsafe URL fetching.
- Deserialization and dynamic code execution.
- Cryptography misuse and insecure randomness.
- Security headers, CORS, CSRF, cookies, and transport security.
- Error handling, logging, observability, and secret leakage into logs.
- Dependency and lockfile risk.
- CI/CD, workflow permissions, unpinned actions, unsafe triggers, and release automation.
- Docker and local runtime posture.

### Phase 3: Stack Adapter Pass

Apply adapters only when matching evidence exists.

Initial high-value adapters:

| Adapter | Detection examples | High-value checks |
|---|---|---|
| `php` | `*.php`, `composer.json` | SQL injection, unsafe includes, file upload handling, path traversal, weak session config, direct superglobal use, unsafe `eval`/`unserialize`, error display in production |
| `wordpress` | plugin header, `wp-content`, `add_action`, `add_shortcode` | nonce and capability checks, AJAX auth, shortcode output escaping, file upload paths, REST route permissions, option update abuse |
| `laravel` | `artisan`, `composer.json`, `routes/*.php` | mass assignment, route middleware gaps, CSRF exclusions, query builder raw SQL, debug mode, insecure storage links |
| `python` | `pyproject.toml`, `requirements.txt`, `*.py` | unsafe subprocess, pickle/yaml loading, FastAPI/Flask auth gaps, CORS, debug mode, temp file handling, path traversal |
| `mcp` | MCP server entry point, tool definitions | unsafe tool filesystem access, command execution tools, missing path allowlists, prompt-injection-sensitive tool descriptions |
| `javascript`/`typescript` | `package.json`, `*.js`, `*.ts` | Express route auth, SSRF via fetch/axios, command execution, prototype pollution patterns, XSS sinks, insecure local storage of tokens |
| `react`/browser | React/Vite/Next files | XSS sinks, dangerously-set HTML, token storage, unsafe postMessage, CSP and dependency risk |
| `csharp`/`.net` | `.csproj`, `*.cs` | authorization policies, role seeding, SQL raw execution, JWT validation config, CORS, developer exception page, antiforgery gaps |
| `ci_cd` | `.github/workflows`, scripts | `pull_request_target`, broad token permissions, unpinned actions, secret exposure, unsafe shell interpolation |
| `docker` | `Dockerfile`, compose files | root user, exposed ports, secrets in image args, unsafe volume mounts, missing health checks |

### Phase 4: Chain and Prioritize

Group related findings into attacker paths. A path can outrank an isolated finding when the combination materially increases risk. Example chains:

- Public upload endpoint plus path traversal plus weak content validation.
- WordPress AJAX route without nonce plus missing capability check plus option update.
- Python API route with open CORS plus bearer token in browser storage plus weak authorization.
- GitHub Actions unsafe trigger plus broad token permissions plus publish step.
- MCP command tool plus weak path validation plus agent-accessible untrusted input.

### Phase 5: Triage and Verification

For the top findings:

- Generate ticket-ready Markdown.
- State what must be confirmed in source before fixing.
- Include the smallest expected fix shape without prescribing unrelated refactors.
- Include `verify_fix` instructions.
- Preserve report evidence so a later agent can continue without re-running the whole scan.

## 9. MCP Requirements

The MCP server must expose tools that are safe for AI agents to call during audit and fix workflows.

### Required MCP Tools

#### `scan_repository`

Run a repository scan.

Inputs:

- `path` string, required.
- `profile` string, optional.
- `min_severity` string, optional.
- `min_ian_score` number, optional.
- `include_git_blame` boolean, optional.
- `write_reports` boolean, optional. Defaults to `false` for MCP callers.
- `mirror_to_target_repo` boolean, optional. Defaults to `false` for MCP callers. Has no effect unless `write_reports` is also `true`. When `true`, the report is also written to `audits/YYYY-MM-DD/repo-audit-scan/` inside the target repository.
- `enrich_dependencies` boolean, optional. Per-call override for the dependency-enrichment config. Honoured only when the server has enrichment permission via config/env.

Returns:

- Report summary.
- Findings array.
- Report ID.
- Paths to written artifacts, if any.
- Enrichment metadata, if enrichment ran.

#### `list_rules`

List available rules.

Inputs:

- `profile` string, optional.
- `category` string, optional.
- `severity` string, optional.

Returns:

- Rule IDs, categories, descriptions, default severities, supported profiles, and whether each rule is enabled.

#### `get_finding`

Return one finding from a previous report.

Inputs:

- `report_id` string.
- `finding_id` string.

Returns:

- Full finding record and related report metadata.

#### `triage_report`

Prioritize findings and generate ticket-ready output.

Inputs:

- `report_id` string.
- `limit` number, optional, default `5`.
- `min_ian_score` number, optional.
- `include_markdown` boolean, optional.
- `ticket_provider` string, optional, default from config/environment.
- `create_external_issues` boolean, optional, default `false`.

Returns:

- Prioritized finding list.
- Rationale for ordering.
- Ticket-ready Markdown for each selected finding.
- External issue references only when a provider is configured and issue creation is explicitly enabled.

#### `verify_fix`

Verify whether a finding or rule still fires after a fix.

Inputs:

- `path` string.
- `finding_id` string, optional.
- `rule_id` string, optional.
- `report_id` string, optional.

Returns:

```json
{
  "resolved": true,
  "checked_at": "2026-05-26T19:00:00Z",
  "finding_id": "AUTH-001-001",
  "rule_id": "AUTH-001",
  "remaining_locations": [],
  "notes": "No unresolved policy-to-role mismatch found."
}
```

#### `get_latest_report`

Return the most recent report metadata and summary.

Inputs:

- None, or optional `path`.

Returns:

- Latest report ID.
- Summary.
- Artifact paths.

### Required MCP Resources

- `repo-audit://server/info`
- `repo-audit://server/health`
- `repo-audit://server/status`
- `repo-audit://server/config`
- `repo-audit://adapters`
- `repo-audit://reports`
- `reports://latest`
- `reports://{report_id}`
- `rules://registry`
- `findings://{report_id}/{finding_id}`

### Operational Support Tools

The Spark MCP gateway pattern shows that an MCP server becomes much easier to operate when it exposes its own state as first-class tools/resources. `repo-audit-scan` should include a small support surface so AI agents can confirm the scanner is healthy before relying on findings.

#### MVP Support Tools

##### `server.get_info`

Return static server metadata.

Returns:

- Name.
- Version.
- Protocol version.
- Transport.
- Enabled capabilities.
- Report schema version.
- Rule registry version.

##### `server.get_health`

Return live process health.

Returns:

- `status`: `ok`, `degraded`, or `error`.
- Current timestamp.
- Uptime.
- Memory usage.
- CPU time where available.
- Active scan count.
- Last scan status.
- Writable report destination status.

##### `server.get_status`

Return operational state useful to an agent.

Returns:

- Effective config source.
- Enabled output destinations.
- Enabled rule categories.
- Loaded adapters.
- Last report ID.
- Pending or running scan jobs.
- Any degraded capabilities, such as missing Git, missing parser dependency, or unavailable optional network enrichment.

##### `diagnostics.validate_config`

Validate configuration without running a scan.

Inputs:

- `path` string, optional.
- `config_file` string, optional.

Returns:

- Config validation result.
- Resolved defaults.
- Redacted environment-derived values.
- Warnings for risky settings such as report mirroring into a dirty target repo.

##### `diagnostics.run_self_check`

Run a local self-check of the scanner installation.

Returns:

- Python/runtime version.
- Writable report directories.
- Rule registry load status.
- Adapter load status.
- Git availability.
- Optional dependency availability.
- MCP resource availability.

##### `reports.list_reports`

List known reports from the tool workspace and, optionally, a target repository.

Inputs:

- `path` string, optional.
- `limit` number, optional.

Returns:

- Report IDs.
- Repository names/paths.
- Scan timestamps.
- Highest severity and IAN score.
- Artifact locations.

#### MVP Support Resources

All support resources should return `application/json`.

| URI | Name | Description |
|---|---|---|
| `repo-audit://server/info` | Server Info | Static metadata: name, version, schema versions, transport, capabilities |
| `repo-audit://server/health` | Server Health | Live process health: status, uptime, memory, CPU, active scans |
| `repo-audit://server/status` | Server Status | Effective scanner state: loaded adapters, enabled rules, recent scans |
| `repo-audit://server/config` | Effective Config | Redacted effective config after defaults, env vars, and config files are resolved |
| `repo-audit://adapters` | Adapter Inventory | Loaded stack adapters and detection signals they support |
| `repo-audit://reports` | Report Inventory | Recent report list across the tool workspace |

#### Future Support Tools

These are useful, but should not block the audit MVP:

- `plugins.list_adapters`: list installed third-party rule/adapters.
- `plugins.reload_adapters`: reload local adapters from an allowlisted plugin directory.
- `scan.get_job_status`: inspect an async scan job.
- `scan.cancel_job`: cancel a long-running scan.
- `audit_log.get_recent_events`: show recent MCP tool calls and safety events.
- `safety.list_pending_approvals`: list actions waiting for human approval.
- `safety.approve_action`: approve a gated write action such as external ticket creation or living-doc update application.
- `docs.review_living_docs`: compare living docs with the repository and latest audit.
- `docs.propose_living_doc_updates`: produce patch-ready Markdown updates for review.
- `docs.verify_living_docs`: verify that previously surfaced doc gaps are resolved.

#### Plugin Discovery Guidance

The Spark gateway's IoT-style plugin discovery is useful, but riskier for a security scanner because third-party rules run against source code and may influence agent behavior. For this project:

- MVP should not hot-load arbitrary executable plugins.
- Phase 2 may support local adapter discovery from an allowlisted directory.
- Discovered adapters must declare a manifest with name, version, rule IDs, supported profiles, permissions, and whether they execute external commands.
- Adapters should be disabled by default until explicitly enabled in config.
- Adapter manifests should be included in `server.get_status` and `repo-audit://adapters`.

#### Prompt Guidance

Structured MCP prompts are useful for repeatable agent workflows. The MVP should include these prompts if the chosen MCP framework supports prompts without adding complexity:

- `audit_repository`: guide an agent through scan -> read report -> triage top findings.
- `triage_finding`: guide an agent through treating a finding as a hypothesis before creating a ticket.
- `verify_fix`: guide an agent through post-fix verification and PR evidence.
- `review_living_docs`: future prompt for the documentation feedback loop.

### MCP Safety Rules

- The MCP server must treat repository source, README files, issue text, audit reports, and living docs as untrusted input.
- Tool responses that include source snippets or documentation excerpts must preserve provenance so an agent can distinguish scanned content from tool instructions.
- The MCP server should annotate or redact prompt-injection-like content found in scanned files instead of returning it as unqualified instructions.
- The MCP server must not modify target repository source files.
- The MCP server may write report files only when `write_reports` is true.
- The MCP server must reject paths outside caller-allowed directories if a host integration provides such boundaries.
- The MCP server must not execute project code as part of scanning.
- The MCP server must not run package install commands.
- The MCP server must return explicit errors rather than silently skipping unreadable repositories.
- Write-like operations, including external ticket creation and future living-doc update application, must require explicit opt-in and should support a human approval gate.

## 10. Functional Requirements

### Repository Scanning

- **FR-001:** The tool shall accept a local repository path and scan source, configuration, dependency, and CI/CD files.
- **FR-002:** The tool shall exclude common generated, vendored, dependency, and build-output directories by default.
- **FR-003:** The tool shall support custom exclude paths from config and runtime arguments.
- **FR-004:** The tool shall detect repository shape using source extensions, project files, dependency manifests, framework markers, entry points, runtime scripts, deployment files, and CI/CD files.
- **FR-005:** The tool shall support multiple detected profiles in one repository.
- **FR-006:** The tool shall allow the caller to override or supplement detected profiles.
- **FR-007:** The tool shall report skipped files and skip reasons in metadata.

### Rule Execution

- **FR-008:** The tool shall use a versioned rule registry.
- **FR-009:** Each rule shall have an ID, title, category, default severity, supported profiles, description, detection logic, remediation guidance, and tests.
- **FR-010:** The MVP shall include universal high-signal rules for authorization, access control, injection, crypto, configuration, error handling, input validation, logging/detection, dependencies, CI/CD, file handling, SSRF, deserialization, and supply chain risk.
- **FR-011:** The MVP shall include stack adapters for PHP/WordPress, Python, JavaScript/TypeScript, and CI/CD on top of the universal rule set. C#/.NET and Docker adapters shall be supported by the adapter contract and loadable, but are not required to be MVP-complete in their rule coverage.
- **FR-012:** A finding shall not be emitted unless it has concrete evidence tied to an existing file path.
- **FR-013:** Rules shall support confidence levels: `Low`, `Medium`, `High`.
- **FR-014:** Rules that require manual confirmation shall be marked clearly and shall not be presented as confirmed vulnerabilities.

### IAN Risk Scoring and Prioritization

- **FR-015:** Every finding shall receive an IAN priority score from 0 to 100.
- **FR-016:** The IAN score shall consider impact, exposure, exploitability, chain potential, detection gap, deploy gap, and evidence confidence.
- **FR-017:** Every report shall include one compromise mode: `COVER`, `TRIAGE`, or `ASSUME_BREACH`.
- **FR-018:** Critical attacker paths shall be prioritized above isolated low-impact findings even when raw severity labels are similar.
- **FR-019:** The tool shall explain why a finding was prioritized in plain engineering language.
- **FR-020:** The tool shall allow filtering by minimum IAN score.

Recommended initial scoring model:

| Component | Points |
|---|---:|
| Impact on data, identity, privilege, or availability | 0-25 |
| Exposure: public, customer-reachable, internal, local-only | 0-20 |
| Exploitability and required preconditions | 0-20 |
| Chain multiplier with other findings | 0-15 |
| Detection and incident-response gap | 0-10 |
| Deploy or customer rollout gap | 0-5 |
| Evidence confidence | 0-5 |

Recommended bands:

| IAN Score | Priority |
|---:|---|
| 85-100 | Critical |
| 70-84 | High |
| 45-69 | Medium |
| 20-44 | Low |
| 0-19 | Info |

`ASSUME_BREACH` mode may override the numeric band when the report shows public exposure plus sensitive data plus a critical attacker path such as auth bypass, RCE-adjacent behavior, exposed credentials, direct data exfiltration, or severe detection blindness.

### Reporting

- **FR-021:** The tool shall produce a JSON report for machine consumption.
- **FR-022:** The tool shall produce a Markdown report for humans when report writing is enabled.
- **FR-023:** Reports shall include repository metadata where available: name, path, remote, branch, and commit.
- **FR-024:** Reports shall include scan metadata: started time, completed time, detected profiles, files scanned, files skipped, and LOC estimate.
- **FR-025:** Reports shall group findings by IAN priority and category.
- **FR-026:** Reports shall include remediation guidance and verification guidance for each finding.
- **FR-027:** Reports shall include a concise top-priority action list.
- **FR-028:** When report writing is enabled, reports may be written to the tool workspace and/or the target repository under `audits/YYYY-MM-DD/repo-audit-scan/`. Defaults differ by entry point: the CLI shall write to both destinations by default, while the MCP server shall write to the tool workspace only by default and shall only mirror into the target repository when the caller explicitly opts in.

### Triage

- **FR-029:** The tool shall generate ticket-ready Markdown for selected findings.
- **FR-030:** Triage output shall include enough context for a developer or AI agent to confirm the issue without rereading the entire report.
- **FR-031:** Triage output shall preserve the principle that audit findings are hypotheses until verified in the source.
- **FR-032:** Triage output shall include acceptance criteria for the fix.
- **FR-033:** Triage output shall include verification steps that can be run after the fix.

### Ticket Integration

- **FR-034:** Ticket-system integration shall be controlled by config and environment variables.
- **FR-035:** The default ticket provider shall be `none`.
- **FR-036:** When the provider is `none`, the tool shall never create external tickets and shall only return ticket-ready Markdown.
- **FR-037:** When a provider is configured, external issue creation shall still require an explicit `create_external_issues: true` or equivalent CLI flag.
- **FR-038:** Supported provider names shall include `github`, `jira`, and `azure_devops`, but provider implementation may be phased after the Markdown-only MVP.
- **FR-039:** Ticket integrations shall return external issue URLs/IDs without changing the finding schema.

Recommended environment variables:

```bash
REPO_AUDIT_TICKET_PROVIDER=none
REPO_AUDIT_TICKET_CREATE=false
REPO_AUDIT_TICKET_PROJECT=
REPO_AUDIT_TICKET_DEFAULT_LABELS=security,audit
REPO_AUDIT_DEP_ENRICHMENT=false
REPO_AUDIT_GHSA_TOKEN=
```

### Fix Verification

- **FR-040:** The tool shall verify a specific finding by re-running the relevant rule or equivalent targeted analysis.
- **FR-041:** `verify_fix` shall return `resolved: true` only when no remaining matching locations are found.
- **FR-042:** `verify_fix` shall return remaining locations when unresolved.
- **FR-043:** `verify_fix` shall be callable over both CLI and MCP.
- **FR-044:** Verification shall be scoped to the original finding or rule and shall not require a full report regeneration unless necessary.

### CLI

- **FR-045:** The CLI shall provide a scan command.
- **FR-046:** The CLI shall provide a rules listing command.
- **FR-047:** The CLI shall provide a triage command for an existing report.
- **FR-048:** The CLI shall provide a verify command for a finding or rule.
- **FR-049:** CLI output shall support JSON for automation and Markdown or plain text for humans.

### Operational Support

- **FR-050:** The MCP server shall expose static server metadata through both `server.get_info` and `repo-audit://server/info`.
- **FR-051:** The MCP server shall expose live health through both `server.get_health` and `repo-audit://server/health`.
- **FR-052:** The MCP server shall expose effective operational status through both `server.get_status` and `repo-audit://server/status`.
- **FR-053:** The MCP server shall expose redacted effective configuration through `repo-audit://server/config`.
- **FR-054:** The MCP server shall expose adapter inventory through `repo-audit://adapters`.
- **FR-055:** The MCP server shall provide `diagnostics.validate_config` to validate config without scanning.
- **FR-056:** The MCP server shall provide `diagnostics.run_self_check` to verify local runtime, report paths, rule registry, adapters, and Git availability.
- **FR-057:** The MCP server shall provide `reports.list_reports` to list known reports from the tool workspace and optionally a target repo.
- **FR-058:** All operational resources shall return `application/json`.
- **FR-059:** Prompt-injection-like content found in scanned source, docs, or issue text shall be treated as untrusted content and returned with provenance or warnings, not as instructions to the agent.

### Dependency Vulnerability Enrichment

- **FR-060:** The MVP shall parse local dependency manifests and lockfiles to produce dependency findings without requiring network access.
- **FR-061:** The tool shall support an opt-in enrichment mode that augments dependency findings with CVE-level context sourced from OSV and the GitHub Advisory Database when network access is permitted.
- **FR-062:** Enrichment shall be gated by both a config flag (`dependencies.enrichment.enabled: true`) and an environment variable (`REPO_AUDIT_DEP_ENRICHMENT=true`). Enrichment shall remain off unless both signals agree, or unless the caller passes an equivalent explicit CLI/MCP flag.
- **FR-063:** When enrichment is disabled, dependency findings shall still include manifest/lockfile evidence (file, line, package, version, range). The findings shall be labelled as "lockfile-only" so an agent can decide whether to re-run with enrichment enabled.
- **FR-064:** When enrichment is enabled, the tool shall record the data source(s) used (OSV, GHSA), the data freshness timestamp, and any partial-failure conditions (rate limits, network errors) in the report metadata.
- **FR-065:** Enrichment shall never transmit source code, repository path, secrets, or finding text to external services. Only minimal package coordinates (ecosystem, name, version) shall be sent.

Suggested CLI shape:

```bash
repo-audit-scan scan C:\path\to\repo --profile auto --min-severity Low
repo-audit-scan rules --profile wordpress
repo-audit-scan triage --report scan-reports/<report_id>/report.json --limit 5
repo-audit-scan verify C:\path\to\repo --report scan-reports/<report_id>/report.json --finding AUTH-001-001
```

## 11. Non-functional Requirements

- **NFR-001:** The tool shall run locally by default.
- **NFR-002:** The tool shall not require internet access for the MVP. Opt-in dependency enrichment (FR-061..FR-065) is the only feature that may make outbound network calls, and only when explicitly enabled.
- **NFR-003:** The tool shall not execute target repository application code.
- **NFR-004:** The tool shall complete a scan of a small repository under 10,000 LOC in under 30 seconds on a normal developer laptop.
- **NFR-005:** The tool shall handle repositories over 100,000 LOC through sampling, file caps, or progress reporting rather than crashing.
- **NFR-006:** The JSON report schema shall be versioned.
- **NFR-007:** Rule IDs shall be stable once released.
- **NFR-008:** Errors shall be explicit, actionable, and non-destructive.
- **NFR-009:** Reports shall redact likely secrets from evidence snippets.
- **NFR-010:** The scanner shall be deterministic for the same repo state, config, and rule version.
- **NFR-011:** The implementation shall have automated tests for rule behavior, scoring, report generation, and MCP tool responses.
- **NFR-012:** The tool shall be installable and runnable without requiring global system changes beyond normal Python package installation.
- **NFR-013:** The MCP server shall be compatible with common local AI agent clients that support MCP.

## 12. Edge Cases

- The target path does not exist.
- The target path exists but is not a Git repository.
- The target repository has no remote.
- The target repository has a detached HEAD.
- The target repository has uncommitted changes.
- The tool lacks permission to read some files.
- The repository contains symlink loops.
- The repository contains binary files, minified files, large generated files, or checked-in build outputs.
- The repository is a monorepo with multiple framework profiles.
- The repository contains multiple unrelated apps in one tree.
- The repository has no obvious framework but includes security-sensitive scripts.
- The repository is mostly static HTML/CSS with small embedded scripts.
- The repository contains old PHP scripts without dependency manifests.
- The repository contains WordPress plugin code outside a normal WordPress installation.
- A finding spans multiple files.
- A finding is a chain of weaker signals rather than one direct match.
- A rule has low confidence because the relevant context is incomplete.
- The same issue appears in multiple files and should be deduplicated.
- A file uses unusual line endings or encoding.
- A repo contains test fixtures that intentionally include vulnerable code.
- A repo contains examples or documentation with vulnerable snippets that should not be scored like production code.
- Git blame is unavailable, too slow, or disabled.
- A report exists but the repository has changed since it was generated.
- `verify_fix` is called for a finding whose original file no longer exists.
- `verify_fix` is called after a legitimate refactor moved the relevant code.
- A requested framework profile is unsupported.

## 13. Data Privacy and Safety Considerations

- Source code must remain local by default.
- Reports may contain sensitive code snippets; users should treat report artifacts as confidential.
- Evidence snippets should be short and should redact likely credentials, tokens, connection strings, and private keys.
- Git blame attribution can identify individuals. It should be optional, factual, and framed as training/process context, not blame.
- The tool should avoid storing full source files in reports.
- The tool should not transmit reports or findings to external services unless a future explicit integration requires user opt-in.
- MCP tools should avoid exposing arbitrary file read behavior beyond the repository scan scope.
- Findings should be labelled as confirmed only when supported by direct evidence.
- Low-confidence or manually-verifiable findings should be clearly labelled to reduce false-positive driven churn.
- The tool should not provide exploit payloads that meaningfully increase risk beyond what is needed to confirm and fix the issue.
- The tool should not run destructive commands in target repositories.
- When report output is written into a target repo, the tool should clearly state that it may dirty the worktree.

## 14. Acceptance Criteria

- **AC-001:** Given a local PHP/WordPress fixture with an AJAX handler that lacks nonce or capability checks, `scan_repository` emits an access-control finding with file, line, severity, IAN score, and remediation guidance.
- **AC-002:** Given a repository with SQL string interpolation or unsafe raw-query fixture code in PHP, Python, JavaScript/TypeScript, or C#, the tool emits an injection finding with `Critical` or `High` severity depending on context.
- **AC-003:** Given a repository with no matching issues, the tool emits a valid report with zero findings and no fabricated vulnerabilities.
- **AC-004:** Given a repository with `node_modules`, `bin`, `obj`, `.git`, and `dist`, the scanner excludes those paths by default and records skip counts.
- **AC-005:** Given the same repo, config, and rule version twice, the tool produces equivalent finding IDs and scores.
- **AC-006:** Given `include_git_blame: false`, reports do not include author names or emails.
- **AC-007:** Given `include_git_blame: true` in a Git repo, findings include attribution when Git can provide it and degrade gracefully when it cannot.
- **AC-008:** Given `triage_report --limit 3`, the tool returns the top three findings sorted by IAN priority with rationale and ticket-ready Markdown.
- **AC-009:** Given a finding that has been fixed, `verify_fix` returns `resolved: true` and no remaining locations.
- **AC-010:** Given a finding that has not been fixed, `verify_fix` returns `resolved: false` and remaining locations.
- **AC-011:** Given `write_reports: true` on a CLI invocation, the tool writes JSON and Markdown reports to both the tool workspace and `audits/YYYY-MM-DD/repo-audit-scan/` in the target repository. See AC-029, AC-030, AC-031 for the explicit CLI-vs-MCP defaults.
- **AC-012:** Given `write_reports: false`, the tool returns results without creating report files.
- **AC-013:** Given a malformed config file, the tool returns a clear validation error and does not run with guessed settings.
- **AC-014:** Given an unsupported profile override, the tool returns a clear unsupported-profile error.
- **AC-015:** The MCP server exposes `scan_repository`, `list_rules`, `get_finding`, `triage_report`, `verify_fix`, and `get_latest_report`.
- **AC-016:** MCP tool responses are JSON-serializable and contain no unhandled exceptions or stack traces in normal error cases.
- **AC-017:** Given `REPO_AUDIT_TICKET_PROVIDER=none`, triage returns Markdown and does not attempt to create an external issue.
- **AC-018:** Given a mixed-language repository, the report includes multiple detected profiles and applies both universal rules and matching adapter rules.
- **AC-019:** `server.get_health` and `repo-audit://server/health` return `ok`, `degraded`, or `error` plus uptime and last scan status.
- **AC-020:** `diagnostics.validate_config` reports malformed or risky configuration without running a scan.
- **AC-021:** `diagnostics.run_self_check` reports rule registry, adapter, Git, and report-path readiness.
- **AC-022:** `repo-audit://server/config` returns effective config with credentials and tokens redacted.
- **AC-023:** `repo-audit://adapters` lists loaded adapters and their supported profiles.
- **AC-024:** A fixture containing prompt-injection text in README/source is reported as scanned content with provenance/warning and is not emitted as tool instruction text.
- **AC-025:** Given the same mixed-language fixture repo, the MVP build loads adapters for PHP/WordPress, Python, JavaScript/TypeScript, and CI/CD and lists them in `repo-audit://adapters`. C#/.NET and Docker adapters are loadable but may report empty or seed-only rule sets without failing the scan.
- **AC-026:** Given `REPO_AUDIT_DEP_ENRICHMENT=false` (default), a scan of a fixture with a vulnerable lockfile entry produces a dependency finding labelled "lockfile-only" with manifest evidence and no outbound network call is made.
- **AC-027:** Given `REPO_AUDIT_DEP_ENRICHMENT=true` and network available, the same scan produces an enriched dependency finding containing CVE identifiers, advisory URLs, source attribution, and a freshness timestamp.
- **AC-028:** Given enrichment is enabled but the network is unreachable, the scan completes with lockfile-only findings and the report metadata records the enrichment failure rather than aborting the scan.
- **AC-029:** Given a CLI scan with `write_reports: true`, reports are written to both `scan-reports/<report_id>/` and `audits/YYYY-MM-DD/repo-audit-scan/` in the target repository.
- **AC-030:** Given an MCP `scan_repository` call with `write_reports: true` but no `mirror_to_target_repo` flag, reports are written only to the tool workspace and no files are created inside the target repository.
- **AC-031:** Given an MCP `scan_repository` call with `write_reports: true` and `mirror_to_target_repo: true`, reports are written to both destinations and the response includes both paths.

## 15. Suggested Project Structure

This is a suggested structure for a future implementation. It is not created by this specification.

```text
repo-audit-scan/
  SPEC.md
  README.md
  AGENTS.md
  pyproject.toml
  repo_audit_scan/
    __init__.py
    cli.py
    mcp_server.py
    config.py
    models.py
    diagnostics.py
    server_status.py
    scanner/
      filesystem.py
      inventory.py
      profile_detection.py
      engine.py
      dedupe.py
    rules/
      registry.py
      common/
        auth.py
        access_control.py
        injection.py
        crypto.py
        config.py
        logging.py
        file_handling.py
        supply_chain.py
      adapters/
        php.py
        wordpress.py
        laravel.py
        python.py
        mcp.py
        javascript.py
        typescript.py
        react.py
        csharp_dotnet.py
        ci_cd.py
        docker.py
      dependencies.py
    ticketing/
      providers.py
      markdown.py
    prompts/
      audit_repository.md
      triage_finding.md
      verify_fix.md
    plugins/
      manifest.py
      loader.py
    scoring/
      ian.py
      severity.py
    reports/
      json_report.py
      markdown_report.py
      triage.py
    verify/
      fix_verifier.py
  tests/
    fixtures/
      php_wordpress_ajax_no_capability/
      python_fastapi_unsafe_subprocess/
      node_express_raw_sql/
      dotnet_auth_gap/
      generic_clean_repo/
      mixed_polyglot_repo/
    test_rules.py
    test_scoring.py
    test_reports.py
    test_cli.py
    test_mcp_server.py
    test_diagnostics.py
    test_server_resources.py
  scan-reports/
    .gitkeep
```

Rule storage can be Python modules, YAML files, or a hybrid. The important requirement is that rules are versioned, testable, and expose stable IDs.

## 16. Test Scenarios

### Scanner Tests

1. Scan a clean fixture repo and verify zero findings.
2. Scan a WordPress plugin fixture with an unauthenticated AJAX handler and verify one access-control finding.
3. Scan a PHP fixture with unsafe `include` or `unserialize` usage and verify the matching adapter rule fires.
4. Scan a Python API fixture with unsafe subprocess or unsafe YAML/pickle usage and verify one finding.
5. Scan a JavaScript/TypeScript API fixture with direct SQL interpolation and verify one `INJ-*` finding.
6. Scan a .NET fixture with an authorization role mismatch and verify one `AUTH-*` finding.
7. Scan a fixture with weak crypto and verify one `CRYPTO-*` finding.
8. Scan a fixture with excluded directories and verify those files are skipped.
9. Scan a non-Git directory and verify repository metadata degrades gracefully.
10. Scan a mixed-language repo and verify multiple profiles are detected.

### Scoring Tests

1. Public-facing critical auth bypass produces `ASSUME_BREACH` or high `TRIAGE` output according to the scoring rules.
2. Internal-only low-impact configuration issue scores below a high-risk attacker path.
3. A chain of medium findings can outrank an isolated high finding when the chain materially increases blast radius.
4. Low-confidence findings do not get promoted to confirmed critical findings without direct evidence.

### Reporting Tests

1. JSON report validates against the report schema.
2. Markdown report contains executive summary, IAN mode, top priorities, evidence, and verification guidance.
3. Ticket Markdown includes summary, suspected root cause, affected files, acceptance criteria, and fix verification steps.
4. Evidence snippets redact likely secrets.
5. CLI scans mirror reports to both `scan-reports/<report_id>/` and the target repo `audits/YYYY-MM-DD/repo-audit-scan/` by default.
6. MCP `scan_repository` writes only to the tool workspace by default, even with `write_reports: true`, unless `mirror_to_target_repo: true` is set.

### Dependency Enrichment Tests

1. Lockfile-only mode (default) produces dependency findings from a vulnerable fixture lockfile without any network calls. Findings are labelled "lockfile-only".
2. Enrichment-enabled mode against a fixture lockfile produces findings with CVE IDs, advisory URLs, and source attribution.
3. Enrichment-enabled mode with a simulated network failure falls back to lockfile-only findings and records the failure in report metadata; scan exit code stays 0 (`fail_open: true`).
4. Enrichment-enabled mode does not transmit source code, repository path, or finding text to OSV/GHSA. Only package coordinates are sent.

### MCP Tests

1. `list_rules` returns all enabled rules.
2. `scan_repository` returns JSON-serializable findings.
3. `get_finding` returns a known finding from a report.
4. `triage_report` returns findings sorted by IAN score.
5. `verify_fix` returns unresolved before a fixture fix and resolved after the fixture fix.
6. MCP errors are structured and do not crash the server.
7. `server.get_info`, `server.get_health`, and `server.get_status` return JSON-serializable operational state.
8. `resources/read` works for `repo-audit://server/info`, `repo-audit://server/health`, `repo-audit://server/status`, `repo-audit://server/config`, `repo-audit://adapters`, and `repo-audit://reports`.
9. `diagnostics.validate_config` rejects malformed config without scanning.
10. `diagnostics.run_self_check` reports environment readiness without requiring a target repo.

### CLI Tests

1. `scan` exits with code 0 for a valid repo.
2. `scan` exits non-zero for a missing path with a clear error.
3. `rules` lists rule IDs and categories.
4. `triage` reads an existing report.
5. `verify` checks a finding from an existing report.
6. A fixture containing prompt-injection text in documentation is returned as untrusted scanned content, not as operational instructions.

## 17. Definition of Done

For the future implementation to be considered complete for MVP:

- CLI and MCP server are both implemented.
- Required MCP tools are available and documented (Section 9).
- The scanner runs locally without internet access by default.
- Universal rule categories plus PHP/WordPress, Python, JavaScript/TypeScript, and CI/CD adapters are implemented and tested. C#/.NET and Docker adapters are loadable per the adapter contract but are not required to ship MVP-complete in rule coverage.
- Every emitted finding includes rule ID, title, category, severity, confidence, IAN score, location, evidence, impact, recommendation, and verification guidance.
- Reports are generated in JSON and Markdown.
- CLI scans mirror reports to both `scan-reports/<report_id>/` and the target repo `audits/YYYY-MM-DD/repo-audit-scan/` by default.
- MCP scans write reports to the tool workspace only by default; target-repo mirroring requires an explicit caller opt-in.
- Dependency findings are produced from local lockfiles without network calls by default. Opt-in OSV/GHSA enrichment is implemented behind a dual config + env gate and never transmits source or finding text.
- Operational MCP tools and resources expose server info, health, status, redacted config, adapter inventory, diagnostics, and report inventory.
- Triage output can produce ticket-ready Markdown for the top findings.
- Ticket provider defaults to `none`, so no external issues are created unless explicitly configured and requested.
- `verify_fix` can confirm resolution for at least one representative rule from each MVP category.
- Test fixtures cover clean repos, vulnerable repos, excluded paths, scoring, report generation, dependency enrichment (both modes), CLI behaviour, MCP behaviour, and the CLI-vs-MCP mirroring defaults.
- The README documents installation, CLI usage, MCP configuration, safety model, and examples.
- The AGENTS guide explains the scan -> triage -> fix -> verify workflow for AI agents.
- No implementation feature requires source code to leave the local machine.
- The tool has been tested against the accelerator-style sample workflow and can reproduce the core audit-to-triage loop.
- The Living Documentation Feedback Loop (Section 18) is explicitly out of scope for MVP and is not required to ship.

For this current specification task:

- `SPEC.md` exists at the repository root.
- No application code or implementation files have been created.
- Assumptions and open questions are captured explicitly.

## 18. Living Documentation Feedback Loop (Phase 2)

This section documents a Phase 2 module that complements the audit workflow with a documentation feedback loop. It is **not part of MVP** and must not block the core scanner from shipping. It is captured here because it is highly aligned with the AI Accelerator Day 1 workflow, and a coding agent will be able to slice it cleanly once the audit MVP is in place.

### 18.1 Purpose

The audit MVP produces evidence-backed security findings against a repository. Many of those findings expose gaps that are not purely "fix the code" gaps — they are knowledge gaps. The living docs say one thing, the repository does another, and the audit confirms the divergence.

The feedback loop closes this gap by letting the audit output drive review and improvement of the project's living documentation skeleton (see `Volaris-AI/living_doc_skeleton`). The MCP server provides tools; the AI agent or human owns judgment and approval.

### 18.2 Workflow

```text
scan repository (audit MVP)
  -> produce findings + IAN-prioritised report
review living docs against repo + findings
  -> surface doc gaps (stale, missing, contradicted by code)
propose living doc updates (draft Markdown patches, not applied)
  -> agent or human reviews and approves
apply approved living doc updates (gated, opt-in)
  -> updates land in the living docs path
verify living docs
  -> confirm the previously surfaced gaps are now resolved
```

The MCP server never silently rewrites project knowledge. Update application is gated by explicit caller intent plus an approval gate.

### 18.3 Phase 2 MCP Tools

These are listed in Section 9 under Future Support Tools. The Phase 2 plan formalises them:

#### `docs.review_living_docs`

Inputs:

- `path` string, required (repository root).
- `docs_path` string, optional (defaults to a living-docs path discovered from repo conventions).
- `report_id` string, optional (anchors the review to a specific audit report).

Returns:

- Doc gap list with IDs, evidence, related findings, suggested resolution category (stale, missing, contradicted, unverifiable).

#### `docs.propose_living_doc_updates`

Inputs:

- `path` string, required.
- `docs_path` string, optional.
- `doc_gap_ids` array of strings, required.

Returns:

- Patch-ready Markdown for each gap, including target file path and proposed insertion point. **Updates are not applied.**

#### `docs.apply_living_doc_updates`

Inputs:

- `path` string, required.
- `approved_patch_ids` array of strings, required.
- `actor` string, required (records who approved).

Returns:

- Per-patch apply result, files changed, and a verification handle.

#### `docs.verify_living_docs`

Inputs:

- `path` string, required.
- `report_id` string, optional.

Returns:

- Resolved-gap list and any remaining gaps.

### 18.4 Safety Model

- All `docs.*` tools treat living docs and repository source as untrusted input, as in Section 9 MCP Safety Rules.
- `docs.review_living_docs` and `docs.propose_living_doc_updates` are read-only and safe by default.
- `docs.apply_living_doc_updates` is the only write tool. It must:
  - Require an explicit list of approved patch IDs (no batch "apply all" path).
  - Refuse to apply patches that were not produced by an immediately-preceding `docs.propose_living_doc_updates` call against the same repository state.
  - Record actor identity, timestamp, and patch fingerprint in an audit log.
  - Support a `safety.list_pending_approvals` / `safety.approve_action` gate for hosts that wrap MCP with a human-in-the-loop approval UI.
- The Phase 2 module must surface, but never auto-apply, doc updates that would change ownership claims, security posture statements, or compliance claims.

### 18.5 Phase 2 Acceptance Criteria

- **AC-P2-001:** `docs.review_living_docs` against a repository whose living docs claim authenticated-only routes, paired with an audit report showing AUTH-* findings, returns one or more doc gaps with evidence citing both the docs and the failing code.
- **AC-P2-002:** `docs.propose_living_doc_updates` returns Markdown patches for the requested gap IDs without writing any files.
- **AC-P2-003:** `docs.apply_living_doc_updates` rejects patch IDs that did not originate from a recent `docs.propose_living_doc_updates` call.
- **AC-P2-004:** `docs.verify_living_docs` returns `resolved: true` for a gap whose approved patch has been applied.
- **AC-P2-005:** The MCP audit log records actor, timestamp, and patch fingerprint for every successful `docs.apply_living_doc_updates` call.

### 18.6 Out of Scope for Phase 2

- Auto-generation of new top-level living-doc sections from scratch.
- Cross-repository living-doc synchronisation.
- Editing project source code, READMEs outside the living-docs path, or release notes.
- Any path that mutates documentation without an explicit approval step.

## 19. Traceability Matrix

This matrix maps each Functional Requirement to the Acceptance Criteria and Test Scenarios that verify it. It is intentionally lightweight — its purpose is to give a coding agent a single place to reason about what each requirement is verified by, without re-reading the whole spec.

Test scenario IDs use the form `TS-<group>-<n>`, where `<group>` is one of `SCN` (Scanner), `SCO` (Scoring), `REP` (Reporting), `DEP` (Dependency Enrichment), `MCP` (MCP), `CLI` (CLI).

### 19.1 FR → AC → Test Mapping

| FR | Topic | Acceptance Criteria | Test Scenarios |
|---|---|---|---|
| FR-001 | Accept local repo path and scan | AC-003, AC-004 | TS-SCN-1, TS-SCN-8 |
| FR-002 | Default excludes for generated/vendored dirs | AC-004 | TS-SCN-8 |
| FR-003 | Custom exclude paths | AC-004 | TS-SCN-8 |
| FR-004 | Repository shape detection | AC-018, AC-025 | TS-SCN-10 |
| FR-005 | Multiple detected profiles per repo | AC-018, AC-025 | TS-SCN-10 |
| FR-006 | Caller override/supplement profiles | AC-014 | TS-CLI-2 |
| FR-007 | Report skipped files and reasons | AC-004 | TS-SCN-8 |
| FR-008 | Versioned rule registry | AC-005 | TS-MCP-1 |
| FR-009 | Required rule fields (ID, title, etc.) | AC-001, AC-002 | TS-SCN-2..7 |
| FR-010 | Universal MVP rule categories | AC-001, AC-002 | TS-SCN-2..7 |
| FR-011 | MVP stack adapters (PHP/WP, Python, JS/TS, CI/CD) | AC-018, AC-025 | TS-SCN-2..6, TS-SCN-10 |
| FR-012 | Concrete evidence required per finding | AC-003 | TS-SCN-1 |
| FR-013 | Confidence levels Low/Med/High | AC-005 | TS-SCO-4 |
| FR-014 | Manual-confirmation flag on uncertain rules | AC-005 | TS-SCO-4 |
| FR-015 | IAN score 0-100 per finding | AC-001 | TS-SCO-1..4 |
| FR-016 | IAN scoring inputs (impact, exposure, ...) | AC-001 | TS-SCO-1..3 |
| FR-017 | Compromise mode per report | AC-001 | TS-SCO-1 |
| FR-018 | Chains can outrank isolated findings | AC-008 | TS-SCO-3 |
| FR-019 | Explain prioritisation in plain language | AC-008 | TS-MCP-4 |
| FR-020 | Filter by minimum IAN score | AC-008 | TS-MCP-4 |
| FR-021 | JSON report output | AC-011, AC-012 | TS-REP-1 |
| FR-022 | Markdown report when writing enabled | AC-011 | TS-REP-2 |
| FR-023 | Report includes repo metadata | AC-011 | TS-REP-1 |
| FR-024 | Report includes scan metadata | AC-018 | TS-REP-1, TS-SCN-10 |
| FR-025 | Group findings by IAN priority and category | AC-008 | TS-REP-2 |
| FR-026 | Remediation + verification guidance per finding | AC-001 | TS-REP-2 |
| FR-027 | Concise top-priority action list | AC-008 | TS-REP-2 |
| FR-028 | CLI mirrors both / MCP tool-workspace only | AC-011, AC-029, AC-030, AC-031 | TS-REP-5, TS-REP-6 |
| FR-029 | Ticket-ready Markdown for selected findings | AC-008 | TS-REP-3 |
| FR-030 | Triage context standalone | AC-008 | TS-REP-3 |
| FR-031 | Findings remain hypotheses until verified | AC-005 | TS-REP-3 |
| FR-032 | Acceptance criteria in triage output | AC-008 | TS-REP-3 |
| FR-033 | Verification steps in triage output | AC-008 | TS-REP-3 |
| FR-034 | Ticket integration config/env driven | AC-017 | TS-MCP-4 |
| FR-035 | Default provider is `none` | AC-017 | TS-MCP-4 |
| FR-036 | `none` returns Markdown only | AC-017 | TS-MCP-4 |
| FR-037 | Explicit opt-in needed for external issue creation | AC-017 | TS-MCP-4 |
| FR-038 | Supported provider names | AC-017 | TS-MCP-4 |
| FR-039 | External issue refs do not change finding schema | AC-017 | TS-MCP-4 |
| FR-040 | Verify-fix re-runs targeted analysis | AC-009, AC-010 | TS-MCP-5 |
| FR-041 | `resolved: true` only when no matches | AC-009 | TS-MCP-5 |
| FR-042 | Return remaining locations when unresolved | AC-010 | TS-MCP-5 |
| FR-043 | CLI + MCP both support verify | AC-009, AC-010 | TS-MCP-5, TS-CLI-5 |
| FR-044 | Verify scope limited to finding/rule | AC-009 | TS-MCP-5 |
| FR-045 | CLI `scan` command | AC-011, AC-012 | TS-CLI-1, TS-CLI-2 |
| FR-046 | CLI `rules` command | AC-014 | TS-CLI-3 |
| FR-047 | CLI `triage` command | AC-008 | TS-CLI-4 |
| FR-048 | CLI `verify` command | AC-009 | TS-CLI-5 |
| FR-049 | CLI output supports JSON and human formats | AC-008 | TS-CLI-1 |
| FR-050 | `server.get_info` + resource | AC-015, AC-019 | TS-MCP-7, TS-MCP-8 |
| FR-051 | `server.get_health` + resource | AC-019 | TS-MCP-7, TS-MCP-8 |
| FR-052 | `server.get_status` + resource | AC-019 | TS-MCP-7, TS-MCP-8 |
| FR-053 | `repo-audit://server/config` redacted | AC-022 | TS-MCP-8 |
| FR-054 | `repo-audit://adapters` lists loaded adapters | AC-023, AC-025 | TS-MCP-8 |
| FR-055 | `diagnostics.validate_config` | AC-020 | TS-MCP-9 |
| FR-056 | `diagnostics.run_self_check` | AC-021 | TS-MCP-10 |
| FR-057 | `reports.list_reports` | AC-015 | TS-MCP-1 |
| FR-058 | Operational resources return application/json | AC-022, AC-023 | TS-MCP-8 |
| FR-059 | Prompt-injection content tagged with provenance | AC-024 | TS-CLI-6 |
| FR-060 | Local lockfile parsing without network | AC-026 | TS-DEP-1 |
| FR-061 | Opt-in OSV/GHSA enrichment | AC-027 | TS-DEP-2 |
| FR-062 | Dual gating (config + env) for enrichment | AC-026, AC-027 | TS-DEP-1, TS-DEP-2 |
| FR-063 | Lockfile-only findings labelled | AC-026 | TS-DEP-1 |
| FR-064 | Enrichment metadata in report | AC-027, AC-028 | TS-DEP-2, TS-DEP-3 |
| FR-065 | Enrichment transmits only package coords | AC-027 | TS-DEP-4 |

### 19.2 Acceptance Criteria → Test Scenarios

| AC | Test Scenarios |
|---|---|
| AC-001 | TS-SCN-2, TS-SCO-1 |
| AC-002 | TS-SCN-3, TS-SCN-5, TS-SCN-6 |
| AC-003 | TS-SCN-1 |
| AC-004 | TS-SCN-8 |
| AC-005 | TS-SCO-4 |
| AC-006 | TS-SCN-2 (git blame default off) |
| AC-007 | TS-SCN-9 |
| AC-008 | TS-MCP-4, TS-CLI-4 |
| AC-009 | TS-MCP-5, TS-CLI-5 |
| AC-010 | TS-MCP-5 |
| AC-011 | TS-REP-1, TS-REP-2, TS-REP-5 |
| AC-012 | TS-CLI-1 |
| AC-013 | TS-MCP-9 |
| AC-014 | TS-CLI-2 |
| AC-015 | TS-MCP-1..6 |
| AC-016 | TS-MCP-6 |
| AC-017 | TS-MCP-4 |
| AC-018 | TS-SCN-10 |
| AC-019 | TS-MCP-7 |
| AC-020 | TS-MCP-9 |
| AC-021 | TS-MCP-10 |
| AC-022 | TS-MCP-8 |
| AC-023 | TS-MCP-8 |
| AC-024 | TS-CLI-6 |
| AC-025 | TS-MCP-8, TS-SCN-10 |
| AC-026 | TS-DEP-1 |
| AC-027 | TS-DEP-2 |
| AC-028 | TS-DEP-3 |
| AC-029 | TS-REP-5 |
| AC-030 | TS-REP-6 |
| AC-031 | TS-REP-6 |

### 19.3 Coverage Notes

- Every FR is mapped to at least one AC and at least one test scenario.
- Operational support FRs (FR-050..FR-058) share test scenarios because their behaviour is verified by inspecting the same MCP transport and resource surface.
- Phase 2 living-docs FRs and ACs are tracked separately in Section 18 and are intentionally excluded from this MVP traceability matrix.
