# repo-audit-scan — Project Plan

A Python-based MCP server for scanning local repositories for code vulnerabilities,
auth issues, and security misconfigurations. Companion tool to
[repo-security-scan](https://github.com/SPhillips1337/repo-security-scan), which
covers secrets/API keys. This tool covers everything else.

---

## Motivation

`repo-security-scan` detects hardcoded credentials before they leave the repo.
`repo-audit-scan` detects structural and logic vulnerabilities in the code itself —
things like unseeded roles, missing authorization policies, SQL injection patterns,
and insecure configuration — the class of finding that emerges from a code audit
rather than a secret scan.

The `verify_fix` MCP tool is the key differentiator: an agent can call it to confirm
a finding is resolved before writing a PR description, closing the audit workflow loop.

---

## Project Structure

```
repo-audit-scan/
├── mcp_server.py             # FastMCP entry point (same pattern as repo-security-scan)
├── scanner.py                # Standalone CLI scanner (no config required)
├── main.py                   # Full CLI with config/profile support
├── scan.sh                   # Bash wrapper for quick scans
├── install.sh                # Interactive installer (mirrors repo-security-scan)
├── .env.template             # Environment config template
├── .gitignore
├── LICENSE.md
├── README.md
├── AGENTS.md                 # Agent/MCP usage guide
├── src/
│   ├── rules.py              # Rule registry (equivalent of patterns.py)
│   ├── scanner.py            # File traversal and content scanning
│   ├── aggregator.py         # Result aggregation and deduplication
│   └── framework.py          # Framework profile detection (dotnet, node, generic)
├── config/
│   └── schema.yaml           # Config schema reference
├── scripts/
│   └── scheduled_scan.py     # Git-monitoring daemon with alerts
└── scan-reports/             # Output directory for scan reports
```

---

## MCP Tools

Same `fastmcp` pattern as `repo-security-scan`. Five tools:

### `scan_directory(path, framework?, min_severity?)`
Full vulnerability scan of a local directory.
- `path`: absolute path to repo root
- `framework`: `"dotnet"` | `"node"` | `"generic"` (auto-detected if omitted)
- `min_severity`: `"LOW"` | `"MEDIUM"` | `"HIGH"` | `"CRITICAL"` (default `"LOW"`)
- Returns: summary + findings grouped by category and severity

### `scan_for_finding(path, rule_id)`
Check whether a specific rule fires in the given repo.
- `rule_id`: e.g. `"AUTH-002"` (see Rule Registry below)
- Returns: list of matching locations with file, line, and matched snippet
- Use case: confirm a known finding before starting a fix

### `verify_fix(path, rule_id)`
Confirm that a previously-identified finding is no longer present.
- Returns: `{ "resolved": true/false, "remaining_locations": [...] }`
- Use case: call this after applying a fix, before writing the PR description

### `list_rules(framework?)`
Return all rules in the registry, optionally filtered by framework.
- Returns: rule ID, category, severity, description, framework tags

### `get_latest_report()` *(resource: `reports://latest`)*
Retrieve the most recent JSON scan report from `scan-reports/`.

---

## Rule Registry (`src/rules.py`)

Rules follow the same structure as `PATTERN_REGISTRY` in `repo-security-scan`:
`name`, `category`, `severity`, `description`, `regex`, `frameworks[]`.

### AUTH — Authorization & Role Management

| ID | Severity | Description |
|----|----------|-------------|
| AUTH-001 | CRITICAL | `[Authorize(Policy = "X")]` where `X` is not registered in `AddAuthorization` |
| AUTH-002 | CRITICAL | Role name used as string literal instead of `nameof(UserRole.X)` |
| AUTH-003 | HIGH | Authorization policy registered with no matching `RequireRole` call |
| AUTH-004 | HIGH | `[AllowAnonymous]` on a route whose name contains `admin`, `manage`, or `internal` |
| AUTH-005 | MEDIUM | Controller/page with no `[Authorize]` whose name suggests protected content |

### INJ — Injection

| ID | Severity | Description |
|----|----------|-------------|
| INJ-001 | CRITICAL | String interpolation inside SQL (`$"SELECT...{var}"`) |
| INJ-002 | CRITICAL | `ExecuteSqlRaw` / `FromSqlRaw` called with a non-constant string |
| INJ-003 | HIGH | `Process.Start` or `cmd.exe` invoked with a variable argument |
| INJ-004 | HIGH | `Path.Combine` result passed directly to file open without validation |

### CRYPTO — Cryptography & Configuration

| ID | Severity | Description |
|----|----------|-------------|
| CRYPTO-001 | HIGH | `MD5.Create()` or `SHA1.Create()` used in a security context |
| CRYPTO-002 | HIGH | `ValidateLifetime = false` in JWT validation parameters |
| CRYPTO-003 | MEDIUM | HTTP (not HTTPS) URL in `appsettings*.json` or config files |
| CRYPTO-004 | MEDIUM | Hardcoded connection string containing `Password=` or `pwd=` |

### ERR — Error Handling

| ID | Severity | Description |
|----|----------|-------------|
| ERR-001 | HIGH | Empty catch block (`catch { }` or `catch (Exception) { }`) |
| ERR-002 | HIGH | `Exception.StackTrace` or `Exception.ToString()` returned in HTTP response |
| ERR-003 | MEDIUM | `Console.WriteLine(exception)` in production code paths |

### VAL — Input Validation

| ID | Severity | Description |
|----|----------|-------------|
| VAL-001 | HIGH | POST endpoint missing `[ValidateAntiForgeryToken]` |
| VAL-002 | HIGH | `Response.Redirect` called with a user-controlled string |
| VAL-003 | MEDIUM | `ModelState.IsValid` check absent on a controller action with `[HttpPost]` |

### CFG — Secure Configuration (ASP.NET Core)

| ID | Severity | Description |
|----|----------|-------------|
| CFG-001 | HIGH | `app.UseDeveloperExceptionPage()` outside `IsDevelopment()` guard |
| CFG-002 | MEDIUM | `options.RequireHttpsMetadata = false` in production config |
| CFG-003 | MEDIUM | CORS policy using `AllowAnyOrigin()` combined with `AllowCredentials()` |

---

## Framework Profiles (`src/framework.py`)

Auto-detection logic (file extension + presence of project files):

| Profile | Detection signal | Active rule categories |
|---------|-----------------|----------------------|
| `dotnet` | `*.csproj`, `*.cs` present | AUTH, INJ, CRYPTO, ERR, VAL, CFG |
| `node` | `package.json` present | INJ, CRYPTO, ERR, VAL |
| `generic` | fallback | INJ, CRYPTO, ERR |

---

## Severity Levels

Identical to `repo-security-scan` for consistency:

| Level | Meaning |
|-------|---------|
| CRITICAL | Exploitable without authentication on a fresh deployment |
| HIGH | Likely to cause a security incident if triggered |
| MEDIUM | Should be reviewed; may be a false positive depending on context |
| LOW | Informational; best-practice violation |

---

## Relationship to repo-security-scan

These two tools are designed to run together, not replace each other:

```
repo-security-scan    →  finds:  hardcoded secrets, API keys, tokens
repo-audit-scan       →  finds:  auth gaps, injection, misconfig, bad patterns
```

Both share:
- Same Python/fastmcp stack
- Same severity model
- Same `scan-reports/` output convention
- Same `get_latest_report` resource pattern

Consider: a future `repo-scan-all` wrapper MCP that runs both and returns a unified report.

---

## Phase 3 Extension — Adversarial Assurance Loop

After the MVP scan/triage/verify flow, add an adversarial lane where a challenger
agent reviews findings and attempts to invalidate weak fixes.

Proposed post-MVP sequence:

```text
scan -> triage -> fix -> verify_fix -> adversarial_challenge -> consensus -> close
```

Planned capabilities:
- `adversarial.review_finding(report_id, finding_id)`
- `adversarial.challenge_fix(report_id, finding_id, patch_ref?)`
- `adversarial.compare_verdicts(report_id)`
- Assurance artifacts (`assurance.md` / `assurance.json`) with support/challenge outcomes,
  confidence adjustments, and human-review triggers for contested critical findings.

---

## Agent Workflow Integration

With both MCPs connected, an agent can run the full audit-to-fix loop autonomously:

```
1. scan_directory(path)                    → identify all findings
2. scan_for_finding(path, "AUTH-001")      → confirm specific finding exists
3. [apply fix]
4. verify_fix(path, "AUTH-001")            → confirm resolved
5. [write PR description]
6. [create Confluence writeup]
```

This is the workflow captured in the `audit-finding-fix` Cowork skill and
`audit-finding-fix-prompt.md`.

---

## Bootstrap Checklist

When starting this project:

- [ ] Create new repo `repo-audit-scan` on GitHub (stephenzphillips)
- [ ] Copy `mcp_server.py`, `install.sh`, `.env.template`, `.gitignore` structure from `repo-security-scan` as scaffold
- [ ] Write `src/rules.py` — start with AUTH and INJ categories (highest value)
- [ ] Write `src/scanner.py` — adapt from `repo-security-scan/src/scanner.py`; same file-walk logic, swap pattern registry
- [ ] Write `src/framework.py` — auto-detect dotnet/node/generic
- [ ] Write `src/aggregator.py` — can be copied almost verbatim from `repo-security-scan`
- [ ] Add `verify_fix` and `scan_for_finding` tools to `mcp_server.py`
- [ ] Write `AGENTS.md` documenting the 5 MCP tools and example agent prompts
- [ ] Write `README.md` mirroring the structure of `repo-security-scan/README.md`
- [ ] Test with `spark.ai.aaa` event repo — should fire AUTH-001 (unseeded TenderManager role) on an unpatched checkout

---

## Reference

- Existing secrets scanner: https://github.com/SPhillips1337/repo-security-scan
- spark.ai.aaa audit findings that inspired the AUTH rule set: SEC-CRIT-3 (TenderManager role never seeded)
- Audit workflow prompt: `audit-finding-fix-prompt.md` (in this outputs folder)
- Cowork skill: `audit-finding-fix.skill` (in this outputs folder)
