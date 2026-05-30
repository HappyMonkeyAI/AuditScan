---
type: episodic
tags: [walkthrough, documentation, readme, architecture, T-021]
created: 2026-05-30
related: [README.md, ARCHITECTURE.md, TROUBLESHOOTING.md]
blast_radius: [docs]
confidence: high
---

# T-021 — Documentation pass (walkthrough)

## What was written
- `README.md` refreshed: 6 adapters, 124 rules / 25 categories, accurate CLI
  (scan/rules/triage/verify + flags incl. `--rules`, enrichment double-gating),
  12 MCP tools, IAN scoring, mirroring defaults, safety model, project tree.
- `ARCHITECTURE.md` (new): pipeline diagram, component table, the 5-member
  adapter contract, data model (Evidence→RuleResult→Finding→Report), CLI-vs-MCP
  mirroring rationale, safety model, known limitations.
- `TROUBLESHOOTING.md` (new): install/venv, no-findings triage path, CI/CD path
  matching, enrichment env gating, verify/path-containment, MCP mirroring,
  report locations.

## Verification
Every factual claim cross-checked against source (not assumed): CLI argparse
subcommands/flags, MCP tool registration names, rule count (124) and category
count (25) from the fixture, dependency lockfile parsers (requirements.txt,
package-lock.json, composer.lock), IAN weights 0.40/0.35/0.25, 10MB inventory
cap, Java/C# seed rules present.

## Status
20/21 MVP tasks complete. Only T-019 (formalize fixture repositories) remains;
per-adapter fixtures already exist (php_wordpress_ajax_no_capability,
cicd_github_actions, python_app, js_app).

## Gotcha
Bash JSON-parse of project.json reported a phantom error from the stale mount
(L-002); the real file (Read tool) is valid through its closing brace.
