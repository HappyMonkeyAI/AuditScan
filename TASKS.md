# TASKS.md — repo-audit-scan MVP Build Plan

**Status:** Ready for execution
**Source spec:** [`SPEC.md`](./SPEC.md) v1.0
**Operating protocol:** [`AGENTS.md`](./AGENTS.md)
**Memory:** [`.agents/memories/`](./.agents/memories/)
**Last updated:** 2026-05-26

This file slices the MVP scope (per `SPEC.md` §17 Definition of Done) into
mid-grain work-packages. Each task is roughly a day of focused work and
maps to a coherent PR. Phase 1.5 (C#/.NET and Docker adapters reaching
MVP-quality coverage) and Phase 2 (Living Documentation Feedback Loop) are
tracked separately in §3 Roadmap.

---

## How to Use This File

Each task is structured as:

```text
### T-### — <subject>
- [ ] Status checkbox
**Track:** Which parallel track this belongs to (A..M)
**Depends on:** Other T-### IDs that must be completed first
**Satisfies:** FR-### and AC-### IDs from SPEC.md
**Description:** What the task delivers
**Done when:** The verification bar for this task
```

**Sequencing rule.** A task may only be marked `in progress` once all
tasks in its **Depends on** list are complete. Tasks within the same
track are usually sequential; tasks in different tracks can run in
parallel.

**Verdict discipline.** Each task ends with a Trident Cross-Audit (see
`AGENTS.md` §12). A task is **done** only when both auditors return
APPROVE or APPROVE-WITH-CONDITIONS (with conditions satisfied), and the
PASS / FAIL / UNVERIFIABLE matrix for the listed ACs is filed in the PR.

---

## 1. Critical Path Overview

```
                          ┌── T-005 (IAN scoring) ──┐
                          │                         │
T-001 ── T-002 ── T-003 ──┼── T-004 (universal)     ├── T-011 (reports) ── T-012 (triage)
  (scaffold)  (inventory) │                         │
                          │   ┌── T-007 (PHP/WP) ─┐ │
                          │   ├── T-008 (Python) ─┤ │
                          ├── T-006 (adapter ────┼── T-013 (CLI) ───────────────┐
                          │   │   contract)      │ │                            │
                          │   ├── T-009 (JS/TS) ─┤ │   T-014 (MCP) ── T-015 (ops surface)
                          │   └── T-010 (CI/CD) ─┘ │     │
                          │                         │   T-017 (verify_fix)
                          └── T-016 (dep enrichment)
                              T-018 (safety guards)  ──── cross-cut
                              T-019 / T-020 (tests)  ──── cross-cut
                                                          T-021 (docs)
```

Tracks:
- **A — Foundation:** T-001, T-002
- **B — Rule engine:** T-003, T-004
- **C — Scoring:** T-005
- **D — Adapters:** T-006, T-007, T-008, T-009, T-010
- **E — Reporting:** T-011, T-012
- **F — Entrypoints:** T-013 (CLI), T-014 (MCP)
- **G — Operational:** T-015
- **H — Enrichment:** T-016
- **I — Verification:** T-017
- **J — Safety (cross-cut):** T-018
- **K — Tests (cross-cut):** T-019, T-020
- **L — Docs:** T-021

---

## 2. MVP Tasks (21 tasks)

### T-001 — Project scaffolding, models, and error/log primitives
- [ ] Status
**Track:** A | **Depends on:** (none) | **Status:** 🔴 Pending

### T-002 — Filesystem walker, repository inventory, Git metadata  
- [ ] Status
**Track:** A | **Depends on:** T-001 | **Status:** 🔴 Pending

### T-003 — Rule registry, Rule protocol, dedupe, manual-confirmation
- [ ] Status
**Track:** B | **Depends on:** T-001 | **Status:** 🔴 Pending

### T-004 — Universal rule set (representative coverage across categories)
- [ ] Status
**Track:** B | **Depends on:** T-003 | **Status:** 🔴 Pending

### T-005 — IAN scoring model, compromise mode, chain detection
- [ ] Status
**Track:** C | **Depends on:** T-001 | **Status:** 🔴 Pending

### T-006 — Adapter contract, loader, and inventory resource
- [ ] Status
**Track:** D | **Depends on:** T-002, T-003 | **Status:** 🔴 Pending

### T-007 — PHP / WordPress adapter
- [ ] Status
**Track:** D | **Depends on:** T-006 | **Status:** 🔴 Pending

### T-008 — Python adapter
- [ ] Status
**Track:** D | **Depends on:** T-006 | **Status:** 🔴 Pending

### T-009 — JavaScript / TypeScript adapter
- [ ] Status
**Track:** D | **Depends on:** T-006 | **Status:** 🔴 Pending

### T-010 — CI/CD adapter
- [ ] Status
**Track:** D | **Depends on:** T-006 | **Status:** 🔴 Pending

### T-011 — JSON and Markdown report writers
- [x] Status
**Track:** E | **Depends on:** T-003, T-005 | **Status:** COMPLETE

### T-012 — Triage Markdown writer (ticket-ready output)
- [x] Status
**Track:** E | **Depends on:** T-005, T-011 | **Status:** COMPLETE

### T-013 — CLI (scan / rules / triage / verify), output formats, default mirroring
- [x] Status
**Track:** F | **Depends on:** T-003, T-005, T-011, T-012 | **Status:** COMPLETE

### T-014 — MCP server, core tools, default tool-workspace-only mirroring
- [ ] Status
**Track:** F | **Depends on:** T-003, T-005, T-011, T-012 | **Status:** 🔴 Pending

### T-015 — Operational support: get_info / get_health / get_status, diagnostics, resources
- [ ] Status
**Track:** G | **Depends on:** T-014, T-006 | **Status:** 🔴 Pending

### T-016 — Dependency enrichment (lockfile-only + opt-in OSV/GHSA)
- [ ] Status
**Track:** H | **Depends on:** T-002, T-003, T-011 | **Status:** 🔴 Pending

### T-017 — verify_fix (CLI + MCP parity)
- [ ] Status
**Track:** I | **Depends on:** T-003, T-014 | **Status:** 🔴 Pending

### T-018 — Safety: redaction, untrusted-content provenance, path containment
- [ ] Status
**Track:** J | **Depends on:** T-001, T-011, T-014 | **Status:** 🔴 Pending

### T-019 — Test scaffolding and fixture repositories
- [ ] Status
**Track:** K | **Depends on:** T-001 | **Status:** 🔴 Pending

### T-020 — Test suites (rules, scoring, reports, CLI, MCP, diagnostics, dep, safety)
- [ ] Status
**Track:** K | **Depends on:** each respective implementation | **Status:** 🔴 Pending

### T-021 — Documentation pass (README, AGENTS hygiene)
- [ ] Status
**Track:** L | **Depends on:** T-013, T-014, T-015 | **Status:** 🔴 Pending

---

## 3. Roadmap (Phase 1.5 + Phase 2 — out of MVP scope)

### Phase 1.5 — C#/.NET and Docker adapter completion
- [ ] **R-001 — C#/.NET adapter (full MVP coverage)**
- [ ] **R-002 — Docker adapter (full MVP coverage)**

### Phase 2 — Living Documentation Feedback Loop
- [ ] **R-010 — docs.review_living_docs**
- [ ] **R-011 — docs.propose_living_doc_updates**
- [ ] **R-012 — docs.apply_living_doc_updates**
- [ ] **R-013 — docs.verify_living_docs**
- [ ] **R-014 — Phase 2 ACs**

---

## 4. Conventions

- **Branching:** One branch per task: `agent/T-### -<slug>`
- **Commit hygiene:** Conventional Commits per `AGENTS.md` §8
- **Verdict on PR:** PR description includes PASS/FAIL/UNVERIFIABLE matrix
- **LTM:** Archive implementation_plan.md under `.agents/memories/history/`
- **Scope drift:** Create follow-up T-### rather than widening scope

---

*Maximise momentum. Minimise gravity.*
