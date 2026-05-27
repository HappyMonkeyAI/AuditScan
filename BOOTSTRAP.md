# BOOTSTRAP.md — Long-Term Memory Bootstrap Workflow

**Role:** You are the Knowledge Architect for this repository.
**Objective:** Bootstrap (or refresh) the Long-Term Memory system under
`.agents/memories/` by mining the spec, the plan, the brief, the codebase,
and prior AI conversation history, then extracting high-value architectural
insights, patterns, and lessons.

This workflow is adapted from the Anti-Gravity `BOOTSTRAP.md` and tailored
for Claude running inside Cowork mode / Claude Code / Claude Agent SDK. See
`AGENTS.md` for the operating protocol that governs this work.

---

## When to Run This

Run the bootstrap workflow when:

- The `.agents/memories/` directories are empty or near-empty (current
  state of this project as of 2026-05-26).
- The LTM has gone stale: spec or code have moved significantly past what
  the memory says.
- A new agent (or a new session with no continuity) is taking over.

Do **not** run this on every session. It's an explicit, deliberate action.

---

## Current State Snapshot (2026-05-26)

This project starts almost empty. The bootstrap inputs available right now
are:

- `SPEC.md` — the implementation-ready specification (v1.0).
- `PLAN.md` — the earlier project plan (.NET-leaning; superseded by the
  polyglot direction in SPEC §11 / Resolved Decisions).
- `BRIEF.md` — the original ask.
- This file (`BOOTSTRAP.md`) and `AGENTS.md`.
- **No application source code yet.** No commits to mine. No test runs.
  No prior real bugs.

So the first bootstrap pass will be **light**: a few architectural
decisions seeded from `SPEC.md`'s Resolved Decisions block, a single
codebase insight stub (intent / scope / shape), and an empty pattern log.
That is correct. Do not over-fabricate.

A meaningful second bootstrap pass will be possible after the first
implementation slice lands.

---

## Execution Instructions

### 1. Grounding (Sanity)

Before mining anything, read in this order:

1. `AGENTS.md` — the operating protocol.
2. `SPEC.md` — what we're building and why.
3. `PLAN.md` — the original plan (note where it diverges from SPEC).
4. `BRIEF.md` — the original ask.

If you find inconsistencies between these, capture them as open questions
to surface back to the user before continuing.

### 2. Context Mining

Scan available sources to identify:

- **Major modules and surfaces.** What units of work does the spec
  decompose into? (For this project: the universal rule engine, stack
  adapters, IAN scoring, report writer, MCP surface, CLI, operational
  support tools.)
- **Critical decisions.** What's been decided and *why*? Look for things
  marked as resolved, especially in `SPEC.md` §1 Resolved Decisions.
- **Recurring patterns.** Code structures, integration strategies, or
  architectural moves repeated across modules.
- **Failure modes.** Anything explicitly called out as "do not do X". If
  there's no real history yet, mine the Non-goals section for inverse
  patterns.

Once code exists, also mine:

- **Conversation logs** for design decisions made mid-build.
- **Commit history** for fixes that landed without a paper trail.
- **CI / test failure history** for recurring breakage points.

### 3. Information Synthesis

Categorise the mined data into the schema defined in `AGENTS.md` §2.
Each output file MUST include YAML frontmatter (see the templates).

#### A. Codebase Insights → `.agents/memories/codebase_insights/`

Markdown files for major modules / surfaces. Focus on **hidden
knowledge**: *Why does X exist? What are the non-obvious dependencies?
What's the trap door if someone refactors this naively?*

Template: `.agents/memories/templates/codebase_insight_template.md`.

For the current state, a single high-level insight describing the overall
audit pipeline (inventory → universal pass → adapter pass → chain →
triage/verify) is the right shape. Per-module insights wait until those
modules exist.

#### B. Architectural Decisions → `.agents/memories/architectural_decisions/`

One markdown file per major decision. Include status (Proposed / Active /
Superseded / Deprecated) and context. **Initial seed list** drawn from
`SPEC.md` Resolved Decisions:

1. **ADR-01** — Universal audit core + stack adapters (rather than
   .NET-first or Node-first).
2. **ADR-02** — MVP adapter cross-section: PHP/WordPress, Python, JS/TS,
   CI/CD. C#/.NET and Docker adapters loadable but not MVP-complete.
3. **ADR-03** — Dependency vulnerability enrichment: local lockfile by
   default, opt-in OSV/GHSA when both config and env agree.
4. **ADR-04** — Report mirroring defaults differ by entry point: CLI
   mirrors both destinations, MCP defaults to tool-workspace-only.
5. **ADR-05** — Ticket integration defaults to `none`; external issue
   creation requires explicit opt-in.
6. **ADR-06** — Git blame attribution is opt-in only; commit + file +
   line evidence is sufficient by default.
7. **ADR-07** — Living Documentation Feedback Loop is Phase 2, not MVP.

Template: `.agents/memories/templates/architectural_decision_template.md`.

#### C. Patterns & Lessons → `.agents/memories/patterns_and_lessons.md`

Append **only** if there's real evidence. Possible initial entries from
the spec and conversation so far:

- **Pattern P-001** — Spec-driven, AGENTS-driven loop. (Already seeded.)
- **Pattern P-002** — Findings are hypotheses until verified in source
  (from `SPEC.md` FR-031). Worth promoting to a general agent rule for
  this project: never present an audit hit as confirmed without source
  evidence.

No "Never Again" lessons yet — this project has not accumulated
post-mortems.

#### D. Handoff (Optional)

If the bootstrap run itself spans multiple turns, write a handoff at
`.agents/memories/history/handoffs/YYYYMMDD_HHMMSS_handoff.md` so the
next session can resume cleanly. Use
`.agents/memories/templates/handoff_template.md`.

### 4. Verification & Commitment

- Ground every entry in something specific from the spec, plan, brief, or
  code. If you can't cite a source, don't write it.
- Surface the proposed memory tree (file list + one-line summary per
  file) to the user **before** committing it. No silent rewrites.
- Once approved, save the files and follow the commit protocol in
  `AGENTS.md` §8 (propose-and-wait — no auto-commit).

---

## Output Shape

A complete first bootstrap pass for this repository produces approximately:

```text
.agents/memories/
├── codebase_insights/
│   └── 01_audit_pipeline_overview.md       # one high-level insight
├── architectural_decisions/
│   ├── ADR-001-universal-core-and-adapters.md
│   ├── ADR-002-mvp-adapter-coverage.md
│   ├── ADR-003-dependency-enrichment.md
│   ├── ADR-004-report-mirroring-defaults.md
│   ├── ADR-005-ticket-integration-default.md
│   ├── ADR-006-git-blame-opt-in.md
│   └── ADR-007-living-docs-feedback-phase2.md
├── patterns_and_lessons.md                  # already seeded; refine
└── history/                                 # remains empty until real work lands
```

Each file is short, dense, and self-contained — a fresh agent should be
able to read any one of them and act on it without reading the spec.

---

## Anti-Patterns to Avoid

- **Padding.** Do not fabricate insights for modules that don't exist.
- **Restating the spec.** Memory is for the *why* and the trap doors, not
  a copy of `SPEC.md`.
- **Append-only thinking.** Patterns and lessons are synthesised. New
  evidence updates the existing entry; it doesn't add a new one.
- **Untagged entries.** Every memory file MUST include the YAML
  frontmatter from `AGENTS.md` §2.
- **Silent writes.** Surface the proposed tree before saving. The user
  approves the shape, not just the words.

---

**Prime Directive:** Eliminate the need for future agents to relearn what
we've already solved. Maximise momentum. Minimise gravity.
