---
type: procedural
tags: [patterns, lessons, postmortems]
created: 2026-05-26
related: []
blast_radius: [all]
confidence: high
---

# Patterns & Lessons

Procedural memory for this project. Contains two streams:

1. **Patterns that worked** — repeatable approaches we want future sessions
   to reach for first.
2. **"Never again" lessons** — failures and the corrective rule that came
   out of them.

Both streams are **synthesised, not appended**. When a new entry would
duplicate an existing one, fold it in and update the abstraction. Memory is
context-independent: an entry should read correctly six months from now
without surrounding chatter.

---

## Patterns

### P-001 — Spec-driven, AGENTS-driven loop

When kicking off implementation work, Claude reads `SPEC.md` and `AGENTS.md`
before writing any code. The spec is the contract; AGENTS.md is the
operating rules. Plans and PRs that deviate from either must call out the
deviation explicitly.

**Source:** AI Accelerator Day 1 workflow.
**Confirmed on:** N/A yet — bootstrapped from spec, not yet exercised.

---

## "Never Again" Lessons

*(Empty — this project has not yet accumulated post-mortems. Add the
first entry the first time a failed approach costs more than 15 minutes.)*

---

## How to Add an Entry

1. Decide which stream it belongs in (Pattern or Lesson).
2. Search existing entries for the same idea. If one exists, **edit it**,
   don't append. Bump its date.
3. Keep entries terse. Two paragraphs maximum. No play-by-play.
4. Tag the relevant memory file in the frontmatter `related` list so the
   pre-task enrichment step can pull this in alongside the related context.
