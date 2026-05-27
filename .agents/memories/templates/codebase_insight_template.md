---
type: semantic
tags: [module-name, language, framework]
created: YYYY-MM-DD
related: []
blast_radius: []
confidence: high | medium | low
---

# Codebase Insight — {module-or-area-name}

## Purpose

What this module does, in two or three sentences. Avoid restating the source.

## Why It Exists

The "why" behind the code: what problem it solves, what alternatives were
rejected, what constraint forced the current shape.

## Key Entry Points

- `path/to/file.py::function_name` — {role}
- `path/to/file.py::ClassName` — {role}

## Non-obvious Dependencies

What this module relies on that isn't visible at the call site (env vars,
implicit ordering, side effects on other modules, hot config reloads, etc.).

## Gotchas

- {gotcha 1}
- {gotcha 2}

## When to Update This Memory

Conditions that mean this insight has gone stale: API rewrite, contract
change, dependency swap. Update when those happen; do not append.
