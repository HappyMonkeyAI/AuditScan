---
type: episodic
tags: [walkthrough, adapter, python, javascript, typescript, rules, T-008, T-009]
created: 2026-05-30
related: [.agents/memories/patterns_and_lessons.md]
blast_radius: [rules, adapters]
confidence: high
---

# T-008 / T-009 — Deepened Python & JS/TS adapters (walkthrough)

## What was built
No new adapter code — the Python and JavaScript adapters already exist and
delegate to the shared regex scanner. This deepens their *rule coverage* to
the SPEC detector lists by adding 12 rules to `sample_rules.json` (-> 124).

Python (py-005..py-010): unsafe deserialization (`pickle.loads`,
`yaml.load` w/o SafeLoader), command injection (`subprocess shell=True`,
`os.system`), `eval`/`exec`, debug mode, permissive CORS (`allow_origins=["*"]`),
path traversal (`open(... request.*)`, single-line).

JS/TS (js-004..js-009): `child_process.exec`, SSRF (`axios`/`fetch` + `req.*`),
`eval`, prototype pollution (`__proto__`), token in `localStorage`, React
`dangerouslySetInnerHTML=`.

## Cross-adapter scoping
Each rule description names its language ("Python:" / "JavaScript/TypeScript:")
so the marker-based `supports_rule` exclusion routes each rule to the right
adapter only. Verified both directions.

## Fixtures / tests
`tests/fixtures/python_app/{vulnerable,safe}.py`,
`tests/fixtures/js_app/{vulnerable,safe}.js`; `TestPythonAdapterDepth` and
`TestJsAdapterDepth` assert all new detectors fire on vulnerable, none on safe
(safe is clean of ALL py-/js- rules), plus cross-adapter exclusion.

## Audit outcome
Both auditors APPROVE-WITH-CONDITIONS. All 12 patterns confirmed linear (no
ReDoS). `py-007 \beval(` correctly does NOT match `literal_eval(` (no word
boundary inside the identifier). Fixes applied: `js-009` changed from bare
substring to `dangerouslySetInnerHTML\s*=` (was matching a prose comment);
`py-010` constrained to a single line (`[^)\n]*`). Documented known FN gaps
(os.popen, `request.` vs `req.`, `constructor.prototype`, spawn shell:true) and
the pre-existing no-regex-timeout / double-copy memory concern as follow-ups.

## Verification
14 pattern-smoke + 8 standalone fixture checks; 129 pass across the rest of the
suite. Real `pytest -q` ~130. (In-sandbox pytest on edited files unreliable —
L-002; validated via /tmp reconstruction.)

## MVP status
All four MVP adapters now implemented and deepened. Remaining MVP: T-019
(formalize fixtures) and T-021 (docs).
