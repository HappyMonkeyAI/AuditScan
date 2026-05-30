---
type: episodic
tags: [dogfooding, false-positive, docker-001, precision, rules]
created: 2026-05-30
related: [.agents/memories/patterns_and_lessons.md]
blast_radius: [rules]
confidence: high
---

# Dogfooding fix — docker-001 false positive

## Trigger
First real-repo run (github.com/SPhillips1337/LLM-Codex-Reference-Vault, 26
Python scripts). Scan completed end-to-end: 34 scanned / 28 skipped, languages
[python, markdown], framework pip, IAN scoring applied.

## Finding
1 CRITICAL finding — `docker-001` "Secrets in Dockerfile" — on
`DEVTO_API_KEY = os.getenv("DEVTO_APIKEY")` in `ingest_devto.py`. False
positive: secure env read, no hardcoded secret. Repo has zero real hardcoded
secrets (grep-confirmed). So: 0 true positives, 1 false positive.

## Root cause
`docker-001` pattern `ENV.*PASSWORD|SECRET|KEY` → precedence
`(ENV.*PASSWORD)|SECRET|KEY` → matches bare substring `KEY` anywhere. Plus the
rule ran on a `.py` file because `supports_rule` is default-allow and "docker"
is not in PythonAdapter's exclusion markers.

## Fix
Pattern → `(?<![A-Za-z])(?:ENV|ARG)\s+[A-Z_]*(?:PASSWORD|SECRET|KEY|TOKEN)[A-Z_]*\s*[= ]\s*(?!\$)\S`
(Dockerfile ENV/ARG secret assignment to a literal; excludes `${...}` and bare
`ARG NAME`). Description sharpened. Regression test added
(`test_docker_secret_rule_does_not_flag_env_var_reads`). Re-scan of the repo →
0 findings. Full suite 134 passed; vulnerable-repo true positives unaffected.

## Follow-up (logged, not done)
Move `supports_rule` to default-deny so stack-tagged rules only run on their
stack's files — the systemic cause. See L-003.
