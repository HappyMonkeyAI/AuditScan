"""Bounded integration with the optional repo-security-scan engine.

The external scanner is treated as an untrusted subprocess. Its output is capped,
never used as a command, and only structured JSON findings are adapted.
"""
from __future__ import annotations

import json
import os
import shlex
import subprocess
import re
from pathlib import Path
from typing import Any

from repo_audit_scan.models import Confidence, Evidence, RuleResult, Severity

_MAX_OUTPUT = 1_000_000
_TIMEOUT_SECONDS = 30


def run_repo_security_scan(repo_path: Path) -> tuple[list[RuleResult], dict[str, Any]]:
    """Run configured scanner, returning findings and explicit engine metadata."""
    command = os.environ.get("REPO_SECURITY_SCAN_COMMAND", "").strip()
    if not command:
        return [], {"status": "unavailable", "detail": "REPO_SECURITY_SCAN_COMMAND is not configured"}
    argv = shlex.split(command, posix=False)
    argv.append(str(repo_path))
    try:
        completed = subprocess.run(
            argv,
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_SECONDS,
            check=False,
            env={"PATH": os.environ.get("PATH", "")},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [], {"status": "failed", "detail": type(exc).__name__}
    raw = completed.stdout[:_MAX_OUTPUT]
    try:
        payload = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        match = re.search(r"Scan complete:\s+(\d+) unique finding", raw)
        if match:
            count = int(match.group(1))
            results = [RuleResult(
                rule_id="external-secret-scan",
                rule_title="External secret scanner finding",
                category="secrets",
                severity=Severity.CRITICAL if completed.returncode == 1 else Severity.HIGH,
                confidence=Confidence.MEDIUM,
                evidence=[Evidence(file_path="[external-scanner]", code_snippet="[REDACTED]", context="untrusted scanner summary")],
                remediation_guidance="Review the external scanner report and rotate any exposed credentials.",
                manual_confirmation_required=True,
            ) for _ in range(min(count, 100))]
            return results, {"status": "completed", "detail": f"text output; {count} findings"}
        return [], {"status": "failed", "detail": "scanner returned unrecognized output"}
    results: list[RuleResult] = []
    for item in payload.get("findings", []) if isinstance(payload, dict) else []:
        if not isinstance(item, dict):
            continue
        path = str(item.get("file", "[scanner]"))[:500]
        snippet = "[REDACTED]" if item.get("secret") or item.get("value") else str(item.get("message", "secret finding"))[:500]
        results.append(RuleResult(
            rule_id="external-secret-scan",
            rule_title="External secret scanner finding",
            category="secrets",
            severity=Severity(str(item.get("severity", "high")).lower()) if str(item.get("severity", "high")).lower() in {s.value for s in Severity} else Severity.HIGH,
            confidence=Confidence.HIGH,
            evidence=[Evidence(file_path=path, line_number=item.get("line"), code_snippet=snippet, context="untrusted external scanner output")],
            remediation_guidance="Remove or rotate the exposed secret; verify the redacted finding manually.",
            manual_confirmation_required=True,
        ))
    return results, {"status": "completed" if completed.returncode == 0 else "completed", "detail": f"exit={completed.returncode}"}
