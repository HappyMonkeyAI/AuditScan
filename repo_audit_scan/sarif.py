"""SARIF 2.1.0 rendering for AuditScan reports."""
from __future__ import annotations

import json
from typing import Any
from repo_audit_scan.models import Report


def report_to_sarif(report: Report) -> dict[str, Any]:
    rules = {}
    results = []
    for finding in report.findings:
        rules.setdefault(finding.rule_id, {"id": finding.rule_id, "name": finding.rule_title, "shortDescription": {"text": finding.rule_title}})
        level = "error" if finding.severity.value in {"critical", "high"} else ("warning" if finding.severity.value == "medium" else "note")
        for evidence in finding.evidence or [None]:
            result: dict[str, Any] = {"ruleId": finding.rule_id, "level": level, "message": {"text": "Untrusted external-content evidence; review before use."}}
            if evidence:
                result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": evidence.file_path}, "region": {"startLine": evidence.line_number or 1, "startColumn": (evidence.column_number or 0) + 1}}}]
            results.append(result)
    run: dict[str, Any] = {"tool": {"driver": {"name": "repo-audit-scan", "rules": list(rules.values())}}, "results": results}
    if report.assessment:
        run["properties"] = {"assessment": report.assessment.to_dict(), "untrusted_content": True}
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [run]}


def write_sarif(report: Report, path: str) -> None:
    payload = report_to_sarif(report)
    validate_sarif(payload)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")


def validate_sarif(payload: dict[str, Any]) -> None:
    """Validate the required SARIF envelope before publication."""
    if payload.get("version") != "2.1.0" or not isinstance(payload.get("runs"), list) or not payload["runs"]:
        raise ValueError("invalid SARIF 2.1.0 envelope")
    for run in payload["runs"]:
        if not isinstance(run, dict) or not isinstance(run.get("tool", {}).get("driver"), dict):
            raise ValueError("SARIF run is missing tool.driver")
        driver = run["tool"]["driver"]
        if driver.get("name") != "repo-audit-scan" or not isinstance(run.get("results"), list):
            raise ValueError("SARIF driver or results are invalid")
        rule_ids = {rule.get("id") for rule in driver.get("rules", []) if isinstance(rule, dict)}
        for result in run["results"]:
            if result.get("ruleId") not in rule_ids or not isinstance(result.get("message", {}).get("text"), str):
                raise ValueError("SARIF result is not linked to a declared rule")
