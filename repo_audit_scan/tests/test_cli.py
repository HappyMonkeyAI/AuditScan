"""CLI command tests for scan, rules, triage, and verify."""

from __future__ import annotations

import json
from pathlib import Path

from repo_audit_scan.cli import main
from repo_audit_scan.models import (
    Confidence,
    CompromiseMode,
    Evidence,
    Finding,
    Report,
    ScanMetadata,
    Severity,
)
from repo_audit_scan.reporting import JSONReportWriter


def _make_cli_report(repo_path: Path) -> Report:
    metadata = ScanMetadata(
        schema_version="1.0",
        tool_version="0.1.0",
        scan_timestamp="2026-05-27T16:00:00Z",
        repository_path=str(repo_path),
        scanned_files_count=1,
        skipped_files_count=0,
        detected_languages=["python"],
    )
    finding = Finding(
        finding_id="finding-0001",
        rule_id="py-001",
        rule_title="Python hardcoded secret",
        category="secrets",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        evidence=[
            Evidence(
                file_path="app.py",
                line_number=1,
                column_number=0,
                code_snippet='api_key = "sk-real-secret"',
                context="test fixture",
            )
        ],
        remediation_guidance="Use environment variables.",
        ian_score=0.9,
        compromise_mode=CompromiseMode.COVER,
        affected_files_count=1,
    )
    return Report(
        report_id="cli-report-001",
        metadata=metadata,
        findings=[finding],
        summary="CLI test report",
    )


def test_rules_command_outputs_json(capsys):
    """Rules command should list rules in JSON."""
    code = main(["rules", "--format", "json"])
    out = capsys.readouterr().out
    payload = json.loads(out)

    assert code == 0
    assert payload["count"] > 0
    assert any(item["rule_id"] == "js-002" for item in payload["rules"])


def test_triage_command_writes_triage_and_review(tmp_path, capsys):
    """Triage command should write triage.md and review.md from a report."""
    repo = tmp_path / "repo"
    repo.mkdir()
    report_path = tmp_path / "report.json"
    report = _make_cli_report(repo)
    report_path.write_text(JSONReportWriter().to_json(report), encoding="utf-8")

    code = main(
        [
            "triage",
            str(report_path),
            "--limit",
            "1",
            "--output-dir",
            str(tmp_path / "triage-out"),
            "--pilot-name",
            "cli-pilot",
            "--review-note",
            "important scan lesson",
        ]
    )
    out = capsys.readouterr().out
    payload = json.loads(out)

    assert code == 0
    assert Path(payload["triage"]).exists()
    assert Path(payload["review"]).exists()
    assert "Ticket 1" in Path(payload["triage"]).read_text(encoding="utf-8")
    review_text = Path(payload["review"]).read_text(encoding="utf-8")
    assert "# Scan Review: cli-pilot" in review_text
    assert "important scan lesson" in review_text


def test_verify_command_returns_resolved_true_after_fix(tmp_path, capsys):
    """Verify command should return resolved true when evidence no longer matches."""
    repo = tmp_path / "repo"
    repo.mkdir()
    app_py = repo / "app.py"
    app_py.write_text('value = "safe"\n', encoding="utf-8")

    report_path = tmp_path / "report.json"
    report = _make_cli_report(repo)
    report_path.write_text(JSONReportWriter().to_json(report), encoding="utf-8")

    code = main(["verify", str(report_path), "finding-0001"])
    out = capsys.readouterr().out
    payload = json.loads(out)

    assert code == 0
    assert payload["finding_id"] == "finding-0001"
    assert payload["resolved"] is True
    assert payload["remaining_locations"] == []


def test_scan_command_supports_json_without_writes(tmp_path, capsys):
    """Scan command should run without writing report files when disabled."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text('api_key = "sk-test-1234"\n', encoding="utf-8")

    code = main(["scan", str(repo), "--format", "json", "--no-write-reports"])
    out = capsys.readouterr().out
    payload = json.loads(out)

    assert code == 0
    assert payload["repository_path"] == str(repo.resolve())
    assert "report_paths" not in payload
