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


def test_external_repo_profile_returns_blocked_policy_for_hostile_fixture(capsys):
    fixture = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "external_content" / "hostile_repo"
    code = main(["scan", str(fixture), "--profile", "external_repo", "--format", "json", "--no-write-reports"])
    payload = json.loads(capsys.readouterr().out)

    assert code == 0
    assert payload["assessment"]["profile"] == "external_repo"
    assert payload["assessment"]["disposition"] == "block"
    assert payload["assessment"]["policy"] == {
        "read_source": True,
        "install": False,
        "execute": False,
        "register_mcp": False,
        "write_memory": False,
    }


def test_external_repo_profile_allows_benign_threejs_fixture(capsys):
    fixture = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "external_content" / "benign_threejs_repo"
    code = main(["scan", str(fixture), "--profile", "external_repo", "--format", "json", "--no-write-reports"])
    payload = json.loads(capsys.readouterr().out)

    assert code == 0
    assert payload["assessment"]["disposition"] == "allow_review"


def test_scan_command_enrichment_flag_is_fail_open(tmp_path, capsys, monkeypatch):
    """Dependency enrichment flag should not fail scan when network enrichment errors."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("requests==2.20.0\n", encoding="utf-8")
    monkeypatch.setenv("REPO_AUDIT_DEP_ENRICHMENT", "true")

    code = main(["scan", str(repo), "--format", "json", "--no-write-reports", "--enrich-dependencies"])
    out = capsys.readouterr().out
    payload = json.loads(out)

    assert code == 0
    assert payload["findings"] >= 1


def test_verify_dependency_finding_uses_snippet_fallback(tmp_path, capsys):
    """Verify should remain unresolved for lockfile findings when snippet is still present."""
    repo = tmp_path / "repo"
    repo.mkdir()
    req = repo / "requirements.txt"
    req.write_text("requests==2.20.0\n", encoding="utf-8")

    metadata = ScanMetadata(
        schema_version="1.0",
        tool_version="0.1.0",
        scan_timestamp="2026-05-28T00:00:00Z",
        repository_path=str(repo),
        scanned_files_count=1,
        skipped_files_count=0,
    )
    finding = Finding(
        finding_id="finding-dep-001",
        rule_id="general-001",
        rule_title="Known vulnerable dependency",
        category="dependency",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        evidence=[Evidence(file_path="requirements.txt", line_number=1, code_snippet="requests==2.20.0")],
        remediation_guidance="Upgrade requests.",
    )
    report = Report(report_id="dep-report-001", metadata=metadata, findings=[finding], summary="dep test")
    report_path = tmp_path / "dep-report.json"
    report_path.write_text(JSONReportWriter().to_json(report), encoding="utf-8")

    unresolved = main(["verify", str(report_path), "finding-dep-001"])
    unresolved_payload = json.loads(capsys.readouterr().out)
    assert unresolved == 0
    assert unresolved_payload["resolved"] is False
    assert unresolved_payload["remaining_locations"] == ["requirements.txt:1"]

    req.write_text("requests==2.32.0\n", encoding="utf-8")
    resolved = main(["verify", str(report_path), "finding-dep-001"])
    resolved_payload = json.loads(capsys.readouterr().out)
    assert resolved == 0
    assert resolved_payload["resolved"] is True


def test_verify_blocks_path_traversal_in_evidence(tmp_path, capsys):
    """Verify must block evidence paths that escape repository root."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "safe.py").write_text("value = 1\n", encoding="utf-8")

    metadata = ScanMetadata(
        schema_version="1.0",
        tool_version="0.1.0",
        scan_timestamp="2026-05-28T00:00:00Z",
        repository_path=str(repo),
        scanned_files_count=1,
        skipped_files_count=0,
    )
    finding = Finding(
        finding_id="finding-path-001",
        rule_id="py-001",
        rule_title="Path traversal verify test",
        category="secrets",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        evidence=[Evidence(file_path="../outside.py", line_number=1, code_snippet='api_key = "sk-123"')],
        remediation_guidance="n/a",
    )
    report = Report(report_id="path-report-001", metadata=metadata, findings=[finding], summary="path test")
    report_path = tmp_path / "path-report.json"
    report_path.write_text(JSONReportWriter().to_json(report), encoding="utf-8")

    code = main(["verify", str(report_path), "finding-path-001"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["resolved"] is False
    assert payload["remaining_locations"] == ["../outside.py:blocked_path"]
