"""Tests for triage and scan-review Markdown writers."""

from repo_audit_scan.models import (
    Confidence,
    CompromiseMode,
    Evidence,
    Finding,
    Report,
    ScanMetadata,
    Severity,
)
from repo_audit_scan.triage import ScanReviewMarkdownWriter, TriageArtifactWriter, TriageMarkdownWriter


def make_triage_report() -> Report:
    """Create a report with findings that exercise ticket prioritization."""
    metadata = ScanMetadata(
        schema_version="1.0",
        tool_version="0.1.0",
        scan_timestamp="2026-05-27T15:00:00Z",
        repository_path="fixtures/dashboard",
        scanned_files_count=12,
        skipped_files_count=2,
        detected_languages=["javascript"],
        detected_frameworks=["express"],
    )
    high = Finding(
        finding_id="finding-high",
        rule_id="js-002",
        rule_title="DOM-based XSS",
        category="injection",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        evidence=[
            Evidence(
                file_path="public/app.js",
                line_number=42,
                column_number=10,
                code_snippet='panel.innerHTML = userControlledMessage; const api_key = "super-secret-token"',
                context="Agent log rendering",
            )
        ],
        remediation_guidance="Render dynamic text through textContent or a vetted sanitizer.",
        ian_score=0.91,
        compromise_mode=CompromiseMode.COVER,
        prioritization_rationale="Browser-rendered agent logs can cross a trust boundary.",
        affected_files_count=1,
    )
    medium = Finding(
        finding_id="finding-medium",
        rule_id="cfg-001",
        rule_title="Debug mode enabled",
        category="configuration",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        evidence=[
            Evidence(
                file_path="server/config.js",
                line_number=7,
                code_snippet="debug: true",
                context="Runtime config",
            )
        ],
        remediation_guidance="Disable debug mode outside local development.",
        ian_score=0.55,
        compromise_mode=CompromiseMode.TRIAGE,
        affected_files_count=1,
    )
    return Report(
        report_id="report-triage",
        metadata=metadata,
        findings=[medium, high],
        summary="Two findings need review.",
    )


def test_triage_writer_returns_top_findings_as_ticket_ready_markdown():
    """Triage output should be standalone, prioritized, and verification-ready."""
    markdown = TriageMarkdownWriter().to_markdown(make_triage_report(), limit=1)

    assert markdown.startswith("# Triage: report-triage")
    assert "Total selected findings: `1`" in markdown
    assert "## Ticket 1: DOM-based XSS" in markdown
    assert "Finding ID: `finding-high`" in markdown
    assert "IAN score: `0.91`" in markdown
    assert "Audit finding status: `hypothesis_pending_verification`" in markdown
    assert "## Ticket 2" not in markdown
    assert "### Acceptance Criteria" in markdown
    assert "- [ ] The finding has been manually verified against the current source." in markdown
    assert "### Verification Steps" in markdown
    assert "Re-run AuditScan verification for `finding-high` or rule `js-002`." in markdown
    assert "Render dynamic text through textContent or a vetted sanitizer." in markdown
    assert "public/app.js:42:10" in markdown
    assert "***SECRET***" in markdown
    assert "super-secret-token" not in markdown


def test_triage_writer_filters_by_minimum_ian_score():
    """Triage selection should support score thresholds for high-priority work."""
    markdown = TriageMarkdownWriter().to_markdown(make_triage_report(), min_ian_score=0.8)

    assert "## Ticket 1: DOM-based XSS" in markdown
    assert "Debug mode enabled" not in markdown
    assert "Total selected findings: `1`" in markdown


def test_scan_review_writer_creates_rule_improvement_journal():
    """Pilot review output should make scanner feedback explicit and auditable."""
    markdown = ScanReviewMarkdownWriter().to_markdown(
        make_triage_report(),
        pilot_name="vibes-dashboard",
        notes=[
            "DOM sink findings need source-to-sink review before ticket creation.",
            "Agent dashboard control-plane rules should be added after this pilot.",
        ],
    )

    assert markdown.startswith("# Scan Review: vibes-dashboard")
    assert "Report ID: `report-triage`" in markdown
    assert "## Review Verdict Legend" in markdown
    assert "`true_positive`" in markdown
    assert "`false_positive`" in markdown
    assert "`misclassified`" in markdown
    assert "`needs_manual_review`" in markdown
    assert "### finding-high - DOM-based XSS" in markdown
    assert "- Reviewer verdict: `needs_manual_review`" in markdown
    assert "- Rule improvement notes:" in markdown
    assert "DOM sink findings need source-to-sink review before ticket creation." in markdown


def test_triage_artifact_writer_writes_triage_and_review_markdown(tmp_path):
    """Artifact writer should create paired triage and review files."""
    paths = TriageArtifactWriter().write(
        make_triage_report(),
        tmp_path,
        pilot_name="dashboard-pilot",
        limit=1,
        review_notes=["Pilot note"],
    )

    assert paths["triage"] == tmp_path / "triage.md"
    assert paths["review"] == tmp_path / "review.md"
    assert paths["triage"].exists()
    assert paths["review"].exists()
    assert "## Ticket 1: DOM-based XSS" in paths["triage"].read_text(encoding="utf-8")
    assert "# Scan Review: dashboard-pilot" in paths["review"].read_text(encoding="utf-8")


def test_triage_classes_are_exported_from_package():
    """Public API should expose T-012 writers at package level."""
    from repo_audit_scan import ScanReviewMarkdownWriter as ExportedReviewWriter
    from repo_audit_scan import TriageArtifactWriter as ExportedArtifactWriter
    from repo_audit_scan import TriageMarkdownWriter as ExportedTriageWriter

    assert ExportedTriageWriter is TriageMarkdownWriter
    assert ExportedReviewWriter is ScanReviewMarkdownWriter
    assert ExportedArtifactWriter is TriageArtifactWriter
