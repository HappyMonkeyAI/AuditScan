"""Tests for the external-content assessment contract."""

import json

import pytest

from repo_audit_scan.models import (
    AgentPolicy,
    AssessmentDisposition,
    AssessmentStatus,
    ExternalAssessment,
    ExternalCheck,
    ExternalTarget,
    Report,
    ScanMetadata,
)
from repo_audit_scan.reporting import JSONReportWriter, MarkdownReportWriter


def test_block_assessment_denies_operational_actions():
    assessment = ExternalAssessment(
        target=ExternalTarget(kind="repository", origin="https://github.com/acme/hostile", resolved_ref="abc123"),
        profile="external_repo",
        status=AssessmentStatus.BLOCKED,
        disposition=AssessmentDisposition.BLOCK,
        checks=[ExternalCheck(name="content_rules", status="completed")],
    )

    assert assessment.policy.read_source is True
    assert assessment.policy.install is False
    assert assessment.policy.execute is False
    assert assessment.policy.register_mcp is False
    assert assessment.policy.write_memory is False


def test_degraded_assessment_is_needs_review_and_tracks_failed_checks():
    assessment = ExternalAssessment(
        target=ExternalTarget(kind="url", origin="https://example.test/docs"),
        profile="external_link",
        status=AssessmentStatus.DEGRADED,
        disposition=AssessmentDisposition.NEEDS_HUMAN_REVIEW,
        checks=[
            ExternalCheck(name="url_fetch", status="completed"),
            ExternalCheck(name="semantic_review", status="unavailable", detail="reviewer offline"),
        ],
    )

    assert assessment.checks_by_status["completed"] == ["url_fetch"]
    assert assessment.checks_by_status["unavailable"] == ["semantic_review"]
    assert assessment.policy.install is False


def test_allow_review_is_not_execution_approval():
    assessment = ExternalAssessment(
        target=ExternalTarget(kind="repository", origin="https://github.com/acme/clean", resolved_ref="def456"),
        profile="external_repo",
        status=AssessmentStatus.COMPLETE,
        disposition=AssessmentDisposition.ALLOW_REVIEW,
        checks=[ExternalCheck(name="static_scan", status="completed")],
    )

    assert assessment.policy.read_source is True
    assert assessment.policy.install is False
    assert assessment.policy.execute is False
    assert assessment.policy.register_mcp is False


def test_external_assessment_is_embedded_in_json_and_markdown_reports():
    assessment = ExternalAssessment(
        target=ExternalTarget(kind="url", origin="https://example.test/readme"),
        profile="external_link",
        status=AssessmentStatus.COMPLETE,
        disposition=AssessmentDisposition.ALLOW_REVIEW,
        checks=[ExternalCheck(name="url_fetch", status="completed")],
    )
    report = Report(
        report_id="report-external-001",
        metadata=ScanMetadata(schema_version="1.0", tool_version="0.1.0", scan_timestamp="2026-09-04T00:00:00Z"),
        assessment=assessment,
    )

    output = JSONReportWriter().to_dict(report)
    assert output["assessment"]["disposition"] == "allow_review"
    assert output["assessment"]["policy"]["execute"] is False
    assert json.dumps(output)[0] == "{"

    markdown = MarkdownReportWriter().to_markdown(report)
    assert "## Assessment" in markdown
    assert "allow_review" in markdown
    assert "untrusted" in markdown.lower()


def test_invalid_disposition_is_rejected():
    with pytest.raises(ValueError):
        ExternalAssessment(
            target=ExternalTarget(kind="url", origin="https://example.test"),
            profile="external_link",
            status=AssessmentStatus.COMPLETE,
            disposition="clean",  # type: ignore[arg-type]
        )


def test_policy_rejects_untrusted_operational_override():
    with pytest.raises(ValueError):
        AgentPolicy(
            read_source=True,
            install=True,
            execute=False,
            register_mcp=False,
            write_memory=False,
        )


def test_external_assessment_round_trips_through_report_json():
    assessment = ExternalAssessment(
        target=ExternalTarget(kind="repository", origin="https://github.com/acme/repo", resolved_ref="abc123"),
        profile="external_repo",
        status=AssessmentStatus.BLOCKED,
        disposition=AssessmentDisposition.BLOCK,
        checks=[ExternalCheck(name="content_rules", status="failed", detail="injection marker")],
    )
    report = Report(
        report_id="report-roundtrip-001",
        metadata=ScanMetadata(schema_version="1.0", tool_version="0.1.0", scan_timestamp="2026-09-04T00:00:00Z"),
        assessment=assessment,
    )

    restored = Report.from_dict(report.to_dict())

    assert restored.assessment is not None
    assert restored.assessment.disposition is AssessmentDisposition.BLOCK
    assert restored.assessment.target.resolved_ref == "abc123"
    assert restored.assessment.checks[0].status == "failed"
