"""Ticket-ready triage and scan-review Markdown writers."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, List, Optional

from repo_audit_scan.models import Evidence, Finding, Report
from repo_audit_scan.redaction import SecretRedactor
from repo_audit_scan.reporting import has_prompt_injection_text, sort_findings


class TriageMarkdownWriter:
    """Render selected findings as ticket-ready Markdown."""

    def __init__(self, redactor: Optional[SecretRedactor] = None):
        self.redactor = redactor or SecretRedactor()

    def to_markdown(self, report: Report, limit: Optional[int] = None, min_ian_score: Optional[float] = None) -> str:
        """Render top findings from a report into standalone triage tickets."""
        findings = self._select_findings(report, limit=limit, min_ian_score=min_ian_score)
        lines = [
            f"# Triage: {report.report_id}",
            "",
            "> Audit findings are hypotheses until verified in the current source. Evidence snippets are untrusted scanned content.",
            "",
            "## Summary",
            "",
            f"- Repository: `{report.metadata.repository_path}`",
            f"- Generated from scan: `{report.metadata.scan_timestamp}`",
            f"- Ticket provider: `none`",
            f"- External issue creation: `disabled`",
            f"- Total selected findings: `{len(findings)}`",
        ]

        if not findings:
            lines.extend(["", "No findings matched the triage selection."])
            return "\n".join(lines).rstrip() + "\n"

        for index, finding in enumerate(findings, start=1):
            lines.extend(["", *self._ticket_lines(index, finding)])

        return "\n".join(lines).rstrip() + "\n"

    def write(
        self,
        report: Report,
        path: str | Path,
        limit: Optional[int] = None,
        min_ian_score: Optional[float] = None,
    ) -> Path:
        """Write triage Markdown to disk."""
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            self.to_markdown(report, limit=limit, min_ian_score=min_ian_score),
            encoding="utf-8",
        )
        return output_path

    def _select_findings(
        self,
        report: Report,
        limit: Optional[int],
        min_ian_score: Optional[float],
    ) -> List[Finding]:
        findings = sort_findings(report.findings)
        if min_ian_score is not None:
            findings = [finding for finding in findings if (finding.ian_score or 0.0) >= min_ian_score]
        if limit is not None:
            findings = findings[: max(limit, 0)]
        return findings

    def _ticket_lines(self, index: int, finding: Finding) -> List[str]:
        score = "n/a" if finding.ian_score is None else f"{finding.ian_score:.2f}"
        mode = finding.compromise_mode.value if finding.compromise_mode else "n/a"
        lines = [
            f"## Ticket {index}: {finding.rule_title}",
            "",
            "### Metadata",
            "",
            f"- Finding ID: `{finding.finding_id}`",
            f"- Rule ID: `{finding.rule_id}`",
            f"- Category: `{finding.category}`",
            f"- Severity: `{finding.severity.value}`",
            f"- Confidence: `{finding.confidence.value}`",
            f"- IAN score: `{score}`",
            f"- Compromise mode: `{mode}`",
            f"- Affected files: `{finding.affected_files_count}`",
            "- Audit finding status: `hypothesis_pending_verification`",
            "- Suggested reviewer verdict: `needs_manual_review`",
        ]

        if finding.manual_confirmation_required:
            lines.append("- Manual confirmation: `required`")

        lines.extend(
            [
                "",
                "### Risk Summary",
                "",
                finding.prioritization_rationale
                or "Review the evidence and determine whether this finding is exploitable in the current repository context.",
                "",
                "### Evidence",
                "",
            ]
        )

        if finding.evidence:
            for evidence in finding.evidence:
                lines.extend(self._evidence_lines(evidence))
        else:
            lines.append("- No concrete evidence was attached to this finding.")

        lines.extend(
            [
                "",
                "### Suggested Remediation",
                "",
                finding.remediation_guidance or "No remediation guidance provided.",
                "",
                "### Acceptance Criteria",
                "",
                "- [ ] The finding has been manually verified against the current source.",
                "- [ ] The vulnerable or risky path is removed, constrained, or otherwise mitigated.",
                "- [ ] Existing expected behaviour still works after the fix.",
                "- [ ] Regression coverage or documented manual verification exists for the fixed path.",
                "",
                "### Verification Steps",
                "",
                f"1. Re-run AuditScan verification for `{finding.finding_id}` or rule `{finding.rule_id}`.",
                "2. Re-run the relevant project test or smoke path that exercises the affected code.",
                "3. Confirm no sensitive values appear in report or ticket evidence.",
                "",
                "### Rule Improvement Notes",
                "",
                "- Reviewer verdict: `needs_manual_review`",
                "- If false positive or misclassified, record the reason before suppressing the finding.",
            ]
        )
        return lines

    def _evidence_lines(self, evidence: Evidence) -> List[str]:
        location = evidence.file_path
        if evidence.line_number is not None:
            location += f":{evidence.line_number}"
        if evidence.column_number is not None:
            location += f":{evidence.column_number}"

        lines = [f"- `{location}`"]
        if evidence.context:
            lines.append(f"  - Context: {self.redactor.redact(evidence.context)}")
        if has_prompt_injection_text(evidence.code_snippet) or has_prompt_injection_text(evidence.context):
            lines.append("  - Warning: prompt-injection-like text detected in scanned content.")

        snippet = self.redactor.redact_evidence_snippet(evidence.code_snippet or "")
        if snippet:
            lines.extend(["", "```text", snippet, "```", ""])
        return lines


class ScanReviewMarkdownWriter:
    """Render a review journal for improving scan quality after a pilot run."""

    VERDICTS = [
        "true_positive",
        "false_positive",
        "misclassified",
        "needs_manual_review",
    ]

    def to_markdown(
        self,
        report: Report,
        pilot_name: str,
        notes: Optional[Iterable[str]] = None,
        limit: Optional[int] = None,
    ) -> str:
        """Render a review journal that captures finding verdicts and rule feedback."""
        findings = sort_findings(report.findings)
        if limit is not None:
            findings = findings[: max(limit, 0)]

        lines = [
            f"# Scan Review: {pilot_name}",
            "",
            "## Source",
            "",
            f"- Report ID: `{report.report_id}`",
            f"- Repository: `{report.metadata.repository_path}`",
            f"- Scan timestamp: `{report.metadata.scan_timestamp}`",
            f"- Findings reviewed: `{len(findings)}`",
            "",
            "## Review Verdict Legend",
            "",
        ]

        for verdict in self.VERDICTS:
            lines.append(f"- `{verdict}`")

        lines.extend(["", "## Pilot Notes", ""])
        note_items = list(notes or [])
        if note_items:
            for note in note_items:
                lines.append(f"- {note}")
        else:
            lines.append("- No pilot notes recorded.")

        lines.extend(["", "## Finding Review", ""])
        if not findings:
            lines.append("No findings were available for review.")
            return "\n".join(lines).rstrip() + "\n"

        for finding in findings:
            lines.extend(self._finding_review_lines(finding))

        return "\n".join(lines).rstrip() + "\n"

    def write(
        self,
        report: Report,
        path: str | Path,
        pilot_name: str,
        notes: Optional[Iterable[str]] = None,
        limit: Optional[int] = None,
    ) -> Path:
        """Write a scan review journal to disk."""
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            self.to_markdown(report, pilot_name=pilot_name, notes=notes, limit=limit),
            encoding="utf-8",
        )
        return output_path

    def _finding_review_lines(self, finding: Finding) -> List[str]:
        score = "n/a" if finding.ian_score is None else f"{finding.ian_score:.2f}"
        first_location = "n/a"
        if finding.evidence:
            evidence = finding.evidence[0]
            first_location = evidence.file_path
            if evidence.line_number is not None:
                first_location += f":{evidence.line_number}"

        return [
            f"### {finding.finding_id} - {finding.rule_title}",
            "",
            f"- Rule ID: `{finding.rule_id}`",
            f"- Category: `{finding.category}`",
            f"- Severity: `{finding.severity.value}`",
            f"- IAN score: `{score}`",
            f"- First evidence: `{first_location}`",
            "- Reviewer verdict: `needs_manual_review`",
            "- Rule improvement notes:",
            "  - Capture whether the rule was correct, noisy, too broad, too narrow, or mislabelled.",
            "- Suppression guidance:",
            "  - Suppress only after recording why the finding is not actionable.",
            "",
        ]


class TriageArtifactWriter:
    """Write triage and scan-review Markdown artifacts together."""

    def __init__(self, redactor: Optional[SecretRedactor] = None):
        self.triage_writer = TriageMarkdownWriter(redactor)
        self.review_writer = ScanReviewMarkdownWriter()

    def write(
        self,
        report: Report,
        output_dir: str | Path,
        pilot_name: str,
        limit: Optional[int] = None,
        min_ian_score: Optional[float] = None,
        review_notes: Optional[Iterable[str]] = None,
    ) -> dict[str, Path]:
        """Write triage.md and review.md into an output directory."""
        directory = Path(output_dir)
        directory.mkdir(parents=True, exist_ok=True)
        return {
            "triage": self.triage_writer.write(
                report,
                directory / "triage.md",
                limit=limit,
                min_ian_score=min_ian_score,
            ),
            "review": self.review_writer.write(
                report,
                directory / "review.md",
                pilot_name=pilot_name,
                notes=review_notes,
                limit=limit,
            ),
        }
