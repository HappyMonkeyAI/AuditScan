"""CLI interface for repo-audit-scan."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
import sys
from typing import Any, Dict, Iterable, List, Optional, Tuple
import uuid

from repo_audit_scan import __version__
from repo_audit_scan.adapter_registry import AdapterRegistry
from repo_audit_scan.adapters_final import ScanContext
from repo_audit_scan.dependency_enrichment import scan_dependencies
from repo_audit_scan.external_content import run_repo_security_scan
from repo_audit_scan.inventory import FilesystemWalker
from repo_audit_scan.logging_setup import setup_logging
from repo_audit_scan.models import (
    AssessmentDisposition,
    AssessmentStatus,
    ExternalAssessment,
    ExternalCheck,
    ExternalTarget,
    Finding,
    Report,
    ScanMetadata,
)
from repo_audit_scan.reporting import ReportArtifactWriter
from repo_audit_scan.rules import Rule, RuleRegistry
from repo_audit_scan.scoring import CompromiseModeClassifier, IANScorer
from repo_audit_scan.triage import TriageArtifactWriter


def _default_rules_path() -> Path:
    return Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "rules" / "sample_rules.json"


def _load_rules(rules_path: Optional[str]) -> RuleRegistry:
    registry = RuleRegistry()
    resolved = Path(rules_path) if rules_path else _default_rules_path()
    if not resolved.exists():
        raise FileNotFoundError(f"Rules file not found: {resolved}")
    registry.load_from_file(str(resolved))
    return registry


def _new_report_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"scan-{ts}-{uuid.uuid4().hex[:8]}"


def _scan_repository(
    repo_path: Path,
    registry: RuleRegistry,
    enrich_dependencies: bool = False,
    fail_open_on_enrichment_error: bool = True,
    profile: str = "universal",
) -> Report:
    if profile not in {"universal", "external_repo"}:
        raise ValueError(f"Unsupported scan profile: {profile}")
    adapters = AdapterRegistry()
    inventory = FilesystemWalker(str(repo_path)).walk()

    rule_results = []
    for file_meta in inventory.files:
        if file_meta.is_binary:
            continue
        full_path = repo_path / file_meta.path
        adapter = adapters.resolve_adapter(str(full_path))
        if adapter is None:
            continue

        try:
            content = full_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        context = ScanContext(
            file_path=file_meta.path,
            file_content=content,
            language=adapter.language,
        )
        rules = registry.list_all()
        if profile == "external_repo" and adapter.language != "external-content":
            rules = [rule for rule in rules if not rule.rule_id.startswith("ecg-")]
        for rule in rules:
            if adapter.supports_rule(rule):
                rule_results.extend(adapter.scan(context, rule))

    dependency_results, dependency_metadata = scan_dependencies(
        repo_path=repo_path,
        registry=registry,
        enrich_dependencies=enrich_dependencies,
        fail_open=fail_open_on_enrichment_error,
    )
    rule_results.extend(dependency_results)
    external_engine_metadata = None
    if profile == "external_repo":
        external_results, external_engine_metadata = run_repo_security_scan(repo_path)
        rule_results.extend(external_results)

    findings: List[Finding] = []
    for index, result in enumerate(rule_results, start=1):
        ian = IANScorer.score_finding(result)
        affected_files = {item.file_path for item in result.evidence}
        mode = CompromiseModeClassifier.classify_mode(
            ian.composite_score,
            evidence_count=len(result.evidence),
            file_count=len(affected_files),
            severity=result.severity,
        )
        adjusted, rationale = CompromiseModeClassifier.adjust_for_mode(
            ian,
            mode,
            evidence_count=len(result.evidence),
        )
        findings.append(
            Finding(
                finding_id=f"finding-{index:04d}",
                rule_id=result.rule_id,
                rule_title=result.rule_title,
                category=result.category,
                severity=result.severity,
                confidence=result.confidence,
                evidence=result.evidence,
                remediation_guidance=result.remediation_guidance,
                ian_score=adjusted,
                compromise_mode=mode,
                prioritization_rationale=rationale,
                affected_files_count=len(affected_files),
                manual_confirmation_required=result.manual_confirmation_required,
            )
        )

    metadata = ScanMetadata(
        schema_version="1.0",
        tool_version=__version__,
        scan_timestamp=datetime.now(timezone.utc).isoformat(),
        repository_path=str(repo_path),
        scanned_files_count=inventory.total_files,
        skipped_files_count=inventory.skipped_count,
        detected_languages=sorted(inventory.detected_languages.keys()),
        detected_frameworks=sorted(inventory.detected_frameworks),
    )
    enrichment_note = (
        f" Dependency scan: {dependency_metadata['packages_scanned']} packages, "
        f"mode={dependency_metadata['mode']}."
    )
    assessment = None
    if profile == "external_repo":
        external_findings = [f for f in findings if f.rule_id.startswith("ecg-")]
        blocked = any(f.severity.value in {"critical", "high"} for f in external_findings)
        engine_unavailable = external_engine_metadata and external_engine_metadata["status"] != "completed"
        checks = [ExternalCheck("deterministic_rules", "completed")]
        if external_engine_metadata:
            checks.append(ExternalCheck("repo_security_scan", external_engine_metadata["status"], external_engine_metadata.get("detail")))
        needs_review = bool(engine_unavailable)
        assessment = ExternalAssessment(
            target=ExternalTarget(kind="staged_path", origin=str(repo_path)),
            profile=profile,
            status=AssessmentStatus.BLOCKED if blocked else (AssessmentStatus.DEGRADED if needs_review else AssessmentStatus.COMPLETE),
            disposition=AssessmentDisposition.BLOCK if blocked else (AssessmentDisposition.NEEDS_HUMAN_REVIEW if needs_review else AssessmentDisposition.ALLOW_REVIEW),
            checks=checks,
        )
    return Report(
        report_id=_new_report_id(),
        metadata=metadata,
        findings=findings,
        summary=f"Scanned {inventory.total_files} files with {len(findings)} findings.{enrichment_note}",
        assessment=assessment,
    )


def _write_scan_reports(report: Report, repo_path: Path, output_root: Path) -> Dict[str, Path]:
    report_dir = output_root / report.report_id
    paths = ReportArtifactWriter().write(report, report_dir)

    date_dir = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    mirror_dir = repo_path / "audits" / date_dir / "repo-audit-scan"
    mirror_paths = ReportArtifactWriter().write(report, mirror_dir)

    return {
        "workspace_json": paths["json"],
        "workspace_markdown": paths["markdown"],
        "mirror_json": mirror_paths["json"],
        "mirror_markdown": mirror_paths["markdown"],
    }


def _read_report_json(report_path: Path) -> Dict[str, Any]:
    if not report_path.exists():
        raise FileNotFoundError(f"Report file not found: {report_path}")
    return json.loads(report_path.read_text(encoding="utf-8"))


def _normalize_report_data(report_data: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize writer JSON payloads to core Report model structure."""
    normalized_findings: List[Dict[str, Any]] = []
    for finding in report_data.get("findings", []):
        normalized_evidence = []
        for item in finding.get("evidence", []):
            normalized_evidence.append(
                {
                    "file_path": item.get("file_path"),
                    "line_number": item.get("line_number"),
                    "column_number": item.get("column_number"),
                    "code_snippet": item.get("code_snippet"),
                    "context": item.get("context"),
                }
            )
        normalized_findings.append(
            {
                "finding_id": finding.get("finding_id"),
                "rule_id": finding.get("rule_id"),
                "rule_title": finding.get("rule_title"),
                "category": finding.get("category"),
                "severity": finding.get("severity"),
                "confidence": finding.get("confidence"),
                "evidence": normalized_evidence,
                "remediation_guidance": finding.get("remediation_guidance", ""),
                "ian_score": finding.get("ian_score"),
                "compromise_mode": finding.get("compromise_mode"),
                "prioritization_rationale": finding.get("prioritization_rationale"),
                "affected_files_count": finding.get("affected_files_count", 0),
                "manual_confirmation_required": finding.get("manual_confirmation_required", False),
            }
        )

    summary_text = report_data.get("summary")
    if isinstance(summary_text, dict):
        summary_text = summary_text.get("text")

    return {
        "report_id": report_data.get("report_id"),
        "metadata": report_data.get("metadata", {}),
        "findings": normalized_findings,
        "summary": summary_text,
    }


def _find_rule(registry: RuleRegistry, rule_id: str) -> Rule:
    rule = registry.get_by_id(rule_id)
    if rule is None:
        raise KeyError(f"Rule not found in registry: {rule_id}")
    return rule


def _verify_finding(
    report_data: Dict[str, Any],
    finding_id: str,
    registry: RuleRegistry,
    repo_override: Optional[Path] = None,
) -> Dict[str, Any]:
    findings = report_data.get("findings", [])
    finding = next((item for item in findings if item.get("finding_id") == finding_id), None)
    if finding is None:
        raise KeyError(f"Finding not found: {finding_id}")

    rule_id = finding["rule_id"]
    rule = _find_rule(registry, rule_id)
    metadata = report_data.get("metadata", {})
    repo_path = repo_override or Path(metadata.get("repository_path", "."))

    adapters = AdapterRegistry()
    remaining: List[str] = []
    inspected = set()
    repo_root = repo_path.resolve()
    for evidence in finding.get("evidence", []):
        file_path = evidence.get("file_path")
        if not file_path or file_path in inspected:
            continue
        inspected.add(file_path)
        full_path = _resolve_repo_relative_path(repo_root, file_path)
        if full_path is None:
            remaining.append(f"{file_path}:blocked_path")
            continue
        if not full_path.exists():
            remaining.append(f"{file_path}:missing")
            continue
        try:
            content = full_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            remaining.append(f"{file_path}:unreadable")
            continue
        adapter = adapters.resolve_adapter(str(full_path))
        if adapter is not None:
            context = ScanContext(file_path=file_path, file_content=content, language=adapter.language)
            if adapter.supports_rule(rule):
                results = adapter.scan(context, rule)
                if results:
                    for result in results:
                        for item in result.evidence:
                            loc = f"{item.file_path}:{item.line_number}" if item.line_number else item.file_path
                            remaining.append(loc)
                    continue

        # Fallback for findings that are not adapter-backed (for example lockfile dependency checks).
        snippet = evidence.get("code_snippet")
        if snippet and str(snippet) in content:
            line_no = evidence.get("line_number")
            remaining.append(f"{file_path}:{line_no}" if line_no else file_path)

    return {
        "finding_id": finding_id,
        "rule_id": rule_id,
        "resolved": len(remaining) == 0,
        "remaining_locations": sorted(set(remaining)),
    }


def _resolve_repo_relative_path(repo_root: Path, relative_path: str) -> Optional[Path]:
    candidate = Path(relative_path)
    if candidate.is_absolute():
        return None
    resolved = (repo_root / candidate).resolve()
    try:
        resolved.relative_to(repo_root)
    except ValueError:
        return None
    return resolved


def _resolve_report_path(path_value: str) -> Path:
    candidate = Path(path_value)
    if candidate.exists():
        return candidate
    in_scan_reports = Path("scan-reports") / path_value / "report.json"
    if in_scan_reports.exists():
        return in_scan_reports
    return candidate


def _handle_scan(args: argparse.Namespace) -> int:
    repo_path = Path(args.path).resolve()
    if not repo_path.exists():
        print(f"Repository path does not exist: {repo_path}", file=sys.stderr)
        return 2

    registry = _load_rules(args.rules)
    report = _scan_repository(
        repo_path,
        registry,
        enrich_dependencies=args.enrich_dependencies,
        fail_open_on_enrichment_error=not args.fail_closed_enrichment,
        profile=args.profile,
    )

    response: Dict[str, Any] = {
        "report_id": report.report_id,
        "repository_path": str(repo_path),
        "findings": len(report.findings),
    }
    if report.assessment:
        response["assessment"] = report.assessment.to_dict()

    if args.write_reports:
        output_root = Path(args.output_root).resolve()
        paths = _write_scan_reports(report, repo_path, output_root)
        response["report_paths"] = {key: str(value) for key, value in paths.items()}

    if args.format == "json":
        print(json.dumps(response, indent=2))
    else:
        print(f"scan complete: {response['report_id']} ({response['findings']} findings)")
        if "report_paths" in response:
            print(f"workspace report: {response['report_paths']['workspace_json']}")
            print(f"mirror report: {response['report_paths']['mirror_json']}")
    return 0


def _handle_rules(args: argparse.Namespace) -> int:
    registry = _load_rules(args.rules)
    rules = [rule.to_dict() for rule in registry.list_all()]
    if args.format == "json":
        print(json.dumps({"count": len(rules), "rules": rules}, indent=2))
    else:
        print(f"rules: {len(rules)}")
        for rule in rules:
            print(f"{rule['rule_id']}: {rule['title']} ({rule['severity']})")
    return 0


def _handle_triage(args: argparse.Namespace) -> int:
    report_path = _resolve_report_path(args.report)
    report_data = _read_report_json(report_path)
    report = Report.from_dict(_normalize_report_data(report_data))

    output_dir = Path(args.output_dir).resolve() if args.output_dir else report_path.parent
    pilot_name = args.pilot_name or Path(report.metadata.repository_path).name or report.report_id
    paths = TriageArtifactWriter().write(
        report,
        output_dir,
        pilot_name=pilot_name,
        limit=args.limit,
        min_ian_score=args.min_ian_score,
        review_notes=args.review_note,
    )
    print(
        json.dumps(
            {"triage": str(paths["triage"]), "review": str(paths["review"]), "pilot_name": pilot_name},
            indent=2,
        )
    )
    return 0


def _handle_verify(args: argparse.Namespace) -> int:
    report_path = _resolve_report_path(args.report)
    report_data = _read_report_json(report_path)
    registry = _load_rules(args.rules)
    repo_override = Path(args.repo_path).resolve() if args.repo_path else None
    result = _verify_finding(report_data, args.finding, registry, repo_override=repo_override)
    print(json.dumps(result, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Security-focused code audit scanner")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument(
        "--rules",
        help="Path to a rules JSON file (defaults to repository fixture rules).",
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    scan_parser = subparsers.add_parser("scan", help="Scan a repository")
    scan_parser.add_argument("path", help="Repository path to scan")
    scan_parser.add_argument("--output-root", default="scan-reports", help="Workspace report root directory")
    scan_parser.add_argument("--format", choices=["text", "json"], default="text")
    scan_parser.add_argument("--profile", choices=["universal", "external_repo"], default="universal")
    scan_parser.add_argument("--write-reports", dest="write_reports", action="store_true", default=True)
    scan_parser.add_argument("--no-write-reports", dest="write_reports", action="store_false")
    scan_parser.add_argument(
        "--enrich-dependencies",
        action="store_true",
        help="Enable opt-in dependency advisory enrichment (requires REPO_AUDIT_DEP_ENRICHMENT=true).",
    )
    scan_parser.add_argument(
        "--fail-closed-enrichment",
        action="store_true",
        help="Fail scan when enrichment errors occur (default is fail-open).",
    )

    rules_parser = subparsers.add_parser("rules", help="List available rules")
    rules_parser.add_argument("--format", choices=["text", "json"], default="text")

    triage_parser = subparsers.add_parser("triage", help="Generate ticket-ready triage and review Markdown")
    triage_parser.add_argument("report", help="Report path or report id under scan-reports/")
    triage_parser.add_argument("--limit", type=int, default=10, help="Max findings to include")
    triage_parser.add_argument("--min-ian-score", type=float, help="Filter by minimum IAN score")
    triage_parser.add_argument("--output-dir", help="Directory where triage.md/review.md will be written")
    triage_parser.add_argument("--pilot-name", help="Pilot name label for review.md")
    triage_parser.add_argument("--review-note", action="append", default=[], help="Review note for review.md")

    verify_parser = subparsers.add_parser("verify", help="Verify a finding by re-running its rule on evidence files")
    verify_parser.add_argument("report", help="Report path or report id under scan-reports/")
    verify_parser.add_argument("finding", help="Finding ID to verify")
    verify_parser.add_argument("--repo-path", help="Override repository path from report metadata")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(verbose=args.verbose)

    if not args.command:
        parser.print_help()
        return 0

    try:
        if args.command == "scan":
            return _handle_scan(args)
        if args.command == "rules":
            return _handle_rules(args)
        if args.command == "triage":
            return _handle_triage(args)
        if args.command == "verify":
            return _handle_verify(args)
        print(f"Unknown command: {args.command}", file=sys.stderr)
        return 2
    except (FileNotFoundError, KeyError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
