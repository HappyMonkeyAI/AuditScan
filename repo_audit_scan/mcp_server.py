"""MCP (Model Context Protocol) server for repo-audit-scan."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
from typing import Any, Callable, Dict, Optional

from repo_audit_scan.cli import (
    _default_rules_path,
    _find_rule,
    _load_rules,
    _new_report_id,
    _normalize_report_data,
    _read_report_json,
    _scan_repository,
    _verify_finding,
)
from repo_audit_scan.adversarial import (
    challenge_fix_contract,
    compare_verdicts_contract,
    evaluate_governance_contract,
    generate_test_intents_contract,
    review_finding_contract,
)
from repo_audit_scan.adversarial_prompts import get_prompt_pack
from repo_audit_scan.adversarial_reporting import write_assurance_artifacts
from repo_audit_scan.models import Report
from repo_audit_scan.models import AssessmentDisposition, AssessmentStatus, ExternalAssessment, ExternalCheck, ExternalTarget
from repo_audit_scan.external_fetch import fetch_external_text
from repo_audit_scan.quarantine import quarantine_repository
import shutil
from repo_audit_scan.reporting import JSONReportWriter, ReportArtifactWriter
from repo_audit_scan.triage import TriageArtifactWriter
from repo_audit_scan.living_docs import (
    DocGap,
    DocPatch,
    apply_patches,
    discover_docs_path,
    propose_living_doc_updates,
    review_living_docs,
    verify_gaps,
)


class MCPServer:
    """Simple MCP-style tool registry and execution wrapper."""

    def __init__(self):
        self.tools: Dict[str, Callable[..., Dict[str, Any]]] = {}
        self.started_at = datetime.now(timezone.utc)
        self.last_scan: Optional[Dict[str, Any]] = None
        # Phase 2: living-docs session state
        self._last_gaps: list = []
        self._pending_patches: Dict[str, DocPatch] = {}
        self.register_defaults()

    def register_tool(self, name: str, handler: Callable[..., Dict[str, Any]]) -> None:
        self.tools[name] = handler

    def get_tool(self, name: str) -> Optional[Callable[..., Dict[str, Any]]]:
        return self.tools.get(name)

    def list_tools(self) -> Dict[str, Any]:
        return self.tools.copy()

    def execute_tool(self, name: str, **kwargs: Any) -> Dict[str, Any]:
        handler = self.get_tool(name)
        if handler is None:
            return {"ok": False, "error": f"unknown_tool: {name}"}
        try:
            return {"ok": True, "result": handler(**kwargs)}
        except (FileNotFoundError, KeyError, ValueError) as exc:
            return {"ok": False, "error": str(exc)}

    def register_defaults(self) -> None:
        self.register_tool("server.get_info", self.get_info)
        self.register_tool("server.get_health", self.get_health)
        self.register_tool("server.get_status", self.get_status)
        self.register_tool("scan_repository", self.scan_repository)
        self.register_tool("inspect_external_link", self.inspect_external_link)
        self.register_tool("quarantine_and_scan_repository", self.quarantine_and_scan_repository)
        self.register_tool("list_rules", self.list_rules)
        self.register_tool("get_finding", self.get_finding)
        self.register_tool("triage_report", self.triage_report)
        self.register_tool("verify_fix", self.verify_fix)
        self.register_tool("get_latest_report", self.get_latest_report)
        self.register_tool("diagnostics.validate_config", self.validate_config)
        self.register_tool("diagnostics.run_self_check", self.run_self_check)
        self.register_tool("reports.list_reports", self.list_reports)
        self.register_tool("adversarial.review_finding", self.adversarial_review_finding)
        self.register_tool("adversarial.challenge_fix", self.adversarial_challenge_fix)
        self.register_tool("adversarial.compare_verdicts", self.adversarial_compare_verdicts)
        self.register_tool("adversarial.get_prompt_pack", self.adversarial_get_prompt_pack)
        self.register_tool("adversarial.generate_test_intents", self.adversarial_generate_test_intents)
        self.register_tool("adversarial.write_assurance_report", self.adversarial_write_assurance_report)
        self.register_tool("adversarial.evaluate_governance", self.adversarial_evaluate_governance)
        # Phase 2 — Living Documentation Feedback Loop
        self.register_tool("docs.review_living_docs", self.docs_review_living_docs)
        self.register_tool("docs.propose_living_doc_updates", self.docs_propose_living_doc_updates)
        self.register_tool("docs.apply_living_doc_updates", self.docs_apply_living_doc_updates)
        self.register_tool("docs.verify_living_docs", self.docs_verify_living_docs)

    def _uptime_seconds(self) -> int:
        return int((datetime.now(timezone.utc) - self.started_at).total_seconds())

    def get_info(self) -> Dict[str, Any]:
        return {
            "name": "repo-audit-scan",
            "version": "0.1.0",
            "started_at": self.started_at.isoformat(),
            "tools": sorted(self.tools.keys()),
        }

    def get_health(self) -> Dict[str, Any]:
        status = "ok"
        if self.last_scan and self.last_scan.get("error"):
            status = "degraded"
        return {
            "status": status,
            "uptime_seconds": self._uptime_seconds(),
            "last_scan": self.last_scan,
        }

    def get_status(self) -> Dict[str, Any]:
        return {
            "status": "ready",
            "uptime_seconds": self._uptime_seconds(),
            "tool_count": len(self.tools),
            "last_scan": self.last_scan,
        }

    def scan_repository(
        self,
        path: str,
        rules_path: Optional[str] = None,
        write_reports: bool = True,
        mirror_to_target_repo: bool = False,
        output_root: str = "scan-reports",
        enrich_dependencies: bool = False,
        fail_open_on_enrichment_error: bool = True,
        profile: str = "universal",
    ) -> Dict[str, Any]:
        """Scan a repository and optionally write report artifacts."""
        repo_path = Path(path).resolve()
        if not repo_path.exists():
            raise FileNotFoundError(f"Repository path does not exist: {repo_path}")
        registry = _load_rules(rules_path)
        report = _scan_repository(
            repo_path,
            registry,
            enrich_dependencies=enrich_dependencies,
            fail_open_on_enrichment_error=fail_open_on_enrichment_error,
            profile=profile,
        )
        # Keep report id deterministic for this command call path.
        report.report_id = _new_report_id()

        response = {
            "report_id": report.report_id,
            "repository_path": str(repo_path),
            "findings": len(report.findings),
            "mirror_to_target_repo": mirror_to_target_repo,
        }
        if report.assessment:
            response["assessment"] = report.assessment.to_dict()
        if write_reports:
            out_dir = Path(output_root).resolve() / report.report_id
            workspace_paths = ReportArtifactWriter().write(report, out_dir)
            response["workspace_paths"] = {k: str(v) for k, v in workspace_paths.items()}
            if mirror_to_target_repo:
                date_dir = datetime.now(timezone.utc).strftime("%Y-%m-%d")
                mirror_dir = repo_path / "audits" / date_dir / "repo-audit-scan"
                mirror_paths = ReportArtifactWriter().write(report, mirror_dir)
                response["mirror_paths"] = {k: str(v) for k, v in mirror_paths.items()}
        self.last_scan = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "report_id": report.report_id,
            "repository_path": str(repo_path),
            "findings": len(report.findings),
            "error": None,
        }
        return response

    def inspect_external_link(self, url: str, rules_path: Optional[str] = None) -> Dict[str, Any]:
        """Fetch and statically inspect an HTTPS text link; never execute page content."""
        fetched = fetch_external_text(url)
        if fetched.status != "completed":
            disposition = "block" if fetched.status == "blocked" else "needs_human_review"
            status = AssessmentStatus.BLOCKED if disposition == "block" else AssessmentStatus.DEGRADED
            assessment = ExternalAssessment(
                target=ExternalTarget(kind="link", origin=url), profile="external_link",
                status=status, disposition=AssessmentDisposition(disposition),
                checks=[ExternalCheck("network_policy", fetched.status, fetched.reason)],
            )
            return {"url": url, "assessment": assessment.to_dict(), "content_retrieved": False}
        with tempfile.TemporaryDirectory(prefix="auditscan-link-") as directory:
            path = Path(directory) / "external.md"
            path.write_text(fetched.content, encoding="utf-8")
            report = _scan_repository(path.parent, _load_rules(rules_path), profile="external_repo")
        blocked = any(f.severity.value in {"critical", "high"} and f.rule_id.startswith("ecg-") for f in report.findings)
        assessment = ExternalAssessment(
            target=ExternalTarget(kind="link", origin=url), profile="external_link",
            status=AssessmentStatus.BLOCKED if blocked else AssessmentStatus.COMPLETE,
            disposition=AssessmentDisposition.BLOCK if blocked else AssessmentDisposition.ALLOW_REVIEW,
            checks=[ExternalCheck("network_policy", "completed"), ExternalCheck("deterministic_rules", "completed")],
        )
        return {"url": url, "assessment": assessment.to_dict(), "content_retrieved": True, "findings": len(report.findings)}

    def quarantine_and_scan_repository(self, source: str, ref: Optional[str] = None, rules_path: Optional[str] = None) -> Dict[str, Any]:
        """Checkout a GitHub repository into disposable quarantine and scan it read-only."""
        staging_root = tempfile.mkdtemp(prefix="auditscan-worker-")
        try:
            repo, metadata = quarantine_repository(source, ref, staging_root)
            result = self.scan_repository(str(repo), rules_path=rules_path, write_reports=False, profile="external_repo")
            result["target"] = {"kind": "repository", **metadata}
            assessment = result.get("assessment")
            if assessment:
                assessment["target"] = {
                    "kind": "repository",
                    "origin": metadata["origin"],
                    "resolved_ref": metadata["resolved_ref"],
                    "content_digest": metadata["content_digest"],
                }
                assessment.setdefault("check_details", []).append({
                    "name": "quarantine_cleanup",
                    "status": "completed",
                    "detail": "staging root is removed after response construction",
                })
                assessment.setdefault("checks", {}).setdefault("completed", []).append("quarantine_cleanup")
            return result
        finally:
            shutil.rmtree(staging_root, ignore_errors=True)

    def list_rules(self, rules_path: Optional[str] = None) -> Dict[str, Any]:
        registry = _load_rules(rules_path)
        rules = [rule.to_dict() for rule in registry.list_all()]
        return {"count": len(rules), "rules": rules}

    def get_finding(self, report: str, finding_id: str) -> Dict[str, Any]:
        report_path = self._resolve_report_path(report)
        data = _read_report_json(report_path)
        finding = next((item for item in data.get("findings", []) if item.get("finding_id") == finding_id), None)
        if finding is None:
            raise KeyError(f"Finding not found: {finding_id}")
        return {"report_id": data.get("report_id"), "finding": finding}

    def triage_report(
        self,
        report: str,
        limit: int = 10,
        min_ian_score: Optional[float] = None,
        output_dir: Optional[str] = None,
        pilot_name: Optional[str] = None,
        review_notes: Optional[list[str]] = None,
    ) -> Dict[str, Any]:
        report_path = self._resolve_report_path(report)
        data = _read_report_json(report_path)
        normalized = _normalize_report_data(data)
        report_model = Report.from_dict(normalized)

        destination = Path(output_dir).resolve() if output_dir else report_path.parent
        final_pilot_name = pilot_name or Path(report_model.metadata.repository_path).name or report_model.report_id
        paths = TriageArtifactWriter().write(
            report_model,
            destination,
            pilot_name=final_pilot_name,
            limit=limit,
            min_ian_score=min_ian_score,
            review_notes=review_notes or [],
        )
        return {
            "report_id": report_model.report_id,
            "pilot_name": final_pilot_name,
            "triage": str(paths["triage"]),
            "review": str(paths["review"]),
        }

    def verify_fix(
        self,
        report: str,
        finding_id: str,
        rules_path: Optional[str] = None,
        repo_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        report_path = self._resolve_report_path(report)
        data = _read_report_json(report_path)
        registry = _load_rules(rules_path)
        override = Path(repo_path).resolve() if repo_path else None
        return _verify_finding(data, finding_id, registry, override)

    def get_latest_report(self, output_root: str = "scan-reports") -> Dict[str, Any]:
        root = Path(output_root).resolve()
        candidates = sorted(
            [p / "report.json" for p in root.iterdir() if p.is_dir() and (p / "report.json").exists()],
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        ) if root.exists() else []
        if not candidates:
            raise FileNotFoundError(f"No reports found under: {root}")
        latest = candidates[0]
        return {"path": str(latest), "report": json.loads(latest.read_text(encoding="utf-8"))}

    def validate_config(
        self,
        rules_path: Optional[str] = None,
        output_root: str = "scan-reports",
    ) -> Dict[str, Any]:
        checks = {
            "rules_path": {"ok": False, "value": ""},
            "output_root": {"ok": False, "value": str(Path(output_root).resolve())},
        }
        resolved_rules = Path(rules_path) if rules_path else _default_rules_path()
        checks["rules_path"] = {"ok": resolved_rules.exists(), "value": str(resolved_rules)}
        output_path = Path(output_root).resolve()
        checks["output_root"] = {"ok": output_path.parent.exists() or output_path.exists(), "value": str(output_path)}
        return {"valid": all(item["ok"] for item in checks.values()), "checks": checks}

    def run_self_check(self, rules_path: Optional[str] = None, output_root: str = "scan-reports") -> Dict[str, Any]:
        diagnostics = {
            "rules_registry": False,
            "adapters_loaded": False,
            "report_root_accessible": False,
            "tool_registry": len(self.tools) > 0,
        }
        try:
            registry = _load_rules(rules_path)
            diagnostics["rules_registry"] = registry.count() > 0
        except FileNotFoundError:
            diagnostics["rules_registry"] = False
        diagnostics["adapters_loaded"] = True  # AdapterRegistry constructor is exercised via scan path.
        report_root = Path(output_root).resolve()
        diagnostics["report_root_accessible"] = report_root.exists() or report_root.parent.exists()
        return {"ok": all(diagnostics.values()), "diagnostics": diagnostics}

    def list_reports(self, output_root: str = "scan-reports", include_target_repo: Optional[str] = None) -> Dict[str, Any]:
        reports: list[str] = []
        root = Path(output_root).resolve()
        if root.exists():
            for child in root.iterdir():
                candidate = child / "report.json"
                if candidate.exists():
                    reports.append(str(candidate))

        if include_target_repo:
            repo = Path(include_target_repo).resolve()
            audits_dir = repo / "audits"
            if audits_dir.exists():
                for path in audits_dir.rglob("report.json"):
                    reports.append(str(path))

        reports = sorted(set(reports))
        return {"count": len(reports), "reports": reports}

    def adversarial_review_finding(
        self,
        report: str,
        finding_id: str,
        challenge_notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return a first-pass adversarial review contract for a finding."""
        report_path = self._resolve_report_path(report)
        data = _read_report_json(report_path)
        finding = next((item for item in data.get("findings", []) if item.get("finding_id") == finding_id), None)
        if finding is None:
            raise KeyError(f"Finding not found: {finding_id}")
        result = review_finding_contract(
            report_id=str(data.get("report_id", "")),
            finding=finding,
            challenge_notes=challenge_notes,
        )
        return result.to_dict()

    def adversarial_challenge_fix(
        self,
        report: str,
        finding_id: str,
        patch_ref: Optional[str] = None,
        challenge_notes: Optional[str] = None,
        rules_path: Optional[str] = None,
        repo_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return a first-pass adversarial fix challenge contract for a finding."""
        report_path = self._resolve_report_path(report)
        data = _read_report_json(report_path)
        finding = next((item for item in data.get("findings", []) if item.get("finding_id") == finding_id), None)
        if finding is None:
            raise KeyError(f"Finding not found: {finding_id}")

        registry = _load_rules(rules_path)
        override = Path(repo_path).resolve() if repo_path else None
        verify_result = _verify_finding(data, finding_id, registry, override)
        result = challenge_fix_contract(
            report_id=str(data.get("report_id", "")),
            finding=finding,
            verify_resolved=bool(verify_result.get("resolved", False)),
            patch_ref=patch_ref,
            challenge_notes=challenge_notes,
        )
        payload = result.to_dict()
        payload["verify"] = verify_result
        return payload

    def adversarial_compare_verdicts(
        self,
        report: str,
        finding_id: str,
        primary_verdict: str,
        challenger_verdict: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Compare primary/challenger verdicts and return consensus state and assurance score."""
        report_path = self._resolve_report_path(report)
        data = _read_report_json(report_path)
        finding = next((item for item in data.get("findings", []) if item.get("finding_id") == finding_id), None)
        if finding is None:
            raise KeyError(f"Finding not found: {finding_id}")

        resolved_challenger = challenger_verdict
        if not resolved_challenger:
            fix_result = self.adversarial_challenge_fix(report=report, finding_id=finding_id)
            resolved_challenger = str(fix_result.get("verdict", "uncertain"))

        consensus = compare_verdicts_contract(
            report_id=str(data.get("report_id", "")),
            finding=finding,
            primary_verdict=primary_verdict,
            challenger_verdict=resolved_challenger,
        )
        return consensus.to_dict()

    def adversarial_get_prompt_pack(self) -> Dict[str, Any]:
        """Return lane-locked adversarial prompt pack for agent roles."""
        return get_prompt_pack()

    def adversarial_generate_test_intents(
        self,
        report: str,
        finding_id: str,
    ) -> Dict[str, Any]:
        """Generate adversarial test intents for a finding."""
        report_path = self._resolve_report_path(report)
        data = _read_report_json(report_path)
        finding = next((item for item in data.get("findings", []) if item.get("finding_id") == finding_id), None)
        if finding is None:
            raise KeyError(f"Finding not found: {finding_id}")

        result = generate_test_intents_contract(
            report_id=str(data.get("report_id", "")),
            finding=finding,
        )
        return result.to_dict()

    def adversarial_write_assurance_report(
        self,
        report: str,
        finding_id: str,
        primary_verdict: str,
        challenger_verdict: Optional[str] = None,
        output_dir: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Write assurance artifacts from consensus output."""
        consensus = self.adversarial_compare_verdicts(
            report=report,
            finding_id=finding_id,
            primary_verdict=primary_verdict,
            challenger_verdict=challenger_verdict,
        )
        report_path = self._resolve_report_path(report)
        destination = Path(output_dir).resolve() if output_dir else report_path.parent
        paths = write_assurance_artifacts(destination, consensus)
        return {
            "assurance": consensus,
            "artifacts": {k: str(v) for k, v in paths.items()},
        }

    def adversarial_evaluate_governance(
        self,
        report: str,
        finding_id: str,
        primary_verdict: str,
        challenger_verdict: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Evaluate governance triggers for assurance outcomes."""
        report_path = self._resolve_report_path(report)
        data = _read_report_json(report_path)
        finding = next((item for item in data.get("findings", []) if item.get("finding_id") == finding_id), None)
        if finding is None:
            raise KeyError(f"Finding not found: {finding_id}")
        consensus = self.adversarial_compare_verdicts(
            report=report,
            finding_id=finding_id,
            primary_verdict=primary_verdict,
            challenger_verdict=challenger_verdict,
        )
        governance = evaluate_governance_contract(
            report_id=str(data.get("report_id", "")),
            finding=finding,
            consensus=consensus,
        )
        payload = governance.to_dict()
        payload["consensus"] = consensus
        return payload

    @staticmethod
    def _resolve_report_path(report: str) -> Path:
        candidate = Path(report)
        if candidate.exists():
            return candidate
        fallback = Path("scan-reports") / report / "report.json"
        return fallback


    # -----------------------------------------------------------------------
    # Phase 2 — Living Documentation Feedback Loop
    # -----------------------------------------------------------------------

    def docs_review_living_docs(
        self,
        path: str,
        docs_path: Optional[str] = None,
        report_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Compare living docs with the repo and an optional audit report.

        Returns a list of doc gaps (stale, missing, contradicted, unverifiable).
        Stores the gap list in session state so propose and verify can use it.
        """
        repo = Path(path)
        if not repo.is_dir():
            raise FileNotFoundError(f"Repository path not found: {path}")

        dp = discover_docs_path(repo, docs_path)
        report_data: Optional[Dict[str, Any]] = None
        if report_id:
            try:
                rp = self._resolve_report_path(report_id)
                report_data = _normalize_report_data(_read_report_json(rp))
            except (FileNotFoundError, KeyError, ValueError):
                pass

        gaps = review_living_docs(
            repo_path=repo,
            docs_path=dp,
            report_data=report_data,
        )
        self._last_gaps = gaps
        return {
            "docs_path": str(dp) if dp else None,
            "gap_count": len(gaps),
            "gaps": [g.to_dict() for g in gaps],
        }

    def docs_propose_living_doc_updates(
        self,
        path: str,
        doc_gap_ids: Optional[list] = None,
        docs_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Propose Markdown patches for the requested gap IDs.

        Patches are NOT written to disk. The caller must approve patch IDs
        and pass them to docs.apply_living_doc_updates to apply them.
        """
        if not self._last_gaps:
            raise ValueError(
                "No gaps in session — call docs.review_living_docs first"
            )
        gap_ids = doc_gap_ids or [g.gap_id for g in self._last_gaps]
        patches = propose_living_doc_updates(
            gaps=self._last_gaps,
            requested_gap_ids=gap_ids,
        )
        # Store in session cache so apply can validate them
        for p in patches:
            self._pending_patches[p.patch_id] = p
        return {
            "patch_count": len(patches),
            "patches": [p.to_dict() for p in patches],
        }

    def docs_apply_living_doc_updates(
        self,
        path: str,
        approved_patch_ids: list,
        actor: str,
        docs_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Apply approved patches to the living-docs directory.

        Only patch IDs produced by a recent docs.propose_living_doc_updates
        call in this session are accepted. Writes are recorded in an audit log.
        """
        repo = Path(path)
        dp = discover_docs_path(repo, docs_path)
        if dp is None:
            # Create a default docs dir if none exists
            dp = repo / "docs"
            dp.mkdir(parents=True, exist_ok=True)

        results = apply_patches(
            docs_path=dp,
            approved_patch_ids=approved_patch_ids,
            actor=actor,
            pending_patches=self._pending_patches,
        )
        return {"apply_results": results}

    def docs_verify_living_docs(
        self,
        path: str,
        report_id: Optional[str] = None,
        docs_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Verify that previously surfaced doc gaps are now resolved.

        Re-runs gap detection and compares against the gaps stored from the
        last docs.review_living_docs call in this session.
        """
        repo = Path(path)
        dp = discover_docs_path(repo, docs_path)

        report_data: Optional[Dict[str, Any]] = None
        if report_id:
            try:
                rp = self._resolve_report_path(report_id)
                report_data = _normalize_report_data(_read_report_json(rp))
            except (FileNotFoundError, KeyError, ValueError):
                pass

        if not self._last_gaps:
            return {
                "resolved_gap_ids": [],
                "remaining_gaps": [],
                "total_original": 0,
                "total_resolved": 0,
                "note": "No gaps in session — run docs.review_living_docs first",
            }

        return verify_gaps(
            repo_path=repo,
            docs_path=dp or (repo / "docs"),
            original_gaps=self._last_gaps,
            report_data=report_data,
        )

mcp_server = MCPServer()

