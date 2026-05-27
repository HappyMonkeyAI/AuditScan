"""MCP (Model Context Protocol) server for repo-audit-scan."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from repo_audit_scan.cli import (
    _find_rule,
    _load_rules,
    _new_report_id,
    _normalize_report_data,
    _read_report_json,
    _scan_repository,
    _verify_finding,
)
from repo_audit_scan.models import Report
from repo_audit_scan.reporting import JSONReportWriter, ReportArtifactWriter
from repo_audit_scan.triage import TriageArtifactWriter


class MCPServer:
    """Simple MCP-style tool registry and execution wrapper."""

    def __init__(self):
        self.tools: Dict[str, Callable[..., Dict[str, Any]]] = {}
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
        self.register_tool("scan_repository", self.scan_repository)
        self.register_tool("list_rules", self.list_rules)
        self.register_tool("get_finding", self.get_finding)
        self.register_tool("triage_report", self.triage_report)
        self.register_tool("verify_fix", self.verify_fix)
        self.register_tool("get_latest_report", self.get_latest_report)

    def scan_repository(
        self,
        path: str,
        rules_path: Optional[str] = None,
        write_reports: bool = True,
        mirror_to_target_repo: bool = False,
        output_root: str = "scan-reports",
    ) -> Dict[str, Any]:
        """Scan a repository and optionally write report artifacts."""
        repo_path = Path(path).resolve()
        if not repo_path.exists():
            raise FileNotFoundError(f"Repository path does not exist: {repo_path}")
        registry = _load_rules(rules_path)
        report = _scan_repository(repo_path, registry)
        # Keep report id deterministic for this command call path.
        report.report_id = _new_report_id()

        response = {
            "report_id": report.report_id,
            "repository_path": str(repo_path),
            "findings": len(report.findings),
            "mirror_to_target_repo": mirror_to_target_repo,
        }
        if write_reports:
            out_dir = Path(output_root).resolve() / report.report_id
            workspace_paths = ReportArtifactWriter().write(report, out_dir)
            response["workspace_paths"] = {k: str(v) for k, v in workspace_paths.items()}
            if mirror_to_target_repo:
                date_dir = datetime.now(timezone.utc).strftime("%Y-%m-%d")
                mirror_dir = repo_path / "audits" / date_dir / "repo-audit-scan"
                mirror_paths = ReportArtifactWriter().write(report, mirror_dir)
                response["mirror_paths"] = {k: str(v) for k, v in mirror_paths.items()}
        return response

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

    @staticmethod
    def _resolve_report_path(report: str) -> Path:
        candidate = Path(report)
        if candidate.exists():
            return candidate
        fallback = Path("scan-reports") / report / "report.json"
        return fallback


mcp_server = MCPServer()
