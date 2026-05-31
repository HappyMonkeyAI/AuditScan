"""Tests for MCP server tool handlers."""

from __future__ import annotations

from pathlib import Path

from repo_audit_scan.mcp_server import MCPServer


def test_mcp_server_registers_default_tools():
    """Default MCP tool surface should be available."""
    server = MCPServer()
    tools = server.list_tools()

    assert "scan_repository" in tools
    assert "server.get_info" in tools
    assert "server.get_health" in tools
    assert "server.get_status" in tools
    assert "list_rules" in tools
    assert "get_finding" in tools
    assert "triage_report" in tools
    assert "verify_fix" in tools
    assert "get_latest_report" in tools
    assert "diagnostics.validate_config" in tools
    assert "diagnostics.run_self_check" in tools
    assert "reports.list_reports" in tools
    assert "adversarial.review_finding" in tools
    assert "adversarial.challenge_fix" in tools
    assert "adversarial.compare_verdicts" in tools


def test_scan_and_triage_and_verify_flow(tmp_path):
    """MCP flow should produce reports, triage files, and verification output."""
    server = MCPServer()
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.js").write_text("panel.innerHTML = userInput;\n", encoding="utf-8")
    output_root = tmp_path / "reports"

    scan = server.scan_repository(
        path=str(repo),
        write_reports=True,
        mirror_to_target_repo=False,
        output_root=str(output_root),
    )
    report_id = scan["report_id"]
    report_json = Path(scan["workspace_paths"]["json"])
    assert report_json.exists()

    # Triage should consume the written report and emit artifacts.
    triage = server.triage_report(
        report=str(report_json),
        limit=1,
        output_dir=str(tmp_path / "triage"),
        pilot_name="mcp-pilot",
        review_notes=["pilot note"],
    )
    assert Path(triage["triage"]).exists()
    assert Path(triage["review"]).exists()

    # Fix file then verify.
    (repo / "app.js").write_text("panel.textContent = userInput;\n", encoding="utf-8")
    latest = server.get_latest_report(output_root=str(output_root))
    first_finding_id = latest["report"]["findings"][0]["finding_id"]
    verify = server.verify_fix(
        report=str(report_json),
        finding_id=first_finding_id,
    )
    assert verify["resolved"] is True
    assert verify["remaining_locations"] == []

    # get_finding should return the finding payload.
    found = server.get_finding(str(report_json), first_finding_id)
    assert found["report_id"] == report_id
    assert found["finding"]["finding_id"] == first_finding_id


def test_scan_repository_respects_workspace_only_default(tmp_path):
    """MCP scan should avoid target-repo mirroring unless explicitly requested."""
    server = MCPServer()
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text('api_key = "sk-test-1234"\n', encoding="utf-8")
    output_root = tmp_path / "reports"

    result = server.scan_repository(
        path=str(repo),
        write_reports=True,
        mirror_to_target_repo=False,
        output_root=str(output_root),
    )
    assert "workspace_paths" in result
    assert "mirror_paths" not in result


def test_operational_handlers_return_expected_shapes(tmp_path):
    """Operational handlers should expose info, health, status, diagnostics, and reports list."""
    server = MCPServer()
    info = server.get_info()
    assert info["name"] == "repo-audit-scan"
    assert "tools" in info

    health = server.get_health()
    assert health["status"] in {"ok", "degraded"}
    assert isinstance(health["uptime_seconds"], int)

    status = server.get_status()
    assert status["status"] == "ready"
    assert status["tool_count"] >= 1

    validate = server.validate_config(output_root=str(tmp_path / "reports"))
    assert "valid" in validate
    assert "checks" in validate

    self_check = server.run_self_check(output_root=str(tmp_path / "reports"))
    assert "ok" in self_check
    assert "diagnostics" in self_check

    listed = server.list_reports(output_root=str(tmp_path / "reports"))
    assert listed["count"] == 0
    assert listed["reports"] == []


def test_scan_repository_with_dependency_enrichment_flag_is_fail_open(tmp_path, monkeypatch):
    """MCP scan should still succeed when enrichment is enabled and network is unavailable."""
    server = MCPServer()
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("requests==2.20.0\n", encoding="utf-8")
    monkeypatch.setenv("REPO_AUDIT_DEP_ENRICHMENT", "true")

    result = server.scan_repository(
        path=str(repo),
        write_reports=False,
        enrich_dependencies=True,
        fail_open_on_enrichment_error=True,
    )
    assert result["findings"] >= 1


def test_mcp_verify_dependency_finding_uses_snippet_fallback(tmp_path):
    """MCP verify_fix should re-check non-adapter evidence snippets for dependency findings."""
    from repo_audit_scan.models import Confidence, Evidence, Finding, Report, ScanMetadata, Severity
    from repo_audit_scan.reporting import JSONReportWriter

    server = MCPServer()
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
    report_path = tmp_path / "report.json"
    report_path.write_text(JSONReportWriter().to_json(report), encoding="utf-8")

    unresolved = server.verify_fix(report=str(report_path), finding_id="finding-dep-001")
    assert unresolved["resolved"] is False
    assert unresolved["remaining_locations"] == ["requirements.txt:1"]

    req.write_text("requests==2.32.0\n", encoding="utf-8")
    resolved = server.verify_fix(report=str(report_path), finding_id="finding-dep-001")
    assert resolved["resolved"] is True


def test_mcp_verify_blocks_path_traversal_in_evidence(tmp_path):
    """MCP verify_fix must block evidence paths that escape repository root."""
    from repo_audit_scan.models import Confidence, Evidence, Finding, Report, ScanMetadata, Severity
    from repo_audit_scan.reporting import JSONReportWriter

    server = MCPServer()
    repo = tmp_path / "repo"
    repo.mkdir()

    metadata = ScanMetadata(
        schema_version="1.0",
        tool_version="0.1.0",
        scan_timestamp="2026-05-28T00:00:00Z",
        repository_path=str(repo),
        scanned_files_count=0,
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
    report_path = tmp_path / "report.json"
    report_path.write_text(JSONReportWriter().to_json(report), encoding="utf-8")

    result = server.verify_fix(report=str(report_path), finding_id="finding-path-001")
    assert result["resolved"] is False
    assert result["remaining_locations"] == ["../outside.py:blocked_path"]


def test_adversarial_review_finding_contract(tmp_path):
    """Adversarial finding review should return structured contract fields."""
    from repo_audit_scan.models import Confidence, Evidence, Finding, Report, ScanMetadata, Severity
    from repo_audit_scan.reporting import JSONReportWriter

    server = MCPServer()
    repo = tmp_path / "repo"
    repo.mkdir()
    metadata = ScanMetadata(
        schema_version="1.0",
        tool_version="0.1.0",
        scan_timestamp="2026-05-31T09:00:00Z",
        repository_path=str(repo),
        scanned_files_count=1,
        skipped_files_count=0,
    )
    finding = Finding(
        finding_id="finding-adv-001",
        rule_id="js-002",
        rule_title="DOM-based XSS",
        category="xss",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        evidence=[
            Evidence(file_path="app.js", line_number=1, code_snippet="element.innerHTML = userInput"),
            Evidence(file_path="app.js", line_number=2, code_snippet="render(userInput)"),
        ],
        remediation_guidance="Use textContent and sanitize input.",
    )
    report = Report(report_id="adv-report-001", metadata=metadata, findings=[finding], summary="adv test")
    report_path = tmp_path / "report.json"
    report_path.write_text(JSONReportWriter().to_json(report), encoding="utf-8")

    result = server.adversarial_review_finding(
        report=str(report_path),
        finding_id="finding-adv-001",
        challenge_notes="probe DOM sink bypass via encoded payloads",
    )
    assert result["report_id"] == "adv-report-001"
    assert result["finding_id"] == "finding-adv-001"
    assert result["verdict"] in {"support", "challenge", "uncertain"}
    assert isinstance(result["confidence_delta"], int)
    assert isinstance(result["evidence_delta"], list)
    assert result["recommended_action"] in {"accept", "retest", "escalate_human"}


def test_adversarial_challenge_fix_contract(tmp_path):
    """Adversarial fix challenge should include verify payload and challenger verdict."""
    from repo_audit_scan.models import Confidence, Evidence, Finding, Report, ScanMetadata, Severity
    from repo_audit_scan.reporting import JSONReportWriter

    server = MCPServer()
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.js"
    app.write_text("panel.innerHTML = userInput;\n", encoding="utf-8")

    metadata = ScanMetadata(
        schema_version="1.0",
        tool_version="0.1.0",
        scan_timestamp="2026-05-31T09:15:00Z",
        repository_path=str(repo),
        scanned_files_count=1,
        skipped_files_count=0,
    )
    finding = Finding(
        finding_id="finding-adv-fix-001",
        rule_id="js-002",
        rule_title="DOM-based XSS",
        category="xss",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        evidence=[Evidence(file_path="app.js", line_number=1, code_snippet="panel.innerHTML = userInput;")],
        remediation_guidance="Use textContent and sanitize input.",
    )
    report = Report(report_id="adv-fix-report-001", metadata=metadata, findings=[finding], summary="adv fix test")
    report_path = tmp_path / "report.json"
    report_path.write_text(JSONReportWriter().to_json(report), encoding="utf-8")

    unresolved = server.adversarial_challenge_fix(
        report=str(report_path),
        finding_id="finding-adv-fix-001",
        patch_ref="abc123",
        challenge_notes="attempted encoded payload bypass",
    )
    assert unresolved["report_id"] == "adv-fix-report-001"
    assert unresolved["finding_id"] == "finding-adv-fix-001"
    assert unresolved["patch_ref"] == "abc123"
    assert unresolved["verify"]["resolved"] is False
    assert unresolved["verdict"] in {"challenge", "uncertain", "support"}
    assert unresolved["recommended_action"] in {"accept", "retest", "escalate_human"}

    app.write_text("panel.textContent = userInput;\n", encoding="utf-8")
    resolved = server.adversarial_challenge_fix(
        report=str(report_path),
        finding_id="finding-adv-fix-001",
        patch_ref="def456",
    )
    assert resolved["verify"]["resolved"] is True
    assert resolved["verdict"] == "support"


def test_adversarial_compare_verdicts_contract(tmp_path):
    """Consensus tool should return assurance score and consensus state."""
    from repo_audit_scan.models import Confidence, Evidence, Finding, Report, ScanMetadata, Severity
    from repo_audit_scan.reporting import JSONReportWriter

    server = MCPServer()
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.js"
    app.write_text("panel.textContent = userInput;\n", encoding="utf-8")

    metadata = ScanMetadata(
        schema_version="1.0",
        tool_version="0.1.0",
        scan_timestamp="2026-05-31T10:00:00Z",
        repository_path=str(repo),
        scanned_files_count=1,
        skipped_files_count=0,
    )
    finding = Finding(
        finding_id="finding-adv-consensus-001",
        rule_id="js-002",
        rule_title="DOM-based XSS",
        category="xss",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        evidence=[Evidence(file_path="app.js", line_number=1, code_snippet="panel.innerHTML = userInput;")],
        remediation_guidance="Use textContent and sanitize input.",
    )
    report = Report(report_id="adv-consensus-report-001", metadata=metadata, findings=[finding], summary="consensus test")
    report_path = tmp_path / "report.json"
    report_path.write_text(JSONReportWriter().to_json(report), encoding="utf-8")

    explicit = server.adversarial_compare_verdicts(
        report=str(report_path),
        finding_id="finding-adv-consensus-001",
        primary_verdict="resolved",
        challenger_verdict="support",
    )
    assert explicit["consensus_state"] == "agree"
    assert explicit["assurance_score"] >= 80
    assert explicit["recommended_action"] == "close"

    auto = server.adversarial_compare_verdicts(
        report=str(report_path),
        finding_id="finding-adv-consensus-001",
        primary_verdict="resolved",
    )
    assert auto["consensus_state"] in {"agree", "contested"}
    assert isinstance(auto["assurance_score"], int)
