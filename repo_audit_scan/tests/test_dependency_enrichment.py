"""Tests for dependency lockfile scanning and enrichment behavior."""

from __future__ import annotations

from pathlib import Path

from repo_audit_scan import dependency_enrichment
from repo_audit_scan.cli import _load_rules, _scan_repository


def test_lockfile_only_dependency_finding_without_network(tmp_path):
    """Default scan should emit dependency findings from local lockfiles only."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("requests==2.20.0\n", encoding="utf-8")
    (repo / "app.py").write_text("value = 1\n", encoding="utf-8")

    registry = _load_rules(None)
    report = _scan_repository(repo, registry)

    dependency_findings = [f for f in report.findings if f.category == "dependency"]
    assert dependency_findings
    assert any(item.rule_id == "general-001" for item in dependency_findings)
    assert any(item.evidence and "lockfile-only" in (item.evidence[0].context or "") for item in dependency_findings)


def test_enrichment_fail_open_keeps_scan_successful(tmp_path, monkeypatch):
    """When enrichment is requested but fails, scan should still complete in fail-open mode."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("requests==2.20.0\n", encoding="utf-8")

    monkeypatch.setenv("REPO_AUDIT_DEP_ENRICHMENT", "true")
    monkeypatch.setattr(
        dependency_enrichment,
        "_default_enrichment_provider",
        lambda _packages: (_ for _ in ()).throw(RuntimeError("simulated enrichment failure")),
    )

    registry = _load_rules(None)
    report = _scan_repository(
        repo,
        registry,
        enrich_dependencies=True,
        fail_open_on_enrichment_error=True,
    )

    dependency_findings = [f for f in report.findings if f.category == "dependency"]
    assert dependency_findings
    assert "mode=lockfile-only" in (report.summary or "")
