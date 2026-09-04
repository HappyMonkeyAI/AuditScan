"""Tests for deterministic external-content rules."""

from pathlib import Path

from repo_audit_scan.adapter_registry import AdapterRegistry
from repo_audit_scan.adapters_final import ScanContext
from repo_audit_scan.cli import _load_rules


FIXTURES = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "external_content"


def _scan_file(path: Path):
    registry = _load_rules(None)
    adapter_registry = AdapterRegistry()
    adapter = adapter_registry.resolve_adapter(str(path))
    assert adapter is not None, path
    context = ScanContext(
        file_path=path.relative_to(FIXTURES).as_posix(),
        file_content=path.read_text(encoding="utf-8"),
        language=adapter.language,
    )
    results = []
    for rule in registry.list_all():
        if adapter.supports_rule(rule):
            results.extend(adapter.scan(context, rule))
    return results


def test_external_rules_cover_prompt_memory_manifest_and_lifecycle_surfaces():
    hostile = FIXTURES / "hostile_repo"
    findings = []
    for name in ("README.md", "package.json", "mcp.json"):
        findings.extend(_scan_file(hostile / name))

    rule_ids = {finding.rule_id for finding in findings}
    assert {"ecg-001", "ecg-002", "ecg-003", "ecg-004", "ecg-005", "ecg-006"} <= rule_ids
    assert all(result.evidence for result in findings)


def test_external_rules_do_not_flag_ordinary_threejs_readme_or_package():
    benign = FIXTURES / "benign_threejs_repo"
    findings = []
    for name in ("README.md", "package.json"):
        findings.extend(_scan_file(benign / name))

    assert findings == []


def test_external_content_adapter_claims_only_external_content_files():
    registry = AdapterRegistry()
    assert registry.resolve_language("README.md") == "external-content"
    assert registry.resolve_language("mcp.json") == "external-content"
    assert registry.resolve_language("package.json") == "external-content"
    assert registry.resolve_language("app.py") == "python"


def test_external_rule_checks_are_regex_only_and_do_not_execute_content():
    registry = _load_rules(None)
    external = [rule for rule in registry.list_all() if rule.rule_id.startswith("ecg-")]
    assert len(external) == 6
    assert all(check["type"] == "regex" for rule in external for check in rule.checks)
