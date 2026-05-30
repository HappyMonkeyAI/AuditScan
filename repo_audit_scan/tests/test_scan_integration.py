"""End-to-end scan integration tests (T-019).

Exercises the full `_scan_repository` pipeline (inventory -> adapter resolution
-> rules -> IAN scoring -> Report) over committed fixture repositories, rather
than driving adapters in isolation. Covers SPEC §16 Scenario #1 (clean repo =>
zero findings) and a multi-adapter polyglot scan, including path-based CI/CD
detection that unit tests cannot exercise.
"""

from pathlib import Path

from repo_audit_scan.cli import _scan_repository, _load_rules

FIXTURES = Path(__file__).resolve().parents[2] / "tests" / "fixtures"


def _scan(repo_name):
    registry = _load_rules(None)  # bundled rule set
    return _scan_repository(FIXTURES / repo_name, registry)


def test_clean_repo_produces_zero_findings():
    """SPEC §16 #1: a clean polyglot repo yields no findings end-to-end."""
    report = _scan("generic_clean_repo")
    assert report.findings == []
    assert report.metadata.scanned_files_count > 0  # files were actually walked


def test_mixed_vulnerable_repo_spans_all_adapters():
    """The polyglot vulnerable repo yields findings from every MVP adapter."""
    report = _scan("mixed_vulnerable_repo")
    rule_ids = {f.rule_id for f in report.findings}

    # PHP/WordPress
    assert "wp-ajax-001" in rule_ids
    assert "php-002" in rule_ids
    # Python
    assert {"py-006", "py-007"} & rule_ids
    # JavaScript/TypeScript
    assert {"js-004", "js-006"} & rule_ids
    # CI/CD (path-based detection through the real walker)
    assert {"cicd-001", "cicd-006"} <= rule_ids

    categories = {f.category for f in report.findings}
    assert {"ci-cd", "injection", "access-control"} <= categories


def test_findings_are_scored_and_identified():
    """Every finding carries a positive IAN score and a stable id."""
    report = _scan("mixed_vulnerable_repo")
    assert report.findings
    for f in report.findings:
        assert f.ian_score is not None and f.ian_score > 0
        assert f.finding_id.startswith("finding-")
        assert f.evidence  # at least one evidence entry


def test_docker_secret_rule_does_not_flag_env_var_reads():
    """Regression (dogfooding on LLM-Codex-Reference-Vault): docker-001 must not
    fire on secure `os.getenv("X_API_KEY")` usage, but must still flag a
    hardcoded Dockerfile ENV/ARG secret assignment."""
    from repo_audit_scan.adapters_final import PythonAdapter, ScanContext

    registry = _load_rules(None)
    docker_rule = registry.get_by_id("docker-001")
    adapter = PythonAdapter()

    secure = ScanContext(
        file_path="ingest.py",
        file_content='DEVTO_API_KEY = os.getenv("DEVTO_APIKEY")\nif not DEVTO_API_KEY:\n    raise SystemExit(1)\n',
        language="python",
    )
    assert adapter.scan(secure, docker_rule) == []

    # A genuine hardcoded secret assignment still matches the rule's pattern.
    import re
    pattern = docker_rule.checks[0]["pattern"]
    assert re.search(pattern, "ENV DB_PASSWORD=supersecretvalue")
    assert not re.search(pattern, "ENV API_KEY=${API_KEY}")  # interpolation, not hardcoded


def test_cicd_workflow_detected_by_path_end_to_end():
    """A workflow under .github/workflows is detected and scored without an
    explicit ScanContext (regression for the CI/CD adapter's path matching)."""
    report = _scan("mixed_vulnerable_repo")
    cicd = [f for f in report.findings if f.rule_id.startswith("cicd-")]
    assert len(cicd) >= 5
    assert all(".github/workflows/" in e.file_path for f in cicd for e in f.evidence)
