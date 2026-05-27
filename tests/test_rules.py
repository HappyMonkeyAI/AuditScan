"""
Tests for rule registry, deduplication, and manual confirmation.
"""

import pytest
from pathlib import Path
from repo_audit_scan.rules import Rule, RuleRegistry, DuplicationHandler, ManualConfirmation
from repo_audit_scan.models import Severity, Evidence, RuleResult


@pytest.fixture
def sample_rules_path():
    """Path to sample rules fixture."""
    return Path(__file__).parent / "fixtures" / "rules" / "sample_rules.json"


@pytest.fixture
def registry(sample_rules_path):
    """Loaded registry with 50+ sample rules."""
    reg = RuleRegistry()
    reg.load_from_file(str(sample_rules_path))
    return reg


class TestRule:
    """Tests for Rule dataclass."""

    def test_rule_creation(self):
        """Rule should be creatable with required fields."""
        rule = Rule(
            rule_id="test-001",
            category="secrets",
            title="Test Rule",
            description="A test rule",
            severity=Severity.HIGH,
        )

        assert rule.rule_id == "test-001"
        assert rule.category == "secrets"
        assert rule.severity == Severity.HIGH

    def test_rule_serialization(self):
        """Rule should serialize to dict."""
        rule = Rule(
            rule_id="test-001",
            category="secrets",
            title="Test Rule",
            description="A test rule",
            severity=Severity.CRITICAL,
            remediation_guidance="Use environment variables",
            requires_manual_confirmation=True,
        )

        data = rule.to_dict()

        assert data["rule_id"] == "test-001"
        assert data["severity"] in ("critical", "CRITICAL")  # Accept either case
        assert data["requires_manual_confirmation"] is True

    def test_rule_deserialization(self):
        """Rule should deserialize from dict."""
        data = {
            "rule_id": "py-001",
            "category": "secrets",
            "title": "API Key",
            "description": "Hardcoded API key",
            "severity": "critical",  # lowercase as per enum
            "checks": [{"type": "regex", "pattern": "api_key"}],
            "remediation_guidance": "Use env vars",
        }

        rule = Rule.from_dict(data)

        assert rule.rule_id == "py-001"
        assert rule.category == "secrets"
        assert rule.severity == Severity.CRITICAL
        assert len(rule.checks) == 1


class TestRuleRegistry:
    """Tests for RuleRegistry."""

    def test_registry_initialization(self):
        """Registry should initialize empty."""
        reg = RuleRegistry()
        assert reg.count() == 0

    def test_add_single_rule(self):
        """Registry should add rules."""
        reg = RuleRegistry()
        rule = Rule(
            rule_id="test-001",
            category="secrets",
            title="Test",
            description="Test rule",
            severity=Severity.HIGH,
        )
        reg.add_rule(rule)

        assert reg.count() == 1
        assert reg.get_by_id("test-001") is not None

    def test_load_from_file(self, sample_rules_path):
        """Registry should load from JSON file."""
        reg = RuleRegistry()
        reg.load_from_file(str(sample_rules_path))

        # Should have loaded 50+ rules
        assert reg.count() >= 50

    def test_get_by_id(self, registry):
        """Registry should retrieve rule by ID."""
        rule = registry.get_by_id("py-001")

        assert rule is not None
        assert rule.rule_id == "py-001"
        assert rule.category == "secrets"

    def test_get_by_nonexistent_id(self, registry):
        """Should return None for nonexistent rule ID."""
        rule = registry.get_by_id("nonexistent-999")
        assert rule is None

    def test_get_by_category(self, registry):
        """Registry should retrieve rules by category."""
        secrets_rules = registry.get_by_category("secrets")

        # Should have multiple secrets rules (py-001, php-001, js-001, aws-001, etc)
        assert len(secrets_rules) >= 5

        # All should be in secrets category
        for rule in secrets_rules:
            assert rule.category == "secrets"

    def test_list_all(self, registry):
        """Registry should list all rules."""
        all_rules = registry.list_all()

        # Should have 50+ rules
        assert len(all_rules) >= 50

        # All should be Rule objects
        for rule in all_rules:
            assert isinstance(rule, Rule)

    def test_categories(self, registry):
        """Registry should list all categories."""
        categories = registry.categories()

        # Should have multiple categories
        assert len(categories) >= 10
        assert "secrets" in categories
        assert "injection" in categories
        assert "authentication" in categories

    def test_registry_serialization(self, registry):
        """Registry should serialize to dict."""
        data = registry.to_dict()

        assert "rules" in data
        assert len(data["rules"]) == registry.count()

    def test_registry_duplicate_rule_id(self):
        """Registry should handle duplicate rule IDs (overwrite)."""
        reg = RuleRegistry()

        rule1 = Rule(
            rule_id="test-001",
            category="secrets",
            title="First version",
            description="First",
            severity=Severity.HIGH,
        )
        rule2 = Rule(
            rule_id="test-001",
            category="secrets",
            title="Second version",
            description="Second",
            severity=Severity.CRITICAL,
        )

        reg.add_rule(rule1)
        assert reg.count() == 1

        reg.add_rule(rule2)
        assert reg.count() == 1  # Still 1, not 2

        # Should have the second version
        retrieved = reg.get_by_id("test-001")
        assert retrieved.title == "Second version"


class TestDuplication:
    """Tests for deduplication logic."""

    def test_deduplicate_single_rule_multiple_locations(self, registry):
        """Should aggregate evidence from same rule in multiple files."""
        # Simulate finding the same rule in 3 different files
        evidence1 = Evidence(
            file_path="app.py",
            line_number=10,
            column_number=5,
            code_snippet="api_key = 'sk-...'",
            context="Config initialization",
        )
        evidence2 = Evidence(
            file_path="config.py",
            line_number=25,
            column_number=0,
            code_snippet="KEY = 'sk-...'",
            context="Settings module",
        )
        evidence3 = Evidence(
            file_path="utils.py",
            line_number=100,
            column_number=10,
            code_snippet="secret = 'sk-...'",
            context="Helper function",
        )

        rule = registry.get_by_id("py-001")
        result1 = RuleResult(
            rule_id="py-001",
            rule_title=rule.title,
            category=rule.category,
            severity=rule.severity,
            confidence="HIGH",
            evidence=[evidence1],
            remediation_guidance=rule.remediation_guidance,
        )
        result2 = RuleResult(
            rule_id="py-001",
            rule_title=rule.title,
            category=rule.category,
            severity=rule.severity,
            confidence="HIGH",
            evidence=[evidence2],
            remediation_guidance=rule.remediation_guidance,
        )
        result3 = RuleResult(
            rule_id="py-001",
            rule_title=rule.title,
            category=rule.category,
            severity=rule.severity,
            confidence="HIGH",
            evidence=[evidence3],
            remediation_guidance=rule.remediation_guidance,
        )

        # Deduplicate
        findings_dict = {"py-001": [result1, result2, result3]}
        deduplicated = DuplicationHandler.deduplicate(findings_dict)

        # Should have aggregated
        assert "py-001" in deduplicated
        assert deduplicated["py-001"]["evidence_count"] == 3
        assert deduplicated["py-001"]["affected_files_count"] == 3
        assert len(deduplicated["py-001"]["sample_locations"]) == 3

        # Sample locations should include all files
        locations = set(deduplicated["py-001"]["sample_locations"])
        assert "app.py" in locations
        assert "config.py" in locations
        assert "utils.py" in locations

    def test_deduplicate_multiple_rules(self, registry):
        """Should handle deduplication across multiple rule IDs."""
        evidence_py = Evidence(
            file_path="app.py",
            line_number=10,
            column_number=5,
            code_snippet="api_key = 'sk-...'",
            context="",
        )
        evidence_js = Evidence(
            file_path="app.js",
            line_number=20,
            column_number=0,
            code_snippet="const apiKey = 'sk-...'",
            context="",
        )

        rule_py = registry.get_by_id("py-001")
        rule_js = registry.get_by_id("js-001")

        result_py = RuleResult(
            rule_id="py-001",
            rule_title=rule_py.title,
            category=rule_py.category,
            severity=rule_py.severity,
            confidence="HIGH",
            evidence=[evidence_py],
            remediation_guidance=rule_py.remediation_guidance,
        )
        result_js = RuleResult(
            rule_id="js-001",
            rule_title=rule_js.title,
            category=rule_js.category,
            severity=rule_js.severity,
            confidence="HIGH",
            evidence=[evidence_js],
            remediation_guidance=rule_js.remediation_guidance,
        )

        # Deduplicate
        findings_dict = {"py-001": [result_py], "js-001": [result_js]}
        deduplicated = DuplicationHandler.deduplicate(findings_dict)

        assert len(deduplicated) == 2
        assert "py-001" in deduplicated
        assert "js-001" in deduplicated


class TestManualConfirmation:
    """Tests for manual confirmation tracking."""

    def test_confirm_finding(self):
        """Should record confirmation for a rule."""
        confirmations = ManualConfirmation()
        confirmations.confirm("py-001", ManualConfirmation.Status.CONFIRMED, "Real vulnerability confirmed")

        assert confirmations.is_confirmed("py-001") is True
        assert confirmations.is_dismissed("py-001") is False

    def test_dismiss_finding(self):
        """Should record dismissal of a rule."""
        confirmations = ManualConfirmation()
        confirmations.confirm("py-001", ManualConfirmation.Status.DISMISSED, "False positive - intentional test data")

        assert confirmations.is_dismissed("py-001") is True
        assert confirmations.is_confirmed("py-001") is False

    def test_defer_finding(self):
        """Should record deferred findings."""
        confirmations = ManualConfirmation()
        confirmations.confirm("py-001", ManualConfirmation.Status.DEFERRED, "Need to verify with team")

        status = confirmations.get_status("py-001")
        assert status == ManualConfirmation.Status.DEFERRED

    def test_unreviewed_status(self):
        """Should return UNREVIEWED for unconfirmed findings."""
        confirmations = ManualConfirmation()

        status = confirmations.get_status("nonexistent-001")
        assert status == ManualConfirmation.Status.UNREVIEWED

    def test_confirmation_serialization(self):
        """Should serialize confirmations to dict."""
        confirmations = ManualConfirmation()
        confirmations.confirm("py-001", ManualConfirmation.Status.CONFIRMED)
        confirmations.confirm("js-001", ManualConfirmation.Status.DISMISSED)

        data = confirmations.to_dict()

        assert "py-001" in data
        assert data["py-001"]["status"] == "confirmed"
        assert "js-001" in data
        assert data["js-001"]["status"] == "dismissed"

    def test_confirmation_update(self):
        """Should allow updating confirmations."""
        confirmations = ManualConfirmation()

        # Initially confirm
        confirmations.confirm("py-001", ManualConfirmation.Status.CONFIRMED)
        assert confirmations.is_confirmed("py-001") is True

        # Update to dismissed
        confirmations.confirm("py-001", ManualConfirmation.Status.DISMISSED, "Actually a false positive")
        assert confirmations.is_dismissed("py-001") is True


class TestIntegration:
    """Integration tests combining all components."""

    def test_full_workflow(self, registry):
        """Should handle complete registry and confirmation workflow."""
        # Get rules
        py_rules = registry.get_by_category("secrets")
        assert len(py_rules) >= 1

        # Create findings (simulated)
        evidence1 = Evidence(
            file_path="main.py",
            line_number=5,
            column_number=0,
            code_snippet="API_KEY = 'sk-...'",
            context="",
        )
        evidence2 = Evidence(
            file_path="settings.py",
            line_number=15,
            column_number=0,
            code_snippet="SECRET = 'sk-...'",
            context="",
        )

        rule = registry.get_by_id("py-001")
        result1 = RuleResult(
            rule_id="py-001",
            rule_title=rule.title,
            category=rule.category,
            severity=rule.severity,
            confidence="HIGH",
            evidence=[evidence1],
            remediation_guidance=rule.remediation_guidance,
        )
        result2 = RuleResult(
            rule_id="py-001",
            rule_title=rule.title,
            category=rule.category,
            severity=rule.severity,
            confidence="HIGH",
            evidence=[evidence2],
            remediation_guidance=rule.remediation_guidance,
        )

        # Deduplicate
        findings_dict = {"py-001": [result1, result2]}
        deduplicated = DuplicationHandler.deduplicate(findings_dict)

        assert deduplicated["py-001"]["evidence_count"] == 2

        # Confirm or dismiss
        confirmations = ManualConfirmation()
        confirmations.confirm("py-001", ManualConfirmation.Status.CONFIRMED)

        assert confirmations.is_confirmed("py-001") is True

    def test_large_registry_performance(self, registry):
        """Large registry should handle lookups efficiently."""
        # Get all rules
        all_rules = registry.list_all()
        assert len(all_rules) >= 50

        # All categories should be accessible
        categories = registry.categories()
        for category in categories:
            rules = registry.get_by_category(category)
            assert len(rules) > 0

        # Random lookups should succeed
        for rule in all_rules[:10]:
            retrieved = registry.get_by_id(rule.rule_id)
            assert retrieved is not None
            assert retrieved.rule_id == rule.rule_id
