"""
Tests for IAN scoring model, compromise mode classification, and chain detection.
"""

import pytest
from repo_audit_scan.scoring import (
    Impact,
    Accessibility,
    Necessity,
    IANScore,
    IANScorer,
    CompromiseModeClassifier,
    ChainDetector,
)
from repo_audit_scan.models import (
    Finding,
    RuleResult,
    Evidence,
    Severity,
    Confidence,
    CompromiseMode,
)


@pytest.fixture
def sample_evidence():
    """Sample evidence for testing."""
    return Evidence(
        file_path="app.py",
        line_number=42,
        column_number=10,
        code_snippet="api_key = 'sk-1234567890'",
        context="API initialization",
    )


@pytest.fixture
def sample_rule_result(sample_evidence):
    """Sample RuleResult for scoring tests."""
    return RuleResult(
        rule_id="py-001",
        rule_title="Hardcoded API Key",
        category="secrets",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        evidence=[sample_evidence],
        remediation_guidance="Move to environment variables",
    )


class TestIANScorer:
    """Tests for IANScorer.score_finding()."""

    def test_critical_severity_maps_to_impact(self, sample_rule_result):
        """CRITICAL severity should map to Impact.CRITICAL with score 1.0."""
        score = IANScorer.score_finding(sample_rule_result)
        assert score.impact == Impact.CRITICAL
        assert score.impact_score == 1.0

    def test_high_confidence_maps_to_easy_accessibility(self, sample_rule_result):
        """HIGH confidence should map to Accessibility.EASY with score 0.8."""
        score = IANScorer.score_finding(sample_rule_result)
        assert score.accessibility == Accessibility.EASY
        assert score.accessibility_score == 0.8

    def test_secrets_category_maps_to_critical_necessity(self, sample_rule_result):
        """secrets category should map to Necessity.CRITICAL with score 1.0."""
        score = IANScorer.score_finding(sample_rule_result)
        assert score.necessity == Necessity.CRITICAL
        assert score.necessity_score == 1.0

    def test_composite_score_calculation(self, sample_rule_result):
        """Composite should be 40% impact + 35% accessibility + 25% necessity."""
        score = IANScorer.score_finding(sample_rule_result)
        expected = (1.0 * 0.4) + (0.8 * 0.35) + (1.0 * 0.25)
        assert pytest.approx(score.composite_score, abs=0.01) == expected

    def test_low_severity_maps_to_low_impact(self, sample_rule_result):
        """LOW severity should map to Impact.LOW with score 0.3."""
        sample_rule_result.severity = Severity.LOW
        score = IANScorer.score_finding(sample_rule_result)
        assert score.impact == Impact.LOW
        assert score.impact_score == 0.3

    def test_info_severity_maps_to_info_impact(self, sample_rule_result):
        """INFO severity should map to Impact.INFO with score 0.1."""
        sample_rule_result.severity = Severity.INFO
        score = IANScorer.score_finding(sample_rule_result)
        assert score.impact == Impact.INFO
        assert score.impact_score == 0.1

    def test_medium_confidence_maps_to_moderate_accessibility(self, sample_rule_result):
        """MEDIUM confidence should map to Accessibility.MODERATE with score 0.5."""
        sample_rule_result.confidence = Confidence.MEDIUM
        score = IANScorer.score_finding(sample_rule_result)
        assert score.accessibility == Accessibility.MODERATE
        assert score.accessibility_score == 0.5

    def test_low_confidence_maps_to_difficult_accessibility(self, sample_rule_result):
        """LOW confidence should map to Accessibility.DIFFICULT with score 0.3."""
        sample_rule_result.confidence = Confidence.LOW
        score = IANScorer.score_finding(sample_rule_result)
        assert score.accessibility == Accessibility.DIFFICULT
        assert score.accessibility_score == 0.3

    def test_error_handling_category_maps_to_medium_necessity(self, sample_rule_result):
        """error-handling category should map to Necessity.MEDIUM with score 0.5."""
        sample_rule_result.category = "error-handling"
        score = IANScorer.score_finding(sample_rule_result)
        assert score.necessity == Necessity.MEDIUM
        assert score.necessity_score == 0.5

    def test_deployment_category_maps_to_medium_necessity(self, sample_rule_result):
        """deployment category should map to Necessity.MEDIUM with score 0.5."""
        sample_rule_result.category = "deployment"
        score = IANScorer.score_finding(sample_rule_result)
        assert score.necessity == Necessity.MEDIUM
        assert score.necessity_score == 0.5

    def test_unknown_category_defaults_to_medium_necessity(self, sample_rule_result):
        """Unknown category should default to Necessity.MEDIUM with score 0.5."""
        sample_rule_result.category = "unknown-category"
        score = IANScorer.score_finding(sample_rule_result)
        assert score.necessity == Necessity.MEDIUM
        assert score.necessity_score == 0.5

    def test_rationale_is_generated(self, sample_rule_result):
        """Rationale should describe the scoring breakdown."""
        score = IANScorer.score_finding(sample_rule_result)
        assert len(score.rationale) > 0
        assert "CRITICAL" in score.rationale.upper()


class TestCompromiseModeClassifier:
    """Tests for CompromiseModeClassifier."""

    def test_classify_critical_high_prevalence_as_assume_breach(self):
        """CRITICAL severity with 6+ evidence should be ASSUME_BREACH."""
        mode = CompromiseModeClassifier.classify_mode(
            composite_score=0.5,
            evidence_count=6,
            file_count=4,
            severity=Severity.CRITICAL,
        )
        assert mode == CompromiseMode.ASSUME_BREACH

    def test_classify_critical_multiple_files_as_assume_breach(self):
        """CRITICAL severity with 4+ files should be ASSUME_BREACH."""
        mode = CompromiseModeClassifier.classify_mode(
            composite_score=0.5,
            evidence_count=2,
            file_count=4,
            severity=Severity.CRITICAL,
        )
        assert mode == CompromiseMode.ASSUME_BREACH

    def test_classify_critical_moderate_prevalence_as_triage(self):
        """CRITICAL severity with low prevalence should be TRIAGE."""
        mode = CompromiseModeClassifier.classify_mode(
            composite_score=0.5,
            evidence_count=2,
            file_count=1,
            severity=Severity.CRITICAL,
        )
        assert mode == CompromiseMode.TRIAGE

    def test_classify_high_score_as_cover(self):
        """Composite score >= 0.75 should be COVER."""
        mode = CompromiseModeClassifier.classify_mode(
            composite_score=0.75,
            evidence_count=1,
            file_count=1,
            severity=Severity.MEDIUM,
        )
        assert mode == CompromiseMode.COVER

    def test_classify_very_high_score_as_cover(self):
        """Composite score > 0.75 should be COVER."""
        mode = CompromiseModeClassifier.classify_mode(
            composite_score=0.9,
            evidence_count=1,
            file_count=1,
            severity=Severity.MEDIUM,
        )
        assert mode == CompromiseMode.COVER

    def test_classify_medium_score_as_triage(self):
        """Composite score < 0.75 with normal prevalence should be TRIAGE."""
        mode = CompromiseModeClassifier.classify_mode(
            composite_score=0.6,
            evidence_count=2,
            file_count=1,
            severity=Severity.MEDIUM,
        )
        assert mode == CompromiseMode.TRIAGE

    def test_adjust_cover_mode_increases_score(self):
        """COVER mode should increase composite score."""
        ian_score = IANScore(
            impact=Impact.CRITICAL,
            impact_score=1.0,
            accessibility=Accessibility.EASY,
            accessibility_score=0.8,
            necessity=Necessity.CRITICAL,
            necessity_score=1.0,
            composite_score=0.93,
        )
        adjusted, rationale = CompromiseModeClassifier.adjust_for_mode(
            ian_score, CompromiseMode.COVER, evidence_count=5
        )
        assert adjusted == pytest.approx(1.0, abs=0.01)
        assert "COVER" in rationale.upper()

    def test_adjust_triage_mode_no_adjustment(self):
        """TRIAGE mode should not adjust score."""
        ian_score = IANScore(
            impact=Impact.MEDIUM,
            impact_score=0.5,
            accessibility=Accessibility.MODERATE,
            accessibility_score=0.5,
            necessity=Necessity.MEDIUM,
            necessity_score=0.5,
            composite_score=0.5,
        )
        adjusted, rationale = CompromiseModeClassifier.adjust_for_mode(
            ian_score, CompromiseMode.TRIAGE, evidence_count=1
        )
        assert adjusted == 0.5
        assert "TRIAGE" in rationale.upper()

    def test_adjust_assume_breach_critical_impact_boosts_score(self):
        """ASSUME_BREACH with CRITICAL impact should boost score."""
        ian_score = IANScore(
            impact=Impact.CRITICAL,
            impact_score=1.0,
            accessibility=Accessibility.EASY,
            accessibility_score=0.8,
            necessity=Necessity.CRITICAL,
            necessity_score=1.0,
            composite_score=0.93,
        )
        adjusted, rationale = CompromiseModeClassifier.adjust_for_mode(
            ian_score, CompromiseMode.ASSUME_BREACH, evidence_count=1
        )
        assert adjusted == pytest.approx(1.0, abs=0.01)
        assert "ASSUME_BREACH" in rationale.upper()

    def test_adjust_assume_breach_non_critical_reduces_score(self):
        """ASSUME_BREACH with non-CRITICAL impact should reduce score."""
        ian_score = IANScore(
            impact=Impact.MEDIUM,
            impact_score=0.5,
            accessibility=Accessibility.MODERATE,
            accessibility_score=0.5,
            necessity=Necessity.MEDIUM,
            necessity_score=0.5,
            composite_score=0.5,
        )
        adjusted, rationale = CompromiseModeClassifier.adjust_for_mode(
            ian_score, CompromiseMode.ASSUME_BREACH, evidence_count=1
        )
        assert adjusted == pytest.approx(0.4, abs=0.01)
        assert "ASSUME_BREACH" in rationale.upper()


class TestChainDetector:
    """Tests for ChainDetector."""

    def test_detect_auth_to_session_chain(self):
        """authentication finding should show dependency to session finding."""
        findings = [
            Finding(
                finding_id="finding-001",
                rule_id="auth-001",
                rule_title="Weak Session",
                category="authentication",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                evidence=[],
                remediation_guidance="",
            ),
            Finding(
                finding_id="finding-002",
                rule_id="session-002",
                rule_title="Session Fixation",
                category="session",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                evidence=[],
                remediation_guidance="",
            ),
        ]
        chains = ChainDetector.detect_chains(findings)
        assert "auth-001" in chains
        assert "session-002" in chains["auth-001"]

    def test_detect_injection_to_xss_chain(self):
        """injection finding should show dependency to xss finding."""
        findings = [
            Finding(
                finding_id="finding-003",
                rule_id="inj-001",
                rule_title="SQL Injection",
                category="injection",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                evidence=[],
                remediation_guidance="",
            ),
            Finding(
                finding_id="finding-004",
                rule_id="xss-001",
                rule_title="DOM-based XSS",
                category="xss",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                evidence=[],
                remediation_guidance="",
            ),
        ]
        chains = ChainDetector.detect_chains(findings)
        assert "inj-001" in chains
        assert "xss-001" in chains["inj-001"]

    def test_detect_secrets_to_crypto_chain(self):
        """secrets finding should show dependency to cryptography finding."""
        findings = [
            Finding(
                finding_id="finding-005",
                rule_id="sec-001",
                rule_title="Hardcoded Key",
                category="secrets",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                evidence=[],
                remediation_guidance="",
            ),
            Finding(
                finding_id="finding-006",
                rule_id="crypto-001",
                rule_title="Weak Encryption",
                category="cryptography",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                evidence=[],
                remediation_guidance="",
            ),
        ]
        chains = ChainDetector.detect_chains(findings)
        assert "sec-001" in chains
        assert "crypto-001" in chains["sec-001"]

    def test_no_chain_for_unrelated_findings(self):
        """Unrelated findings should not form chains."""
        findings = [
            Finding(
                finding_id="finding-007",
                rule_id="log-001",
                rule_title="Missing Logging",
                category="logging",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                evidence=[],
                remediation_guidance="",
            ),
            Finding(
                finding_id="finding-008",
                rule_id="dep-001",
                rule_title="Outdated Dependency",
                category="dependency",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                evidence=[],
                remediation_guidance="",
            ),
        ]
        chains = ChainDetector.detect_chains(findings)
        assert len(chains) == 0

    def test_detect_prerequisites_for_privilege_escalation(self):
        """privilege finding should list authentication as prerequisite."""
        finding = Finding(
            finding_id="finding-009",
            rule_id="priv-001",
            rule_title="Privilege Escalation",
            category="privilege-escalation",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            evidence=[],
            remediation_guidance="",
        )
        prerequisites = ChainDetector.detect_prerequisites(finding)
        assert "authentication" in prerequisites

    def test_detect_prerequisites_for_session_issue(self):
        """session finding should list xss as prerequisite."""
        finding = Finding(
            finding_id="finding-010",
            rule_id="sess-001",
            rule_title="Session Fixation",
            category="session",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            evidence=[],
            remediation_guidance="",
        )
        prerequisites = ChainDetector.detect_prerequisites(finding)
        assert "xss" in prerequisites

    def test_detect_prerequisites_for_crypto_issue(self):
        """cryptography finding should list secrets as prerequisite."""
        finding = Finding(
            finding_id="finding-011",
            rule_id="crypto-001",
            rule_title="Weak Encryption",
            category="cryptography",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            evidence=[],
            remediation_guidance="",
        )
        prerequisites = ChainDetector.detect_prerequisites(finding)
        assert "secrets" in prerequisites

    def test_detect_prerequisites_for_file_operations(self):
        """file-operations finding should list path-traversal as prerequisite."""
        finding = Finding(
            finding_id="finding-012",
            rule_id="file-001",
            rule_title="Unsafe File Read",
            category="file-operations",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            evidence=[],
            remediation_guidance="",
        )
        prerequisites = ChainDetector.detect_prerequisites(finding)
        assert "path-traversal" in prerequisites

    def test_chain_detection_with_multiple_findings(self):
        """Should detect multiple chains across findings."""
        findings = [
            Finding(
                finding_id="finding-013",
                rule_id="auth-001",
                rule_title="Weak Auth",
                category="authentication",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                evidence=[],
                remediation_guidance="",
            ),
            Finding(
                finding_id="finding-014",
                rule_id="session-001",
                rule_title="Session Fixation",
                category="session",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                evidence=[],
                remediation_guidance="",
            ),
            Finding(
                finding_id="finding-015",
                rule_id="xss-001",
                rule_title="XSS Vulnerability",
                category="xss",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                evidence=[],
                remediation_guidance="",
            ),
        ]
        chains = ChainDetector.detect_chains(findings)
        assert len(chains) >= 1
        assert "auth-001" in chains or "xss-001" in chains
