"""
IAN Scoring model, compromise mode logic, and chain detection.

Provides:
- IANScorer: Impact, Accessibility, Necessity scoring
- CompromiseModeClassifier: Classify and adjust scores based on context
- ChainDetector: Detect rule dependencies and chains
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from enum import Enum
import re

from repo_audit_scan.models import (
    Finding, RuleResult, Severity, Confidence, CompromiseMode
)


class Impact(str, Enum):
    """Impact level classification."""
    CRITICAL = "critical"  # System breach, data exfil, privilege escalation
    HIGH = "high"  # Confidentiality, integrity, or availability loss
    MEDIUM = "medium"  # Partial loss of C/I/A
    LOW = "low"  # Minimal or theoretical impact
    INFO = "info"  # No real impact


class Accessibility(str, Enum):
    """Accessibility level (exploitability)."""
    TRIVIAL = "trivial"  # No authentication, no interaction needed
    EASY = "easy"  # Minimal steps, publicly exploitable
    MODERATE = "moderate"  # Some prerequisites, moderate effort
    DIFFICULT = "difficult"  # Significant barriers or insider knowledge
    IMPOSSIBLE = "impossible"  # Not practically exploitable


class Necessity(str, Enum):
    """Necessity level (urgency to fix)."""
    CRITICAL = "critical"  # Fix immediately, blocks deployment
    HIGH = "high"  # Fix before release
    MEDIUM = "medium"  # Fix in next sprint
    LOW = "low"  # Nice to have, can defer
    DEFERRED = "deferred"  # Low priority, accept risk


@dataclass
class IANScore:
    """IAN scoring result."""
    impact: Impact
    impact_score: float  # 0.0 - 1.0
    accessibility: Accessibility
    accessibility_score: float  # 0.0 - 1.0
    necessity: Necessity
    necessity_score: float  # 0.0 - 1.0
    composite_score: float  # weighted average
    rationale: str = ""

    def __post_init__(self):
        """Ensure scores are valid."""
        for score in [self.impact_score, self.accessibility_score, self.necessity_score]:
            if not 0.0 <= score <= 1.0:
                raise ValueError(f"Score must be between 0.0 and 1.0, got {score}")


class IANScorer:
    """
    Impact, Accessibility, Necessity scoring model.

    Combines Severity, Confidence, and Category to produce a holistic IAN score.
    """

    # Severity → Impact mapping
    SEVERITY_TO_IMPACT = {
        Severity.CRITICAL: (Impact.CRITICAL, 1.0),
        Severity.HIGH: (Impact.HIGH, 0.8),
        Severity.MEDIUM: (Impact.MEDIUM, 0.5),
        Severity.LOW: (Impact.LOW, 0.3),
        Severity.INFO: (Impact.INFO, 0.1),
    }

    # Confidence → Accessibility mapping
    CONFIDENCE_TO_ACCESSIBILITY = {
        Confidence.HIGH: (Accessibility.EASY, 0.8),
        Confidence.MEDIUM: (Accessibility.MODERATE, 0.5),
        Confidence.LOW: (Accessibility.DIFFICULT, 0.3),
    }

    # Category → Necessity mapping (baseline)
    CATEGORY_NECESSITY = {
        "secrets": Necessity.CRITICAL,
        "injection": Necessity.CRITICAL,
        "authentication": Necessity.CRITICAL,
        "cryptography": Necessity.HIGH,
        "access-control": Necessity.HIGH,
        "file-operations": Necessity.HIGH,
        "api-security": Necessity.HIGH,
        "xss": Necessity.HIGH,
        "error-handling": Necessity.MEDIUM,
        "data-validation": Necessity.MEDIUM,
        "logging": Necessity.MEDIUM,
        "configuration": Necessity.MEDIUM,
        "deployment": Necessity.MEDIUM,
        "compliance": Necessity.HIGH,
        "dependency": Necessity.MEDIUM,
        "ci-cd": Necessity.HIGH,
        "monitoring": Necessity.MEDIUM,
        "memory-safety": Necessity.CRITICAL,
        "concurrency": Necessity.MEDIUM,
        "disaster-recovery": Necessity.LOW,
    }

    @staticmethod
    def score_finding(result: RuleResult) -> IANScore:
        """
        Score a rule result using IAN model.

        Args:
            result: RuleResult to score

        Returns:
            IANScore with impact, accessibility, necessity components
        """
        # Impact from severity
        impact, impact_score = IANScorer.SEVERITY_TO_IMPACT.get(
            result.severity,
            (Impact.MEDIUM, 0.5)
        )

        # Accessibility from confidence
        accessibility, accessibility_score = IANScorer.CONFIDENCE_TO_ACCESSIBILITY.get(
            result.confidence,
            (Accessibility.MODERATE, 0.5)
        )

        # Necessity from category
        necessity = IANScorer.CATEGORY_NECESSITY.get(result.category, Necessity.MEDIUM)
        necessity_score = {
            Necessity.CRITICAL: 1.0,
            Necessity.HIGH: 0.8,
            Necessity.MEDIUM: 0.5,
            Necessity.LOW: 0.3,
            Necessity.DEFERRED: 0.1,
        }.get(necessity, 0.5)

        # Composite score: weighted average
        # Weights: Impact 40%, Accessibility 35%, Necessity 25%
        composite = (impact_score * 0.4) + (accessibility_score * 0.35) + (necessity_score * 0.25)

        rationale = (
            f"Impact: {impact.value} ({impact_score:.2f}) from {result.severity.value} severity. "
            f"Accessibility: {accessibility.value} ({accessibility_score:.2f}) from {result.confidence.value} confidence. "
            f"Necessity: {necessity.value} ({necessity_score:.2f}) for {result.category} category."
        )

        return IANScore(
            impact=impact,
            impact_score=impact_score,
            accessibility=accessibility,
            accessibility_score=accessibility_score,
            necessity=necessity,
            necessity_score=necessity_score,
            composite_score=composite,
            rationale=rationale,
        )


class CompromiseModeClassifier:
    """
    Classify and adjust IAN scores based on compromise mode context.

    Modes:
    - COVER: Minimize exposure, fix everything (high scores)
    - TRIAGE: Standard risk-based prioritization (normal scores)
    - ASSUME_BREACH: Assume adversary has access, focus on containment (adjusted)
    """

    @staticmethod
    def classify_mode(
        composite_score: float,
        evidence_count: int,
        file_count: int,
        severity: Severity,
    ) -> CompromiseMode:
        """
        Auto-classify compromise mode based on finding characteristics.

        Args:
            composite_score: IAN composite score (0.0-1.0)
            evidence_count: Number of evidence instances
            file_count: Number of affected files
            severity: Finding severity level

        Returns:
            CompromiseMode classification
        """
        # ASSUME_BREACH if critical severity with high prevalence
        if severity == Severity.CRITICAL and (evidence_count > 5 or file_count > 3):
            return CompromiseMode.ASSUME_BREACH

        # COVER if composite score >= 0.75 (high risk)
        if composite_score >= 0.75:
            return CompromiseMode.COVER

        # Default to TRIAGE (standard risk-based)
        return CompromiseMode.TRIAGE

    @staticmethod
    def adjust_for_mode(
        ian_score: IANScore,
        mode: CompromiseMode,
        evidence_count: int,
    ) -> Tuple[float, str]:
        """
        Adjust composite score based on compromise mode.

        Args:
            ian_score: Original IAN score
            mode: Compromise mode context
            evidence_count: Number of instances found

        Returns:
            Tuple of (adjusted_composite_score, adjustment_rationale)
        """
        base_score = ian_score.composite_score

        if mode == CompromiseMode.COVER:
            # Maximize scores for maximum coverage
            # Penalty for widespread findings (multiply by prevalence)
            prevalence_multiplier = min(1.0 + (evidence_count * 0.05), 1.25)
            adjusted = min(base_score * prevalence_multiplier, 1.0)
            rationale = f"COVER mode: maximize detection. Adjusted {base_score:.3f} → {adjusted:.3f} based on {evidence_count} instances."

        elif mode == CompromiseMode.ASSUME_BREACH:
            # Focus on containment and damage assessment
            # Boost necessity if high impact, reduce if low accessibility
            if ian_score.impact == Impact.CRITICAL:
                adjusted = min(base_score + 0.15, 1.0)
                rationale = f"ASSUME_BREACH mode: critical impact requires immediate containment. {base_score:.3f} → {adjusted:.3f}."
            else:
                adjusted = max(base_score - 0.1, 0.0)
                rationale = f"ASSUME_BREACH mode: lower priority if not critical impact. {base_score:.3f} → {adjusted:.3f}."

        else:  # TRIAGE
            # Standard risk-based: no adjustment
            adjusted = base_score
            rationale = f"TRIAGE mode: standard risk-based prioritization. Score: {adjusted:.3f}."

        return adjusted, rationale


class ChainDetector:
    """
    Detect rule dependencies and chains.

    Identifies patterns where one vulnerability depends on or enables another.
    Examples:
    - Authentication bypass → privilege escalation
    - XSS → session fixation → account takeover
    - SQL injection → data exfil
    """

    # Chain patterns: rule_id patterns that imply dependencies
    CHAIN_PATTERNS = {
        "authentication": ["session", "password", "csrf", "mfa"],
        "injection": ["xss", "command", "file-operations"],
        "secrets": ["cryptography", "authentication"],
        "file-operations": ["path", "directory"],
        "xss": ["session", "authentication"],
    }

    @staticmethod
    def detect_chains(
        findings: List[Finding],
    ) -> Dict[str, List[str]]:
        """
        Detect chains: which rule IDs depend on or enable other findings.

        Args:
            findings: List of findings to analyze

        Returns:
            Dictionary mapping rule_id → list of dependent rule_ids
        """
        chains = {}
        rule_categories = {f.rule_id: f.category for f in findings}

        for finding in findings:
            rule_id = finding.rule_id
            category = finding.category
            dependent_rules = []

            # Find other findings that could be enabled by this one
            for other_finding in findings:
                if other_finding.rule_id == rule_id:
                    continue

                # Check if category pattern matches
                if category in ChainDetector.CHAIN_PATTERNS:
                    patterns = ChainDetector.CHAIN_PATTERNS[category]
                    if any(p in other_finding.category.lower() for p in patterns):
                        dependent_rules.append(other_finding.rule_id)

            if dependent_rules:
                chains[rule_id] = dependent_rules

        return chains

    @staticmethod
    def detect_prerequisites(finding: Finding) -> Set[str]:
        """
        Identify prerequisites (other rule IDs) needed to exploit this finding.

        Args:
            finding: Finding to analyze

        Returns:
            Set of prerequisite rule_ids or categories
        """
        prerequisites = set()
        category = finding.category.lower()

        # Rule-specific prerequisites
        if "privilege" in category:
            prerequisites.add("authentication")
        if "session" in category:
            prerequisites.add("xss")
        if "cryptography" in category:
            prerequisites.add("secrets")
        if "file-operations" in category:
            prerequisites.add("path-traversal")

        return prerequisites
