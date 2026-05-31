"""Adversarial assurance contracts and review helpers."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional


class AdversarialVerdict(str, Enum):
    """Adversarial review verdict states."""

    SUPPORT = "support"
    CHALLENGE = "challenge"
    UNCERTAIN = "uncertain"


@dataclass
class AdversarialReviewResult:
    """Structured result for adversarial finding review."""

    report_id: str
    finding_id: str
    verdict: AdversarialVerdict
    confidence_delta: int
    rationale: str
    evidence_delta: List[str]
    recommended_action: str
    requires_human_review: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "finding_id": self.finding_id,
            "verdict": self.verdict.value,
            "confidence_delta": self.confidence_delta,
            "rationale": self.rationale,
            "evidence_delta": self.evidence_delta,
            "recommended_action": self.recommended_action,
            "requires_human_review": self.requires_human_review,
        }


@dataclass
class AdversarialFixChallengeResult:
    """Structured result for adversarial fix-challenge review."""

    report_id: str
    finding_id: str
    patch_ref: Optional[str]
    verify_resolved: bool
    verdict: AdversarialVerdict
    confidence_delta: int
    rationale: str
    exploit_attempts: List[str]
    recommended_action: str
    requires_human_review: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "finding_id": self.finding_id,
            "patch_ref": self.patch_ref,
            "verify_resolved": self.verify_resolved,
            "verdict": self.verdict.value,
            "confidence_delta": self.confidence_delta,
            "rationale": self.rationale,
            "exploit_attempts": self.exploit_attempts,
            "recommended_action": self.recommended_action,
            "requires_human_review": self.requires_human_review,
        }


def review_finding_contract(report_id: str, finding: Dict[str, Any], challenge_notes: Optional[str] = None) -> AdversarialReviewResult:
    """Build a first-pass adversarial review payload for a finding."""
    finding_id = str(finding.get("finding_id", "unknown-finding"))
    severity = str(finding.get("severity", "")).lower()
    confidence = str(finding.get("confidence", "")).lower()
    evidence = finding.get("evidence", []) or []
    evidence_count = len(evidence)

    verdict = AdversarialVerdict.UNCERTAIN
    confidence_delta = 0
    rationale = "Initial challenger pass needs explicit exploitability probe."
    recommended_action = "retest"
    requires_human_review = False

    if evidence_count >= 2 and confidence == "high":
        verdict = AdversarialVerdict.SUPPORT
        confidence_delta = 8
        rationale = "Multiple evidence points with high confidence support the original finding."
        recommended_action = "accept"
    elif evidence_count == 0 or confidence == "low":
        verdict = AdversarialVerdict.CHALLENGE
        confidence_delta = -15
        rationale = "Evidence quality is weak for closure decisions; challenger contests finding confidence."
        recommended_action = "escalate_human"

    if severity == "critical" and verdict != AdversarialVerdict.SUPPORT:
        requires_human_review = True

    evidence_delta = [f"evidence_count={evidence_count}", f"confidence={confidence or 'unknown'}"]
    if challenge_notes:
        evidence_delta.append(f"challenge_notes={challenge_notes}")

    return AdversarialReviewResult(
        report_id=report_id,
        finding_id=finding_id,
        verdict=verdict,
        confidence_delta=confidence_delta,
        rationale=rationale,
        evidence_delta=evidence_delta,
        recommended_action=recommended_action,
        requires_human_review=requires_human_review,
    )


def challenge_fix_contract(
    report_id: str,
    finding: Dict[str, Any],
    verify_resolved: bool,
    patch_ref: Optional[str] = None,
    challenge_notes: Optional[str] = None,
) -> AdversarialFixChallengeResult:
    """Build a first-pass adversarial fix challenge payload."""
    finding_id = str(finding.get("finding_id", "unknown-finding"))
    severity = str(finding.get("severity", "")).lower()

    if verify_resolved:
        verdict = AdversarialVerdict.SUPPORT
        confidence_delta = 6
        rationale = "Primary verification reports resolved; challenger currently finds no residual exploit signal."
        recommended_action = "accept"
    else:
        verdict = AdversarialVerdict.CHALLENGE
        confidence_delta = -12
        rationale = "Primary verification still reports unresolved locations; challenger rejects fix closure."
        recommended_action = "retest"

    requires_human_review = severity == "critical" and verdict != AdversarialVerdict.SUPPORT
    if requires_human_review:
        recommended_action = "escalate_human"

    exploit_attempts = [
        "replay-original-evidence-path",
        "variant-input-encoding-probe",
    ]
    if challenge_notes:
        exploit_attempts.append(f"challenger-notes:{challenge_notes}")

    return AdversarialFixChallengeResult(
        report_id=report_id,
        finding_id=finding_id,
        patch_ref=patch_ref,
        verify_resolved=verify_resolved,
        verdict=verdict,
        confidence_delta=confidence_delta,
        rationale=rationale,
        exploit_attempts=exploit_attempts,
        recommended_action=recommended_action,
        requires_human_review=requires_human_review,
    )
