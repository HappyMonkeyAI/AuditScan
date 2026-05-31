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


@dataclass
class AdversarialConsensusResult:
    """Structured consensus result between primary and challenger verdicts."""

    report_id: str
    finding_id: str
    primary_verdict: str
    challenger_verdict: AdversarialVerdict
    consensus_state: str
    assurance_score: int
    recommended_action: str
    requires_human_review: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "finding_id": self.finding_id,
            "primary_verdict": self.primary_verdict,
            "challenger_verdict": self.challenger_verdict.value,
            "consensus_state": self.consensus_state,
            "assurance_score": self.assurance_score,
            "recommended_action": self.recommended_action,
            "requires_human_review": self.requires_human_review,
        }


@dataclass
class AdversarialTestIntentResult:
    """Structured adversarial test intent bundle for a finding."""

    report_id: str
    finding_id: str
    test_intents: List[Dict[str, Any]]
    suggested_execution_order: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "finding_id": self.finding_id,
            "test_intents": self.test_intents,
            "suggested_execution_order": self.suggested_execution_order,
        }


@dataclass
class AdversarialGovernanceResult:
    """Governance decision output for assurance handling."""

    report_id: str
    finding_id: str
    policy_version: str
    decision: str
    triggers: List[str]
    requires_human_review: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "finding_id": self.finding_id,
            "policy_version": self.policy_version,
            "decision": self.decision,
            "triggers": self.triggers,
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


def compare_verdicts_contract(
    report_id: str,
    finding: Dict[str, Any],
    primary_verdict: str,
    challenger_verdict: str,
) -> AdversarialConsensusResult:
    """Build consensus and assurance score from primary/challenger verdicts."""
    finding_id = str(finding.get("finding_id", "unknown-finding"))
    severity = str(finding.get("severity", "")).lower()

    primary = primary_verdict.strip().lower()
    challenger = challenger_verdict.strip().lower()
    if challenger not in {"support", "challenge", "uncertain"}:
        challenger = "uncertain"

    if primary == "resolved" and challenger == "support":
        consensus_state = "agree"
        assurance_score = 90
        recommended_action = "close"
    elif primary == "unresolved" and challenger == "challenge":
        consensus_state = "agree"
        assurance_score = 80
        recommended_action = "retest"
    else:
        consensus_state = "contested"
        assurance_score = 45 if challenger == "challenge" else 55
        recommended_action = "escalate_human"

    requires_human_review = consensus_state == "contested" or (severity == "critical" and challenger != "support")

    return AdversarialConsensusResult(
        report_id=report_id,
        finding_id=finding_id,
        primary_verdict=primary,
        challenger_verdict=AdversarialVerdict(challenger),
        consensus_state=consensus_state,
        assurance_score=assurance_score,
        recommended_action=recommended_action,
        requires_human_review=requires_human_review,
    )


def generate_test_intents_contract(report_id: str, finding: Dict[str, Any]) -> AdversarialTestIntentResult:
    """Generate adversarial test intents for a finding."""
    finding_id = str(finding.get("finding_id", "unknown-finding"))
    rule_id = str(finding.get("rule_id", "unknown-rule"))
    severity = str(finding.get("severity", "medium")).lower()
    evidence = finding.get("evidence", []) or []
    first_evidence = evidence[0] if evidence else {}
    file_path = str(first_evidence.get("file_path", "unknown-file"))
    line_number = first_evidence.get("line_number")
    location = f"{file_path}:{line_number}" if line_number else file_path

    risk_weight = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(severity, 3)

    intents: List[Dict[str, Any]] = [
        {
            "intent_id": f"{finding_id}-regression",
            "type": "regression",
            "title": f"Regression guard for {rule_id}",
            "goal": "Ensure the original vulnerable path remains closed.",
            "target_location": location,
            "strategy": "Reproduce original evidence path and assert safe handling.",
            "priority": risk_weight + 1,
        },
        {
            "intent_id": f"{finding_id}-bypass",
            "type": "adversarial_bypass",
            "title": f"Bypass variants for {rule_id}",
            "goal": "Probe encoded/obfuscated variants that may bypass the fix.",
            "target_location": location,
            "strategy": "Mutate input encoding, case, and payload shape to test bypass resilience.",
            "priority": risk_weight,
        },
        {
            "intent_id": f"{finding_id}-boundary",
            "type": "boundary",
            "title": f"Boundary tests for {rule_id}",
            "goal": "Validate edge-case behavior at trust boundaries.",
            "target_location": location,
            "strategy": "Test empty, null, max-size, and malformed inputs at entry boundary.",
            "priority": max(1, risk_weight - 1),
        },
    ]

    order = [item["intent_id"] for item in sorted(intents, key=lambda item: item["priority"], reverse=True)]
    return AdversarialTestIntentResult(
        report_id=report_id,
        finding_id=finding_id,
        test_intents=intents,
        suggested_execution_order=order,
    )


def evaluate_governance_contract(
    report_id: str,
    finding: Dict[str, Any],
    consensus: Dict[str, Any],
) -> AdversarialGovernanceResult:
    """Evaluate governance triggers for assurance decisions."""
    finding_id = str(finding.get("finding_id", "unknown-finding"))
    severity = str(finding.get("severity", "")).lower()
    consensus_state = str(consensus.get("consensus_state", "")).lower()
    assurance_score = int(consensus.get("assurance_score", 0))

    triggers: List[str] = []
    if severity == "critical" and consensus_state == "contested":
        triggers.append("contested_critical_finding")
    if assurance_score < 60:
        triggers.append("low_assurance_score")
    if str(consensus.get("recommended_action", "")).lower() == "escalate_human":
        triggers.append("explicit_human_escalation")

    requires_human_review = len(triggers) > 0
    decision = "human_review_required" if requires_human_review else "auto_close_allowed"
    return AdversarialGovernanceResult(
        report_id=report_id,
        finding_id=finding_id,
        policy_version="1.0",
        decision=decision,
        triggers=triggers,
        requires_human_review=requires_human_review,
    )
