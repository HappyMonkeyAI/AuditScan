"""Lane-locked prompt pack for adversarial assurance agents."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass(frozen=True)
class PromptRole:
    """Prompt definition for a single adversarial lane role."""

    role: str
    goal: str
    does: List[str]
    does_not: List[str]
    required_output: List[str]
    prompt_template: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "role": self.role,
            "goal": self.goal,
            "does": self.does,
            "does_not": self.does_not,
            "required_output": self.required_output,
            "prompt_template": self.prompt_template,
        }


def get_prompt_pack() -> Dict[str, Any]:
    """Return lane-locked prompt pack for adversarial workflow roles."""
    roles = [
        PromptRole(
            role="reviewer",
            goal="Assess whether the original finding is evidence-backed and correctly prioritized.",
            does=[
                "Validate finding evidence against source paths and lines.",
                "Check severity/confidence alignment with evidence quality.",
                "Identify missing context required for safe remediation.",
            ],
            does_not=[
                "Do not propose source-code changes.",
                "Do not execute exploit payloads.",
                "Do not close or dismiss findings unilaterally.",
            ],
            required_output=[
                "verdict: support|challenge|uncertain",
                "evidence_delta",
                "confidence_delta",
                "recommended_action",
            ],
            prompt_template=(
                "You are the adversarial reviewer. Evaluate finding {finding_id} from report {report_id}. "
                "Stay in your lane: verify evidence quality and prioritization only. Return structured output fields: "
                "verdict, rationale, evidence_delta, confidence_delta, recommended_action."
            ),
        ),
        PromptRole(
            role="challenger",
            goal="Challenge whether the claimed fix truly eliminates the exploitable path.",
            does=[
                "Attempt conceptual bypass variants against the original risk path.",
                "Re-check verification output for residual evidence.",
                "Classify whether closure is justified.",
            ],
            does_not=[
                "Do not rewrite application code.",
                "Do not modify acceptance criteria.",
                "Do not broaden scope beyond the targeted finding.",
            ],
            required_output=[
                "verify_resolved",
                "verdict: support|challenge|uncertain",
                "exploit_attempts",
                "recommended_action",
            ],
            prompt_template=(
                "You are the adversarial challenger. For finding {finding_id} in report {report_id}, "
                "test whether the fix holds under bypass variants. Use verify output as ground truth input and return: "
                "verify_resolved, verdict, rationale, exploit_attempts, recommended_action."
            ),
        ),
        PromptRole(
            role="consensus",
            goal="Resolve primary and challenger outcomes into a final assurance decision.",
            does=[
                "Compare primary and challenger verdicts.",
                "Compute assurance score and consensus state.",
                "Trigger human review where policy requires it.",
            ],
            does_not=[
                "Do not re-scan repository content.",
                "Do not reinterpret raw evidence independently.",
                "Do not override governance triggers.",
            ],
            required_output=[
                "consensus_state: agree|contested",
                "assurance_score",
                "recommended_action",
                "requires_human_review",
            ],
            prompt_template=(
                "You are the consensus role. Combine primary_verdict and challenger_verdict for finding {finding_id} "
                "in report {report_id}. Return consensus_state, assurance_score, recommended_action, "
                "requires_human_review with concise rationale."
            ),
        ),
    ]

    return {
        "version": "1.0",
        "workflow": [
            "adversarial.review_finding",
            "adversarial.challenge_fix",
            "adversarial.compare_verdicts",
        ],
        "roles": [role.to_dict() for role in roles],
    }
