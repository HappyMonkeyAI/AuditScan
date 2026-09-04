"""Evidence-constrained semantic review contract.

This module validates reviewer output; it never executes reviewer-authored code.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any

@dataclass(frozen=True)
class ReviewCandidate:
    rule_id: str
    file_path: str
    start_line: int
    end_line: int
    evidence: str


def validate_review_response(response: Any, candidates: list[ReviewCandidate]) -> dict[str, Any]:
    if not isinstance(response, dict) or not isinstance(response.get("findings", []), list):
        raise ValueError("review response must be an object with findings")
    allowed = {(c.rule_id, c.file_path, c.start_line, c.end_line) for c in candidates}
    accepted = []
    for item in response["findings"]:
        if not isinstance(item, dict):
            raise ValueError("review finding must be an object")
        key = (item.get("rule_id"), item.get("file_path"), item.get("start_line"), item.get("end_line"))
        if key not in allowed:
            raise ValueError("review finding is not grounded in a deterministic candidate")
        if any(name in item for name in ("command", "probe", "code", "shell")):
            raise ValueError("review output cannot contain commands or probes")
        accepted.append({"rule_id": key[0], "file_path": key[1], "start_line": key[2], "end_line": key[3], "decision": item.get("decision", "review")})
    return {"status": "complete_semantic", "findings": accepted}
