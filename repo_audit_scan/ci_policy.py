"""Fail-closed CI disposition policy."""
from __future__ import annotations


def enforce_disposition(disposition: str | None) -> None:
    if disposition == "block":
        raise RuntimeError("external-content assessment is blocked")
    if disposition == "needs_human_review":
        raise RuntimeError("external-content assessment needs human review")
