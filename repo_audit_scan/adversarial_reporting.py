"""Assurance artifact writers for adversarial workflow outputs."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict


def write_assurance_json(output_dir: str | Path, payload: Dict[str, Any]) -> Path:
    """Write assurance JSON artifact."""
    target_dir = Path(output_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    path = target_dir / "assurance.json"
    envelope = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "schema_version": "1.0",
        "assurance": payload,
    }
    path.write_text(json.dumps(envelope, indent=2, sort_keys=True), encoding="utf-8")
    return path


def write_assurance_markdown(output_dir: str | Path, payload: Dict[str, Any]) -> Path:
    """Write assurance Markdown artifact."""
    target_dir = Path(output_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    path = target_dir / "assurance.md"

    lines = [
        "# Assurance Report",
        "",
        f"- Report ID: `{payload.get('report_id', 'unknown')}`",
        f"- Finding ID: `{payload.get('finding_id', 'unknown')}`",
        f"- Primary verdict: `{payload.get('primary_verdict', 'unknown')}`",
        f"- Challenger verdict: `{payload.get('challenger_verdict', 'unknown')}`",
        f"- Consensus: `{payload.get('consensus_state', 'unknown')}`",
        f"- Assurance score: `{payload.get('assurance_score', 'unknown')}`",
        f"- Recommended action: `{payload.get('recommended_action', 'unknown')}`",
        f"- Human review required: `{payload.get('requires_human_review', False)}`",
        "",
        "## Notes",
        "",
        "- This artifact summarizes adversarial consensus for closure decisions.",
        "- Treat any contested critical finding as requiring manual review.",
    ]
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return path


def write_assurance_artifacts(output_dir: str | Path, payload: Dict[str, Any]) -> Dict[str, Path]:
    """Write both assurance.json and assurance.md artifacts."""
    return {
        "json": write_assurance_json(output_dir, payload),
        "markdown": write_assurance_markdown(output_dir, payload),
    }
