"""
Phase 2 — Living Documentation Feedback Loop.

Provides gap detection, patch generation, patch application,
and verification for living documentation paired with audit reports.

Tools exposed via MCP:
  docs.review_living_docs       (read-only)
  docs.propose_living_doc_updates (read-only)
  docs.apply_living_doc_updates  (write, gated)
  docs.verify_living_docs        (read-only)
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class DocGap:
    """A gap between what living docs claim and what the codebase/audit shows."""
    gap_id: str
    doc_file: str           # relative path inside docs_path (or "(none)")
    gap_type: str           # "contradicted" | "stale" | "missing" | "unverifiable"
    description: str
    evidence_doc: str       # excerpt from the doc
    evidence_code: Optional[str]  # relevant audit finding or source excerpt
    related_finding_ids: List[str] = field(default_factory=list)
    suggested_action: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DocPatch:
    """A proposed (not yet applied) Markdown update for a DocGap."""
    patch_id: str           # stable SHA-256 fingerprint used as the apply key
    gap_id: str
    target_file: str        # relative path under docs_path
    insertion_hint: str     # "append" | "after_heading:<H>" | "replace"
    proposed_content: str
    applied: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Living-docs discovery
# ---------------------------------------------------------------------------

_DOC_DIR_CANDIDATES = [
    "docs", "living_docs", "living-docs", ".docs",
    "documentation", "doc",
]


def discover_docs_path(repo_path: Path, docs_path: Optional[str] = None) -> Optional[Path]:
    """Return the living-docs directory, or None if not found."""
    if docs_path:
        p = Path(docs_path)
        return p if p.is_dir() else None
    for candidate in _DOC_DIR_CANDIDATES:
        p = repo_path / candidate
        if p.is_dir():
            return p
    return None


def load_doc_files(docs_path: Path) -> Dict[str, str]:
    """Return {relative_path: content} for all .md files under docs_path."""
    files: Dict[str, str] = {}
    for f in sorted(docs_path.rglob("*.md")):
        rel = str(f.relative_to(docs_path))
        try:
            files[rel] = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass
    return files


# ---------------------------------------------------------------------------
# Gap detection
# ---------------------------------------------------------------------------

_AUTH_CLAIM_KEYWORDS = [
    "authenticated", "requires authentication", "authorization",
    "all endpoints require", "protected route", "jwt",
    "bearer token", "role-based", "rbac", "access control",
]

_AUTH_FINDING_CATEGORIES = frozenset({"authentication", "access-control", "api-security"})

_STALE_LINK_RE = re.compile(r'\]\(\./([^)]+)\)')


def _extract_auth_claims(doc_content: str) -> List[str]:
    return [
        line.strip()
        for line in doc_content.splitlines()
        if any(kw in line.lower() for kw in _AUTH_CLAIM_KEYWORDS)
    ]


def review_living_docs(
    repo_path: Path,
    docs_path: Optional[Path],
    report_data: Optional[Dict[str, Any]] = None,
) -> List[DocGap]:
    """
    Compare living docs with the repo state and an optional audit report.
    Returns a list of DocGap objects.

    Gap types produced:
      contradicted  -- doc claims auth properties contradicted by audit findings
      stale         -- doc references paths that no longer exist in the repo
      missing       -- repo has source files but living-docs coverage is absent
    """
    if docs_path is None or not docs_path.is_dir():
        return []

    doc_files = load_doc_files(docs_path)
    gaps: List[DocGap] = []
    counter = [0]

    def _next_id() -> str:
        counter[0] += 1
        return f"gap-{counter[0]:03d}"

    # -- 1. Contradicted by audit findings ---------------------------------
    if report_data:
        findings = report_data.get("findings", [])
        auth_findings = [
            f for f in findings
            if f.get("category", "").lower() in _AUTH_FINDING_CATEGORIES
        ]
        if auth_findings:
            for doc_rel, doc_content in doc_files.items():
                claims = _extract_auth_claims(doc_content)
                if not claims:
                    continue
                finding_ids = [
                    str(f.get("finding_id", f.get("rule_id", "")))
                    for f in auth_findings[:5]
                ]
                evidence_code = "; ".join(
                    f"{f.get('rule_id','?')}: {f.get('title','')}"
                    for f in auth_findings[:3]
                )
                gaps.append(DocGap(
                    gap_id=_next_id(),
                    doc_file=doc_rel,
                    gap_type="contradicted",
                    description=(
                        f"Doc makes {len(claims)} auth/authorization claim(s) but "
                        f"the audit found {len(auth_findings)} auth/access-control "
                        f"finding(s) that may contradict them."
                    ),
                    evidence_doc=claims[0],
                    evidence_code=evidence_code,
                    related_finding_ids=finding_ids,
                    suggested_action=(
                        "Add a 'Known Security Gaps' section acknowledging the findings, "
                        "or correct the doc to reflect the actual auth posture."
                    ),
                ))

    # -- 2. Stale: broken markdown links to local paths --------------------
    for doc_rel, doc_content in doc_files.items():
        for line in doc_content.splitlines():
            for m in _STALE_LINK_RE.finditer(line):
                ref = m.group(1).split("#")[0]  # strip fragment
                if ref and not (repo_path / ref).exists():
                    gaps.append(DocGap(
                        gap_id=_next_id(),
                        doc_file=doc_rel,
                        gap_type="stale",
                        description=f"Reference to '{ref}' in doc does not exist in the repository.",
                        evidence_doc=line.strip(),
                        evidence_code=None,
                        related_finding_ids=[],
                        suggested_action="Remove or update the broken path reference.",
                    ))

    # -- 3. Missing: substantial repo with no living-doc coverage ----------
    if report_data:
        scanned = report_data.get("summary", {}).get("files_scanned", 0)
        substantive_docs = sum(1 for c in doc_files.values() if len(c.strip()) > 200)
        if scanned > 10 and substantive_docs == 0:
            gaps.append(DocGap(
                gap_id=_next_id(),
                doc_file="(none)",
                gap_type="missing",
                description=(
                    f"Repo has {scanned} scanned files but no substantive "
                    f"living-doc coverage ({len(doc_files)} doc file(s), none >200 chars)."
                ),
                evidence_doc="",
                evidence_code=None,
                related_finding_ids=[],
                suggested_action="Populate living docs using the living_doc_skeleton template.",
            ))

    return gaps


# ---------------------------------------------------------------------------
# Patch generation  (read-only — no files written)
# ---------------------------------------------------------------------------

def _fingerprint(gap_id: str, target: str, content: str) -> str:
    raw = f"{gap_id}:{target}:{content}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    return f"patch-{digest}"


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _render_contradicted_patch(gap: DocGap) -> str:
    finding_list = "\n".join(f"- `{fid}`" for fid in gap.related_finding_ids) or "- (see audit report)"
    return (
        f"\n## Known Security Gaps\n\n"
        f"> **Note (proposed {_today()}):** The following security findings were identified "
        f"by an automated audit and may contradict claims elsewhere in this document. "
        f"Review and resolve before next release.\n\n"
        f"**Related audit findings:**\n{finding_list}\n\n"
        f"**Context:** {gap.description}\n"
    )


def _render_stale_patch(gap: DocGap) -> str:
    return (
        f"\n<!-- Gap {gap.gap_id} (proposed {_today()}): "
        f"Stale reference detected. {gap.description} "
        f"Please update or remove this link. -->\n"
    )


def _render_missing_patch(gap: DocGap) -> str:
    return (
        f"# Living Documentation (Placeholder)\n\n"
        f"<!-- Auto-proposed {_today()}: {gap.description} -->\n\n"
        f"This file is a placeholder. "
        f"Populate it using the `living_doc_skeleton` template.\n"
    )


def propose_living_doc_updates(
    gaps: List[DocGap],
    requested_gap_ids: List[str],
) -> List[DocPatch]:
    """
    Generate Markdown patch proposals for the requested gap IDs.
    No files are written — patches must be approved before applying.
    """
    gap_map = {g.gap_id: g for g in gaps}
    patches: List[DocPatch] = []

    for gap_id in requested_gap_ids:
        gap = gap_map.get(gap_id)
        if gap is None:
            continue

        if gap.gap_type == "contradicted":
            target = gap.doc_file if gap.doc_file != "(none)" else "docs/security.md"
            content = _render_contradicted_patch(gap)
            hint = "append"
        elif gap.gap_type == "stale":
            target = gap.doc_file
            content = _render_stale_patch(gap)
            hint = "append"
        elif gap.gap_type == "missing":
            target = "docs/overview.md"
            content = _render_missing_patch(gap)
            hint = "append"
        else:
            target = gap.doc_file if gap.doc_file != "(none)" else "docs/notes.md"
            content = f"<!-- TODO ({_today()}): Resolve gap {gap_id} — {gap.description} -->\n"
            hint = "append"

        patch_id = _fingerprint(gap_id, target, content)
        patches.append(DocPatch(
            patch_id=patch_id,
            gap_id=gap_id,
            target_file=target,
            insertion_hint=hint,
            proposed_content=content,
        ))

    return patches


# ---------------------------------------------------------------------------
# Patch application  (write, gated)
# ---------------------------------------------------------------------------

AUDIT_LOG_FILENAME = ".audit_log.jsonl"


def apply_patches(
    docs_path: Path,
    approved_patch_ids: List[str],
    actor: str,
    pending_patches: Dict[str, DocPatch],
) -> List[Dict[str, Any]]:
    """
    Apply approved patches to the living-docs directory.

    Safety rules:
    - Only patch IDs present in pending_patches (the session-level propose cache)
      are accepted.  IDs not in the cache are rejected with an error.
    - Every successful apply is recorded in {docs_path}/.audit_log.jsonl with
      actor, timestamp, patch_id, gap_id, target_file, and fingerprint.
    """
    results: List[Dict[str, Any]] = []
    audit_log_path = docs_path / AUDIT_LOG_FILENAME
    timestamp = datetime.now(timezone.utc).isoformat()

    for patch_id in approved_patch_ids:
        if patch_id not in pending_patches:
            results.append({
                "patch_id": patch_id,
                "ok": False,
                "error": (
                    "patch_id not found in the current propose session — "
                    "call docs.propose_living_doc_updates first"
                ),
            })
            continue

        patch = pending_patches[patch_id]
        target = docs_path / patch.target_file
        target.parent.mkdir(parents=True, exist_ok=True)

        try:
            existing = target.read_text(encoding="utf-8") if target.exists() else ""
            target.write_text(existing + patch.proposed_content, encoding="utf-8")
            patch.applied = True
            pending_patches[patch_id] = patch

            log_entry: Dict[str, Any] = {
                "actor": actor,
                "timestamp": timestamp,
                "patch_id": patch_id,
                "gap_id": patch.gap_id,
                "target_file": patch.target_file,
                "fingerprint": patch_id,
            }
            with open(audit_log_path, "a", encoding="utf-8") as lf:
                lf.write(json.dumps(log_entry) + "\n")

            results.append({
                "patch_id": patch_id,
                "ok": True,
                "file_changed": patch.target_file,
                "verification_handle": patch_id,
            })
        except OSError as exc:
            results.append({"patch_id": patch_id, "ok": False, "error": str(exc)})

    return results


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify_gaps(
    repo_path: Path,
    docs_path: Path,
    original_gaps: List[DocGap],
    report_data: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Re-run gap detection against current docs state and report resolution status.
    """
    current_gaps = review_living_docs(
        repo_path=repo_path,
        docs_path=docs_path,
        report_data=report_data,
    )
    # A gap is "resolved" if re-detection no longer surfaces a gap of the same
    # type in the same doc file.  We match by (doc_file, gap_type) since gap IDs
    # are assigned positionally and may shift after edits.
    current_signatures = {(g.doc_file, g.gap_type) for g in current_gaps}
    original_signatures = {(g.doc_file, g.gap_type): g.gap_id for g in original_gaps}

    resolved_ids = [
        gid for (sig, gid) in original_signatures.items()
        if sig not in current_signatures
    ]
    remaining = [
        g.to_dict() for g in original_gaps
        if (g.doc_file, g.gap_type) in current_signatures
    ]

    return {
        "resolved_gap_ids": resolved_ids,
        "remaining_gaps": remaining,
        "total_original": len(original_gaps),
        "total_resolved": len(resolved_ids),
    }
