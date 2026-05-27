"""
Rule registry and protocol for audit rule management.

Provides:
- Rule: Protocol/dataclass for audit rules
- RuleRegistry: Registry with load, get, list, and deduplication
- Deduplication: Aggregate multiple rule matches into single finding
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from enum import Enum
import json
from pathlib import Path

from repo_audit_scan.models import Severity, Evidence


@dataclass
class Rule:
    """A single audit rule to be executed against a codebase."""

    rule_id: str  # Unique identifier: "py-001", "php-wp-002", etc.
    category: str  # Category: "secrets", "injection", "auth", "data-validation", etc.
    title: str  # Short title: "Hardcoded API key"
    description: str  # Longer description explaining the issue
    severity: Severity  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    checks: List[Dict] = field(default_factory=list)  # Language-specific checks (regex, AST patterns, etc.)
    remediation_guidance: str = ""  # How to fix
    requires_manual_confirmation: bool = False  # If true, analyst must explicitly confirm

    def to_dict(self) -> dict:
        """Serialize to dict."""
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "checks": self.checks,
            "remediation_guidance": self.remediation_guidance,
            "requires_manual_confirmation": self.requires_manual_confirmation,
        }

    @staticmethod
    def from_dict(data: dict) -> "Rule":
        """Deserialize from dict."""
        return Rule(
            rule_id=data["rule_id"],
            category=data["category"],
            title=data["title"],
            description=data["description"],
            severity=Severity(data["severity"]),
            checks=data.get("checks", []),
            remediation_guidance=data.get("remediation_guidance", ""),
            requires_manual_confirmation=data.get("requires_manual_confirmation", False),
        )


class RuleRegistry:
    """
    Registry of audit rules.

    Supports:
    - Loading rules from JSON/YAML files
    - Getting rules by ID or category
    - Listing all rules
    - Deduplication of rule matches
    """

    def __init__(self):
        self._rules: Dict[str, Rule] = {}
        self._categories: Dict[str, List[str]] = {}  # category -> [rule_ids]

    def add_rule(self, rule: Rule) -> None:
        """Register a single rule."""
        self._rules[rule.rule_id] = rule

        # Update category index
        if rule.category not in self._categories:
            self._categories[rule.category] = []
        self._categories[rule.category].append(rule.rule_id)

    def load_from_dict(self, data: Dict) -> None:
        """
        Load rules from a dictionary.

        Expected format:
        {
            "rules": [
                {
                    "rule_id": "py-001",
                    "category": "secrets",
                    "title": "Hardcoded API key",
                    "description": "...",
                    "severity": "HIGH",
                    "checks": [...],
                    "remediation_guidance": "..."
                },
                ...
            ]
        }
        """
        rules_data = data.get("rules", [])
        for rule_data in rules_data:
            rule = Rule.from_dict(rule_data)
            self.add_rule(rule)

    def load_from_file(self, file_path: str) -> None:
        """
        Load rules from a JSON file.

        Args:
            file_path: Path to JSON file with rules
        """
        file_path = Path(file_path)
        with open(file_path, "r") as f:
            data = json.load(f)
        self.load_from_dict(data)

    def get_by_id(self, rule_id: str) -> Optional[Rule]:
        """Get a rule by its ID."""
        return self._rules.get(rule_id)

    def get_by_category(self, category: str) -> List[Rule]:
        """Get all rules in a category."""
        rule_ids = self._categories.get(category, [])
        return [self._rules[rid] for rid in rule_ids]

    def list_all(self) -> List[Rule]:
        """List all registered rules."""
        return list(self._rules.values())

    def categories(self) -> List[str]:
        """List all categories."""
        return sorted(list(self._categories.keys()))

    def count(self) -> int:
        """Total number of registered rules."""
        return len(self._rules)

    def to_dict(self) -> dict:
        """Serialize all rules to dict."""
        return {
            "rules": [rule.to_dict() for rule in self.list_all()]
        }


class DuplicationHandler:
    """
    Handles deduplication of rule matches.

    When the same rule is found multiple times in different files or locations,
    aggregate the evidence into a single Finding with an evidence array.
    """

    @staticmethod
    def deduplicate(
        findings_dict: Dict[str, List],  # rule_id -> list of RuleResult
    ) -> Dict[str, any]:
        """
        Aggregate findings by rule_id.

        Args:
            findings_dict: Dictionary mapping rule_id to list of RuleResult objects

        Returns:
            Dictionary with deduplicated results:
            {
                "rule_id": {
                    "rule": Rule object,
                    "evidence_count": int,
                    "evidence": [Evidence, Evidence, ...],
                    "affected_files_count": int,
                    "sample_locations": [...]  # First 5 locations
                }
            }
        """
        deduplicated = {}

        for rule_id, results in findings_dict.items():
            if not results:
                continue

            # Take first result to get rule metadata
            first_result = results[0]

            # Aggregate all evidence
            all_evidence = []
            affected_files: Set[str] = set()

            for result in results:
                all_evidence.extend(result.evidence)
                if result.evidence:
                    affected_files.update({e.file_path for e in result.evidence})

            # Get sample locations (first 5 unique file paths)
            sample_locations = list(affected_files)[:5]

            deduplicated[rule_id] = {
                "rule": first_result,
                "evidence_count": len(all_evidence),
                "evidence": all_evidence,
                "affected_files_count": len(affected_files),
                "sample_locations": sample_locations,
            }

        return deduplicated


class ManualConfirmation:
    """
    Tracks manual confirmations of audit findings.

    Security analysts can explicitly mark a finding as:
    - CONFIRMED: This is a real vulnerability
    - DISMISSED: This is a false positive or not applicable
    - DEFERRED: Need more information
    """

    class Status(Enum):
        """Manual confirmation status."""
        UNREVIEWED = "unreviewed"
        CONFIRMED = "confirmed"
        DISMISSED = "dismissed"
        DEFERRED = "deferred"

    def __init__(self):
        self._confirmations: Dict[str, Dict] = {}  # rule_id -> {status, note, timestamp}

    def confirm(self, rule_id: str, status: "ManualConfirmation.Status", note: str = "") -> None:
        """
        Record manual confirmation for a rule finding.

        Args:
            rule_id: The rule ID
            status: CONFIRMED, DISMISSED, or DEFERRED
            note: Optional analyst note
        """
        import datetime

        self._confirmations[rule_id] = {
            "status": status.value,
            "note": note,
            "confirmed_at": datetime.datetime.utcnow().isoformat(),
        }

    def get_status(self, rule_id: str) -> Optional[Status]:
        """Get confirmation status for a rule."""
        if rule_id not in self._confirmations:
            return self.Status.UNREVIEWED

        status_str = self._confirmations[rule_id]["status"]
        return self.Status(status_str)

    def is_confirmed(self, rule_id: str) -> bool:
        """Check if a finding is confirmed as real."""
        return self.get_status(rule_id) == self.Status.CONFIRMED

    def is_dismissed(self, rule_id: str) -> bool:
        """Check if a finding is dismissed as false positive."""
        return self.get_status(rule_id) == self.Status.DISMISSED

    def to_dict(self) -> dict:
        """Serialize confirmations."""
        return self._confirmations
