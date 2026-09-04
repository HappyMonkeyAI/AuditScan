"""Core data models for repo-audit-scan."""
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
from enum import Enum
from datetime import datetime
import json


class Severity(str, Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    """Finding confidence levels."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class CompromiseMode(str, Enum):
    """IAN compromise mode classification."""
    COVER = "cover"
    TRIAGE = "triage"
    ASSUME_BREACH = "assume_breach"


class AssessmentStatus(str, Enum):
    """Overall completeness state of an external-content assessment."""
    COMPLETE = "complete"
    DEGRADED = "degraded"
    BLOCKED = "blocked"


class AssessmentDisposition(str, Enum):
    """Policy disposition for externally sourced content."""
    ALLOW_REVIEW = "allow_review"
    NEEDS_HUMAN_REVIEW = "needs_human_review"
    BLOCK = "block"


@dataclass
class Evidence:
    """Evidence snippet for a finding."""
    file_path: str
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    code_snippet: Optional[str] = None
    context: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Evidence":
        """Create from dictionary."""
        return cls(**data)


@dataclass
class RuleResult:
    """Result from a single rule evaluation."""
    rule_id: str
    rule_title: str
    category: str
    severity: Severity
    confidence: Confidence
    evidence: List[Evidence]
    remediation_guidance: str
    manual_confirmation_required: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = asdict(self)
        data["severity"] = self.severity.value
        data["confidence"] = self.confidence.value
        data["evidence"] = [e.to_dict() for e in self.evidence]
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RuleResult":
        """Create from dictionary."""
        data_copy = data.copy()
        data_copy["severity"] = Severity(data_copy["severity"])
        data_copy["confidence"] = Confidence(data_copy["confidence"])
        data_copy["evidence"] = [Evidence.from_dict(e) for e in data_copy.get("evidence", [])]
        return cls(**data_copy)


@dataclass
class Finding:
    """Security finding detected in a repository."""
    finding_id: str
    rule_id: str
    rule_title: str
    category: str
    severity: Severity
    confidence: Confidence
    evidence: List[Evidence]
    remediation_guidance: str
    ian_score: Optional[float] = None
    compromise_mode: Optional[CompromiseMode] = None
    prioritization_rationale: Optional[str] = None
    affected_files_count: int = 0
    manual_confirmation_required: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = asdict(self)
        data["severity"] = self.severity.value
        data["confidence"] = self.confidence.value
        if self.compromise_mode:
            data["compromise_mode"] = self.compromise_mode.value
        data["evidence"] = [e.to_dict() for e in self.evidence]
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        """Create from dictionary."""
        data_copy = data.copy()
        data_copy["severity"] = Severity(data_copy["severity"])
        data_copy["confidence"] = Confidence(data_copy["confidence"])
        if data_copy.get("compromise_mode"):
            data_copy["compromise_mode"] = CompromiseMode(data_copy["compromise_mode"])
        data_copy["evidence"] = [Evidence.from_dict(e) for e in data_copy.get("evidence", [])]
        return cls(**data_copy)


@dataclass
class ScanMetadata:
    """Metadata about a scan."""
    schema_version: str
    tool_version: str
    scan_timestamp: str
    git_remote: Optional[str] = None
    git_branch: Optional[str] = None
    git_commit: Optional[str] = None
    repository_path: str = "."
    skipped_files_count: int = 0
    scanned_files_count: int = 0
    detected_languages: List[str] = field(default_factory=list)
    detected_frameworks: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanMetadata":
        """Create from dictionary."""
        return cls(**data)


@dataclass
class ExternalTarget:
    """Origin and immutable identity of externally assessed content."""
    kind: str
    origin: str
    resolved_ref: Optional[str] = None
    content_digest: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExternalTarget":
        return cls(**data)


@dataclass
class ExternalCheck:
    """Status of one required assessment component."""
    name: str
    status: str
    detail: Optional[str] = None

    VALID_STATUSES = frozenset({"completed", "skipped", "failed", "unavailable"})

    def __post_init__(self) -> None:
        if self.status not in self.VALID_STATUSES:
            raise ValueError(f"Invalid external check status: {self.status}")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExternalCheck":
        return cls(**data)


@dataclass
class AgentPolicy:
    """Allowed downstream actions after assessing untrusted content."""
    read_source: bool = True
    install: bool = False
    execute: bool = False
    register_mcp: bool = False
    write_memory: bool = False

    def __post_init__(self) -> None:
        if self.install or self.execute or self.register_mcp or self.write_memory:
            raise ValueError("External content cannot grant operational or memory-write access")

    def to_dict(self) -> Dict[str, bool]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentPolicy":
        return cls(**data)


@dataclass
class ExternalAssessment:
    """Machine-readable assessment and policy handoff for external content."""
    target: ExternalTarget
    profile: str
    status: AssessmentStatus
    disposition: AssessmentDisposition
    checks: List[ExternalCheck] = field(default_factory=list)
    policy: AgentPolicy = field(default_factory=AgentPolicy)

    def __post_init__(self) -> None:
        self.status = AssessmentStatus(self.status)
        self.disposition = AssessmentDisposition(self.disposition)
        if self.disposition is not AssessmentDisposition.ALLOW_REVIEW and self.status is AssessmentStatus.COMPLETE:
            raise ValueError("Only allow_review may be complete")
        if self.status is AssessmentStatus.BLOCKED and self.disposition is not AssessmentDisposition.BLOCK:
            raise ValueError("Blocked assessments must have block disposition")

    @property
    def checks_by_status(self) -> Dict[str, List[str]]:
        grouped = {status: [] for status in ExternalCheck.VALID_STATUSES}
        for check in self.checks:
            grouped[check.status].append(check.name)
        return grouped

    def to_dict(self) -> Dict[str, Any]:
        grouped = self.checks_by_status
        return {
            "target": self.target.to_dict(),
            "profile": self.profile,
            "status": self.status.value,
            "disposition": self.disposition.value,
            "checks": {
                "completed": grouped["completed"],
                "skipped": grouped["skipped"],
                "failed": grouped["failed"],
                "unavailable": grouped["unavailable"],
            },
            "check_details": [check.to_dict() for check in self.checks],
            "policy": self.policy.to_dict(),
            "untrusted_content": True,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExternalAssessment":
        return cls(
            target=ExternalTarget.from_dict(data["target"]),
            profile=data["profile"],
            status=AssessmentStatus(data["status"]),
            disposition=AssessmentDisposition(data["disposition"]),
            checks=[ExternalCheck.from_dict(check) for check in data.get("check_details", [])],
            policy=AgentPolicy.from_dict(data.get("policy", {})),
        )


@dataclass
class Report:
    """Complete audit report."""
    report_id: str
    metadata: ScanMetadata
    findings: List[Finding] = field(default_factory=list)
    summary: Optional[str] = None
    assessment: Optional[ExternalAssessment] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "report_id": self.report_id,
            "metadata": self.metadata.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary,
            "assessment": self.assessment.to_dict() if self.assessment else None,
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Report":
        """Create from dictionary."""
        return cls(
            report_id=data["report_id"],
            metadata=ScanMetadata.from_dict(data["metadata"]),
            findings=[Finding.from_dict(f) for f in data.get("findings", [])],
            summary=data.get("summary"),
            assessment=ExternalAssessment.from_dict(data["assessment"]) if data.get("assessment") else None,
        )

    @classmethod
    def from_json(cls, json_str: str) -> "Report":
        """Create from JSON string."""
        return cls.from_dict(json.loads(json_str))


@dataclass
class ScanConfig:
    """Configuration for a scan."""
    repository_path: str
    profiles: List[str] = field(default_factory=lambda: ["universal"])
    enabled_adapters: List[str] = field(default_factory=list)
    max_file_size: int = 10 * 1024 * 1024  # 10 MB
    max_files: int = 100000
    enable_enrichment: bool = False
    fail_open_on_enrichment_error: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanConfig":
        """Create from dictionary."""
        return cls(**data)
