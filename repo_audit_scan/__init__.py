"""repo-audit-scan: Security-focused code audit scanner."""

__version__ = "0.1.0"
__author__ = "AuditScan Team"
__license__ = "MIT"

from repo_audit_scan.models import (
    Finding,
    Report,
    ScanConfig,
    ScanMetadata,
    RuleResult,
    Evidence,
    Severity,
    Confidence,
    CompromiseMode,
)
from repo_audit_scan.error import AuditScanError
from repo_audit_scan.redaction import SecretRedactor
from repo_audit_scan.config import load_config, validate_config
from repo_audit_scan.inventory import FilesystemWalker, RepositoryInventory, FileMetadata
from repo_audit_scan.git_utils import extract_git_metadata, GitMetadata
from repo_audit_scan.rules import Rule, RuleRegistry, DuplicationHandler, ManualConfirmation
from repo_audit_scan.reporting import JSONReportWriter, MarkdownReportWriter, ReportArtifactWriter
from repo_audit_scan.triage import TriageMarkdownWriter, ScanReviewMarkdownWriter, TriageArtifactWriter

__all__ = [
    "Finding",
    "Report",
    "ScanConfig",
    "ScanMetadata",
    "RuleResult",
    "Evidence",
    "Severity",
    "Confidence",
    "CompromiseMode",
    "AuditScanError",
    "SecretRedactor",
    "load_config",
    "validate_config",
    "FilesystemWalker",
    "RepositoryInventory",
    "FileMetadata",
    "extract_git_metadata",
    "GitMetadata",
    "Rule",
    "RuleRegistry",
    "DuplicationHandler",
    "ManualConfirmation",
    "JSONReportWriter",
    "MarkdownReportWriter",
    "ReportArtifactWriter",
    "TriageMarkdownWriter",
    "ScanReviewMarkdownWriter",
    "TriageArtifactWriter",
]
