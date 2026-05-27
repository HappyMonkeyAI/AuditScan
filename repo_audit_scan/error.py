"""Custom exceptions for repo-audit-scan."""


class AuditScanError(Exception):
    """Base exception for repo-audit-scan."""
    pass


class ConfigurationError(AuditScanError):
    """Raised when configuration is invalid."""
    pass


class ScanError(AuditScanError):
    """Raised when a scan fails."""
    pass


class AdapterError(AuditScanError):
    """Raised when an adapter fails."""
    pass


class EnrichmentError(AuditScanError):
    """Raised when dependency enrichment fails."""
    pass


class ValidationError(AuditScanError):
    """Raised when validation fails."""
    pass
