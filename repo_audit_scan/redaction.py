"""Secret and sensitive content redaction."""
import re
from typing import Set


class SecretRedactor:
    """Redacts likely secrets and sensitive data from text."""
    
    # Patterns for common secret formats
    PATTERNS = [
        # API keys and tokens
        (r"(?i)(api[_-]?key|token|password|passwd|pwd|secret)['\"]?\s*[:=]\s*['\"]?([^\s'\"]+)", "***SECRET***"),
        # AWS keys
        (r"AKIA[0-9A-Z]{16}", "***AWS_KEY***"),
        # Private keys
        (r"-----BEGIN (RSA|DSA|EC|PGP|OPENSSH) PRIVATE KEY-----", "***PRIVATE_KEY***"),
        # Email
        (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "***EMAIL***"),
        # URLs with credentials
        (r"(https?://)[^\s:]+:[^\s@]+@", r"\1***:***@"),
        # Slack tokens
        (r"xox[baprs]-\d+[-\w]+", "***SLACK_TOKEN***"),
        # OAuth tokens
        (r"[0-9a-zA-Z]{40}\.[0-9a-zA-Z]{50}", "***OAUTH_TOKEN***"),
        # Credit card-like numbers
        (r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b", "***CARD_NUMBER***"),
    ]
    
    def __init__(self):
        """Initialize the redactor with compiled regex patterns."""
        self.compiled_patterns = [
            (re.compile(pattern, re.MULTILINE), replacement)
            for pattern, replacement in self.PATTERNS
        ]
    
    def redact(self, text: str) -> str:
        """Redact sensitive information from text.
        
        Args:
            text: Text to redact
            
        Returns:
            Text with sensitive information replaced
        """
        if not text:
            return text
        
        redacted = text
        for pattern, replacement in self.compiled_patterns:
            redacted = pattern.sub(replacement, redacted)
        
        return redacted
    
    def redact_evidence_snippet(self, code_snippet: str) -> str:
        """Redact a code evidence snippet for safe reporting.
        
        Args:
            code_snippet: Code snippet from scan results
            
        Returns:
            Redacted code snippet
        """
        return self.redact(code_snippet)
