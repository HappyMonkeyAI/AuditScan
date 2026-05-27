"""Unit tests for secret redaction."""
import pytest
from repo_audit_scan.redaction import SecretRedactor


@pytest.fixture
def redactor():
    """Create a SecretRedactor instance."""
    return SecretRedactor()


def test_redact_api_key(redactor):
    """Test redaction of API keys."""
    text = 'api_key = "sk_live_abc123def456"'
    redacted = redactor.redact(text)
    assert "sk_live_abc123def456" not in redacted
    assert "***" in redacted


def test_redact_password(redactor):
    """Test redaction of passwords."""
    text = 'password: "MySecurePassword123"'
    redacted = redactor.redact(text)
    assert "MySecurePassword123" not in redacted
    assert "***" in redacted


def test_redact_aws_key(redactor):
    """Test redaction of AWS keys."""
    text = "AKIA2ABC3DEF4GHI5JKL"
    redacted = redactor.redact(text)
    assert "AKIA2ABC3DEF4GHI5JKL" not in redacted
    assert "***" in redacted


def test_redact_private_key(redactor):
    """Test redaction of private keys."""
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA..."
    redacted = redactor.redact(text)
    assert "-----BEGIN RSA PRIVATE KEY-----" not in redacted


def test_redact_email(redactor):
    """Test redaction of email addresses."""
    text = "Contact: user@example.com for details"
    redacted = redactor.redact(text)
    assert "user@example.com" not in redacted
    assert "***EMAIL***" in redacted


def test_preserve_non_secret_text(redactor):
    """Test that non-secret text is preserved."""
    text = "This is a normal code comment without any secrets"
    redacted = redactor.redact(text)
    assert redacted == text


def test_redact_evidence_snippet(redactor):
    """Test redaction of a code evidence snippet."""
    snippet = """
    db.execute(f"SELECT * FROM users WHERE id={user_id}")
    config = {"api_key": "secret_key_123"}
    """
    redacted = redactor.redact_evidence_snippet(snippet)
    assert "secret_key_123" not in redacted


def test_empty_string(redactor):
    """Test redaction of empty string."""
    assert redactor.redact("") == ""


def test_none_input(redactor):
    """Test redaction of None input."""
    assert redactor.redact(None) is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
