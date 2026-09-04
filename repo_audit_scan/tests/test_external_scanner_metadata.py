from pathlib import Path

from repo_audit_scan.external_content import run_repo_security_scan


def test_scanner_metadata_includes_operator_revision(monkeypatch, tmp_path):
    scanner = tmp_path / "scanner.py"
    scanner.write_text("import sys; print('{\"findings\": []}')", encoding="utf-8")
    monkeypatch.setenv("REPO_SECURITY_SCAN_COMMAND", f"python {scanner}")
    monkeypatch.setenv("REPO_SECURITY_SCAN_REVISION", "fa9a0d0244d1f6187bf0edf89d991a1e6a837405")
    monkeypatch.setenv("REPO_SECURITY_SCAN_VERSION", "local-pinned")
    findings, metadata = run_repo_security_scan(tmp_path)
    assert findings == []
    assert metadata["scanner"] == "repo-security-scan"
    assert metadata["revision"] == "fa9a0d0244d1f6187bf0edf89d991a1e6a837405"
    assert metadata["version"] == "local-pinned"


def test_scanner_metadata_never_includes_command(monkeypatch):
    monkeypatch.delenv("REPO_SECURITY_SCAN_COMMAND", raising=False)
    _, metadata = run_repo_security_scan(Path("."))
    assert "command" not in metadata
