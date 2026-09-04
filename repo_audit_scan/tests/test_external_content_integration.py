from pathlib import Path
import json
from repo_audit_scan.external_content import run_repo_security_scan


def test_missing_external_engine_is_explicit(tmp_path, monkeypatch):
    monkeypatch.delenv("REPO_SECURITY_SCAN_COMMAND", raising=False)
    findings, metadata = run_repo_security_scan(tmp_path)
    assert findings == []
    assert metadata["status"] == "unavailable"


def test_external_engine_output_is_adapted_and_redacted(tmp_path, monkeypatch):
    output = tmp_path / "scanner.py"
    output.write_text("import json; print(json.dumps({'findings':[{'file':'x.py','line':3,'secret':'token'}]}))", encoding="utf-8")
    monkeypatch.setenv("REPO_SECURITY_SCAN_COMMAND", f"python {output}")
    findings, metadata = run_repo_security_scan(tmp_path)
    assert metadata["status"] == "completed"
    assert len(findings) == 1
    assert findings[0].evidence[0].code_snippet == "[REDACTED]"
    assert findings[0].manual_confirmation_required is True


def test_external_engine_text_cli_output_is_adapted(tmp_path, monkeypatch):
    output = tmp_path / "scanner.py"
    output.write_text("print('Scan complete: 2 unique finding(s) across 2 raw match(es).')", encoding="utf-8")
    monkeypatch.setenv("REPO_SECURITY_SCAN_COMMAND", f"python {output}")
    findings, metadata = run_repo_security_scan(tmp_path)
    assert metadata["status"] == "completed"
    assert len(findings) == 2
    assert all(item.evidence[0].code_snippet == "[REDACTED]" for item in findings)
