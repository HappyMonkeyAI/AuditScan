from pathlib import Path
import pytest
from repo_audit_scan.quarantine_worker import build_scan_command


def test_worker_command_is_networkless_readonly_and_bounded(tmp_path):
    command = build_scan_command(tmp_path)
    assert command[0:7] == ["docker", "run", "--rm", "--network", "none", "--read-only", "--cpus"]
    assert "--memory" in command and "--pids-limit" in command
    mount = command[command.index("--mount") + 1]
    assert "readonly" in mount
    assert "--write-reports" not in command


def test_worker_rejects_file_source(tmp_path):
    source = tmp_path / "file"
    source.write_text("data", encoding="utf-8")
    with pytest.raises(ValueError):
        build_scan_command(source)
