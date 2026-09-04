"""Fixed Docker policy for scanning quarantined source.

This module only constructs an allowlisted worker invocation. Repository content
cannot provide the image, command, mounts, or runtime flags.
"""
from __future__ import annotations

from pathlib import Path

WORKER_IMAGE = "python:3.12-slim"
WORKER_COMMAND = ("python", "-m", "repo_audit_scan", "scan", "/workspace", "--profile", "external_repo", "--no-write-reports", "--format", "json")


def build_scan_command(source: Path) -> list[str]:
    source = source.resolve()
    if not source.is_dir():
        raise ValueError("quarantine source must be a directory")
    return [
        "docker", "run", "--rm", "--network", "none",
        "--read-only", "--cpus", "1", "--memory", "512m", "--pids-limit", "128",
        "--mount", f"type=bind,src={source},dst=/workspace,readonly",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
        WORKER_IMAGE, *WORKER_COMMAND,
    ]
