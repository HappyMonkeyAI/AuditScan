"""Fixed Docker policy for scanning quarantined source.

This module only constructs an allowlisted worker invocation. Repository content
cannot provide the image, command, mounts, or runtime flags.
"""
from __future__ import annotations

from pathlib import Path
import json
import os
import subprocess

WORKER_IMAGE = os.environ.get("AUDITSCAN_WORKER_IMAGE", "repo-audit-scan-worker:local")
WORKER_COMMAND = ("scan", "/workspace", "--profile", "external_repo", "--no-write-reports", "--format", "json")


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


def run_isolated_scan(source: Path, timeout: int = 120) -> dict:
    """Run the fixed worker and return JSON; never execute source on the host."""
    try:
        completed = subprocess.run(build_scan_command(source), capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("isolated worker timed out") from exc
    if completed.returncode != 0:
        raise RuntimeError(f"isolated worker failed with exit code {completed.returncode}: {completed.stderr[-1000:]}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("isolated worker returned invalid JSON") from exc
