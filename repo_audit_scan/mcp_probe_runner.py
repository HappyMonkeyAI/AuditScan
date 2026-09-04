"""Fixed-template MCP probe runner for trusted operator-configured targets."""
from __future__ import annotations

import json
import os
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path

PROBES = ("scope_boundary", "oversized_argument", "controlled_injection", "malformed_schema")

@dataclass(frozen=True)
class ProbeResult:
    name: str
    status: str
    detail: str


def run_fixed_probe(target: str, probe: str) -> ProbeResult:
    if probe not in PROBES:
        raise ValueError("unsupported fixed probe")
    command_text = os.environ.get("AUDITSCAN_TRUSTED_MCP_COMMAND", "").strip()
    if not command_text:
        return ProbeResult(probe, "unavailable", "trusted MCP target command is not configured")
    command = shlex.split(command_text, posix=False)
    requests = [
        {"jsonrpc":"2.0", "id":1, "method":"initialize", "params":{}},
        {"jsonrpc":"2.0", "id":2, "method":"tools/call", "params":{"name":f"auditscan_probe_{probe}","arguments":{}}},
    ]
    try:
        completed = subprocess.run(command, input="\n".join(json.dumps(item) for item in requests) + "\n", text=True, capture_output=True, timeout=15, check=False, env={"PATH": os.environ.get("PATH", "")})
    except (OSError, subprocess.TimeoutExpired) as exc:
        return ProbeResult(probe, "failed", type(exc).__name__)
    if completed.returncode != 0:
        return ProbeResult(probe, "failed", f"exit={completed.returncode}")
    try:
        replies = [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
        response = next(item for item in replies if item.get("id") == 2)
        result = response.get("result", {})
        return ProbeResult(probe, "completed" if result.get("ok") else "failed", str(result.get("result", "no result")))
    except (ValueError, StopIteration, json.JSONDecodeError):
        return ProbeResult(probe, "failed", "invalid MCP JSON-RPC response")


def run_all_fixed_probes() -> list[ProbeResult]:
    return [run_fixed_probe("trusted-configured-target", probe) for probe in PROBES]
