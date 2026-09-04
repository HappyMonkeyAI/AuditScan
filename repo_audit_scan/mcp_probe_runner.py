"""Fixed-template MCP probe contract; no arbitrary commands or payloads."""
from __future__ import annotations
from dataclasses import dataclass

PROBES = frozenset({"scope_boundary", "oversized_argument", "controlled_injection", "malformed_schema"})

@dataclass(frozen=True)
class ProbeResult:
    name: str
    status: str
    detail: str


def run_fixed_probe(target: str, probe: str) -> ProbeResult:
    if probe not in PROBES:
        raise ValueError("unsupported fixed probe")
    # Dynamic execution is intentionally unavailable until a container runtime is configured.
    return ProbeResult(probe, "unavailable", "isolated probe runner is not configured")
