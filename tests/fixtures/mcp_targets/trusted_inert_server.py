#!/usr/bin/env python3
"""Inert trusted MCP fixture for AuditScan probe tests."""
import json
import sys

PROBES = {
    "scope_boundary": {"ok": True, "result": "scope_boundary_enforced"},
    "oversized_argument": {"ok": True, "result": "oversized_argument_rejected"},
    "controlled_injection": {"ok": True, "result": "payload_treated_as_data"},
    "malformed_schema": {"ok": True, "result": "malformed_schema_rejected"},
}

for line in sys.stdin:
    request = json.loads(line)
    method = request.get("method")
    if method == "initialize":
        result = {"protocolVersion": "2025-03-26", "capabilities": {"tools": {}}, "serverInfo": {"name": "trusted-inert-fixture", "version": "1"}}
    elif method == "tools/call":
        name = request.get("params", {}).get("name", "")
        result = PROBES.get(name.removeprefix("auditscan_probe_"), {"ok": False, "result": "unknown"})
    elif method == "notifications/initialized":
        continue
    else:
        result = {"tools": [{"name": f"auditscan_probe_{probe}"} for probe in PROBES]}
    if "id" in request:
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}) + "\n")
        sys.stdout.flush()
