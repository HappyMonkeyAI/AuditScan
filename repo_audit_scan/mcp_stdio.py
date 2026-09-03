"""stdio FastMCP bridge over the in-process MCPServer tool registry.

Catalogue / proxy name: auditscan
Command: uv --directory <AuditScan> run --extra mcp python -m repo_audit_scan.mcp_stdio
"""
from __future__ import annotations

import inspect
from typing import Any, Callable, get_type_hints

from fastmcp import FastMCP

from repo_audit_scan.mcp_server import mcp_server

mcp = FastMCP(
    "auditscan",
    instructions=(
        "Security-focused repository audit scanner (AuditScan / repo-audit-scan). "
        "Use scan_repository on a path, then triage/verify findings. "
        "Adversarial.* tools support Owner-as-Adversary style challenge. "
        "Does not replace human or Owner acceptance (ADR-0001)."
    ),
)


def _mcp_tool_name(registry_name: str) -> str:
    # MCP tool names: prefer underscores over dotted namespaces
    return registry_name.replace(".", "_")


def _bind_tool(registry_name: str, handler: Callable[..., Any]) -> Callable[..., Any]:
    """Build a free function with the same signature as the bound method."""
    sig = inspect.signature(handler)
    # Drop implicit self if present (bound methods already omit self)
    params = list(sig.parameters.values())
    new_sig = sig.replace(parameters=params)

    def _impl(*args: Any, **kwargs: Any) -> Any:
        bound = new_sig.bind(*args, **kwargs)
        bound.apply_defaults()
        return handler(*bound.args, **bound.kwargs)

    _impl.__name__ = _mcp_tool_name(registry_name)
    _impl.__doc__ = inspect.getdoc(handler) or f"AuditScan tool: {registry_name}"
    _impl.__signature__ = new_sig  # type: ignore[attr-defined]
    try:
        _impl.__annotations__ = dict(get_type_hints(handler))
    except Exception:
        _impl.__annotations__ = {
            p.name: (p.annotation if p.annotation is not inspect.Parameter.empty else Any)
            for p in params
        }
        _impl.__annotations__["return"] = Any
    return _impl


def _register_all() -> None:
    for registry_name, handler in sorted(mcp_server.tools.items()):
        fn = _bind_tool(registry_name, handler)
        mcp.tool(name=_mcp_tool_name(registry_name), description=fn.__doc__)(fn)


_register_all()


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
