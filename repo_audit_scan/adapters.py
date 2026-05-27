"""
Language-specific scanner adapters.

Backward-compatibility wrapper that re-exports from adapters_final.
All implementations are in adapters_final to avoid bytecode caching issues.
"""

from repo_audit_scan.adapters_final import (
    LanguageAdapter,
    PythonAdapter,
    JavaScriptAdapter,
    JavaAdapter,
    CSharpAdapter,
    ScanContext,
)

__all__ = [
    'LanguageAdapter',
    'PythonAdapter',
    'JavaScriptAdapter',
    'JavaAdapter',
    'CSharpAdapter',
    'ScanContext',
]
