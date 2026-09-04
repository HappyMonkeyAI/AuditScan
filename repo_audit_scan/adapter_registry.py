"""
Adapter registry and loader.

Provides:
- AdapterRegistry: Central registry for language adapters
- Adapter loading and discovery
- Language/file resolution
"""

from typing import Dict, List, Optional, Set
from pathlib import Path

from repo_audit_scan.adapters_final import (
    LanguageAdapter,
    PythonAdapter,
    JavaScriptAdapter,
    JavaAdapter,
    CSharpAdapter,
    PhpAdapter,
    CICDAdapter,
    DockerAdapter,
    ExternalContentAdapter,
)


class AdapterRegistry:
    """
    Registry for language-specific adapters.

    Manages adapter loading, discovery, and resolution.
    Supports dynamic registration and language detection.
    """

    def __init__(self):
        """Initialize registry with built-in adapters."""
        self._adapters: Dict[str, LanguageAdapter] = {}
        self._load_builtin_adapters()

    def _load_builtin_adapters(self):
        """Load built-in language adapters."""
        builtin_adapters = [
            PythonAdapter(),
            JavaScriptAdapter(),
            JavaAdapter(),
            CSharpAdapter(),
            PhpAdapter(),
            CICDAdapter(),
            DockerAdapter(),
            ExternalContentAdapter(),
        ]

        for adapter in builtin_adapters:
            self._adapters[adapter.language] = adapter

    def register_adapter(self, adapter: LanguageAdapter):
        """
        Register a custom adapter.

        Args:
            adapter: Adapter to register
        """
        self._adapters[adapter.language] = adapter

    def get_adapter(self, language: str) -> Optional[LanguageAdapter]:
        """
        Get adapter for a language.

        Args:
            language: Language name (e.g., 'python', 'javascript')

        Returns:
            Adapter if found, None otherwise
        """
        return self._adapters.get(language.lower())

    def resolve_language(self, file_path: str) -> Optional[str]:
        """
        Resolve language for a file based on extension and adapter detection.

        Args:
            file_path: Path to file

        Returns:
            Language name if detected, None otherwise
        """
        file_path_lower = file_path.lower()

        # Try each adapter
        for language, adapter in self._adapters.items():
            if adapter.detect_language(file_path):
                return language

        return None

    def resolve_adapter(self, file_path: str) -> Optional[LanguageAdapter]:
        """
        Resolve the appropriate adapter for a file.

        Args:
            file_path: Path to file

        Returns:
            Adapter if found, None otherwise
        """
        language = self.resolve_language(file_path)
        if language:
            return self.get_adapter(language)
        return None

    def supported_languages(self) -> List[str]:
        """
        Get list of supported languages.

        Returns:
            Sorted list of language names
        """
        return sorted(self._adapters.keys())

    def supported_extensions(self) -> Dict[str, str]:
        """
        Get mapping of file extensions to languages.

        Returns:
            Dict mapping extension (e.g., '.py') to language name
        """
        extensions = {}

        # Python
        for ext in ['.py']:
            extensions[ext] = 'python'

        # JavaScript/TypeScript
        for ext in ['.js', '.jsx', '.ts', '.tsx']:
            extensions[ext] = 'javascript'

        # Java
        for ext in ['.java']:
            extensions[ext] = 'java'

        # C#
        for ext in ['.cs']:
            extensions[ext] = 'csharp'

        # PHP
        for ext in ['.php', '.phtml', '.php3', '.php4', '.php5']:
            extensions[ext] = 'php'

        return extensions

    def get_frameworks_for_language(self, language: str) -> List[str]:
        """
        Get supported frameworks for a language.

        Args:
            language: Language name

        Returns:
            List of framework names
        """
        adapter = self.get_adapter(language)
        if adapter:
            return adapter.supported_frameworks
        return []

    def count_adapters(self) -> int:
        """Get count of registered adapters."""
        return len(self._adapters)

    def to_dict(self) -> dict:
        """Serialize registry to dict."""
        return {
            "adapters": sorted(self._adapters.keys()),
            "count": len(self._adapters),
            "extensions": self.supported_extensions(),
        }


# Global registry instance
_global_registry: Optional[AdapterRegistry] = None


def get_registry() -> AdapterRegistry:
    """Get or create global adapter registry."""
    global _global_registry
    if _global_registry is None:
        _global_registry = AdapterRegistry()
    return _global_registry


def resolve_adapter(file_path: str) -> Optional[LanguageAdapter]:
    """
    Convenience function to resolve adapter for a file.

    Args:
        file_path: Path to file

    Returns:
        Adapter if found, None otherwise
    """
    return get_registry().resolve_adapter(file_path)


def resolve_language(file_path: str) -> Optional[str]:
    """
    Convenience function to resolve language for a file.

    Args:
        file_path: Path to file

    Returns:
        Language name if detected, None otherwise
    """
    return get_registry().resolve_language(file_path)
