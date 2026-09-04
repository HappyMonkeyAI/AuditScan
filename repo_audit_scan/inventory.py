"""
Filesystem walker and repository inventory builder.

Provides:
- FilesystemWalker: Traverses directories with excludes, size caps, symlink guards
- RepositoryInventory: Aggregated file metadata and statistics
- Language/framework detection via file extensions
"""

import os
import sys
from pathlib import Path
from dataclasses import dataclass, field
from typing import Set, Dict, List, Optional
import pathspec

# Common excludes (similar to .gitignore)
DEFAULT_EXCLUDES = [
    ".git/**",
    ".gitignore",
    "__pycache__/**",
    "*.pyc",
    "node_modules/**",
    ".venv/**",
    "venv/**",
    ".env",
    ".DS_Store",
    "*.o",
    "*.so",
    "build/**",
    "dist/**",
    "**/dist/**",
    "**/.next/**",
    ".pytest_cache/**",
    ".mypy_cache/**",
    ".ruff_cache/**",
]

# Language detection by file extension
LANGUAGE_EXTENSIONS = {
    "python": {".py", ".pyi"},
    "javascript": {".js", ".mjs", ".cjs"},
    "typescript": {".ts", ".tsx"},
    "php": {".php", ".phtml", ".php3", ".php4", ".php5"},
    "java": {".java"},
    "csharp": {".cs"},
    "cpp": {".cpp", ".cc", ".cxx", ".h", ".hpp"},
    "c": {".c", ".h"},
    "rust": {".rs"},
    "go": {".go"},
    "ruby": {".rb"},
    "shell": {".sh", ".bash"},
    "html": {".html", ".htm"},
    "css": {".css", ".scss", ".sass", ".less"},
    "json": {".json"},
    "yaml": {".yaml", ".yml"},
    "markdown": {".md", ".mdx", ".markdown"},
    "dockerfile": {"Dockerfile", ".dockerfile"},
}

# Framework detection by file/directory names
FRAMEWORK_INDICATORS = {
    "django": {"manage.py", "django.conf"},
    "flask": {"flask"},
    "fastapi": {"fastapi"},
    "react": {"package.json", "react", "jsx"},
    "vue": {"vue.config.js", "package.json"},
    "angular": {"angular.json", "package.json"},
    "express": {"express"},
    "nextjs": {"next.config.js", "package.json"},
    "rails": {"Gemfile", "config/rails", "app/"},
    "laravel": {"artisan", "composer.json", "app/"},
    "wordpress": {"wp-config.php", "wp-content/"},
    "spring": {"pom.xml", "build.gradle"},
    "dotnet": {".csproj", ".sln"},
    "maven": {"pom.xml"},
    "gradle": {"build.gradle"},
    "cargo": {"Cargo.toml"},
    "npm": {"package.json"},
    "yarn": {"yarn.lock"},
    "pip": {"requirements.txt", "pyproject.toml", "setup.py"},
}


@dataclass
class FileMetadata:
    """Metadata for a single file in the inventory."""
    path: str  # Relative path from repo root
    size: int  # File size in bytes
    language: Optional[str] = None
    is_binary: bool = False


@dataclass
class RepositoryInventory:
    """Aggregated inventory of a repository."""
    root_path: str
    files: List[FileMetadata] = field(default_factory=list)
    total_files: int = 0
    total_size: int = 0
    skipped_count: int = 0  # Files excluded by rules
    detected_languages: Dict[str, int] = field(default_factory=dict)  # Language -> count
    detected_frameworks: Set[str] = field(default_factory=set)

    def to_dict(self) -> dict:
        """Serialize to dict."""
        return {
            "root_path": self.root_path,
            "total_files": self.total_files,
            "total_size": self.total_size,
            "skipped_count": self.skipped_count,
            "detected_languages": self.detected_languages,
            "detected_frameworks": sorted(list(self.detected_frameworks)),
            "files": [
                {
                    "path": f.path,
                    "size": f.size,
                    "language": f.language,
                    "is_binary": f.is_binary,
                }
                for f in self.files
            ],
        }


class FilesystemWalker:
    """
    Traverses a repository directory with safety guards.

    Features:
    - Exclude patterns (like .gitignore)
    - Size caps (skip files over threshold)
    - Symlink guards (don't follow symlinks)
    - Language/framework detection
    - Binary file detection
    """

    def __init__(
        self,
        root_path: str,
        excludes: Optional[List[str]] = None,
        max_file_size: int = 10 * 1024 * 1024,  # 10 MB default
        max_total_files: int = 100_000,
    ):
        self.root_path = Path(root_path).resolve()
        if not self.root_path.exists():
            raise FileNotFoundError(f"Repository path does not exist: {root_path}")

        # Build exclude pattern matcher
        self.excludes = excludes or DEFAULT_EXCLUDES
        self.spec = pathspec.PathSpec.from_lines("gitwildmatch", self.excludes)

        self.max_file_size = max_file_size
        self.max_total_files = max_total_files

    def walk(self) -> RepositoryInventory:
        """
        Walk the repository and return inventory.

        Returns:
            RepositoryInventory with file metadata and statistics
        """
        inventory = RepositoryInventory(root_path=str(self.root_path))
        file_count = 0

        try:
            for dirpath, dirnames, filenames in os.walk(self.root_path, followlinks=False):
                # Stop early if we hit file limit
                if file_count >= self.max_total_files:
                    break

                # Filter directories by exclude patterns
                dirnames[:] = [
                    d for d in dirnames
                    if not self._is_excluded(Path(dirpath) / d)
                ]

                # Process files
                for filename in filenames:
                    if file_count >= self.max_total_files:
                        break

                    file_path = Path(dirpath) / filename
                    rel_path = file_path.relative_to(self.root_path)

                    # Skip excluded files
                    if self._is_excluded(rel_path):
                        inventory.skipped_count += 1
                        continue

                    # Skip large files
                    try:
                        size = file_path.stat().st_size
                        if size > self.max_file_size:
                            inventory.skipped_count += 1
                            continue
                    except (OSError, IOError):
                        inventory.skipped_count += 1
                        continue

                    # Detect language and binary
                    language = self._detect_language(file_path)
                    is_binary = self._is_binary(file_path)

                    # Add to inventory
                    metadata = FileMetadata(
                        path=str(rel_path).replace("\\", "/"),  # Normalize to forward slashes
                        size=size,
                        language=language,
                        is_binary=is_binary,
                    )
                    inventory.files.append(metadata)

                    # Update statistics
                    file_count += 1
                    inventory.total_files += 1
                    inventory.total_size += size

                    if language:
                        inventory.detected_languages[language] = (
                            inventory.detected_languages.get(language, 0) + 1
                        )

        except Exception as e:
            # Log but don't fail on walk errors
            print(f"Warning: Error walking repository: {e}", file=sys.stderr)

        # Detect frameworks
        self._detect_frameworks(inventory)

        return inventory

    def _is_excluded(self, rel_path: Path) -> bool:
        """Check if a path matches any exclude pattern."""
        # Normalize path separators
        path_str = str(rel_path).replace("\\", "/")
        return self.spec.match_file(path_str)

    def _detect_language(self, file_path: Path) -> Optional[str]:
        """Detect programming language from file extension."""
        suffix = file_path.suffix.lower()
        name = file_path.name.lower()

        # Check suffix first
        for language, extensions in LANGUAGE_EXTENSIONS.items():
            if suffix in extensions:
                return language

        # Check special filenames (Dockerfile, Makefile, etc)
        if name == "dockerfile" or name.endswith(".dockerfile"):
            return "dockerfile"
        if name == "makefile":
            return "makefile"

        return None

    def _is_binary(self, file_path: Path) -> bool:
        """Heuristic: detect if file is binary."""
        # Check extension first for common binary types
        suffix = file_path.suffix.lower()
        binary_extensions = {
            ".o", ".so", ".a", ".dylib", ".dll", ".exe", ".elf",
            ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
            ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
            ".mp3", ".mp4", ".wav", ".avi", ".mkv",
            ".pdf", ".doc", ".docx", ".xls", ".xlsx",
            ".pyc", ".pyo", ".class", ".jar", ".war", ".ear",
        }

        if suffix in binary_extensions:
            return True

        # Try reading first few bytes
        try:
            with open(file_path, "rb") as f:
                chunk = f.read(512)
                # Look for null bytes (common in binary files)
                return b"\x00" in chunk
        except (OSError, IOError):
            # Can't read? Assume binary to be safe
            return True

    def _detect_frameworks(self, inventory: RepositoryInventory) -> None:
        """
        Detect frameworks by looking for indicator files/patterns.
        """
        filenames = {f.path.split("/")[-1] for f in inventory.files}
        all_paths = {f.path for f in inventory.files}

        for framework, indicators in FRAMEWORK_INDICATORS.items():
            found = False
            for indicator in indicators:
                # Check if any file path contains this indicator
                if any(indicator.lower() in path.lower() for path in all_paths):
                    found = True
                    break

            if found:
                inventory.detected_frameworks.add(framework)
