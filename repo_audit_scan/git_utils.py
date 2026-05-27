"""
Git metadata extraction with graceful degradation.

Provides:
- GitMetadata: Structured git information
- extract_git_metadata: Safe extraction with fallback to "unknown"
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import subprocess
import sys


@dataclass
class GitMetadata:
    """Git metadata for a repository."""
    remote: Optional[str] = None  # Origin remote URL
    branch: Optional[str] = None  # Current branch name
    commit: Optional[str] = None  # Current commit SHA

    def to_dict(self) -> dict:
        """Serialize to dict."""
        return {
            "remote": self.remote or "unknown",
            "branch": self.branch or "unknown",
            "commit": self.commit or "unknown",
        }


def extract_git_metadata(repo_path: str) -> GitMetadata:
    """
    Extract Git metadata from a repository.

    Gracefully degrades to "unknown" if git is not available,
    the path is not a git repo, or commands fail.

    Args:
        repo_path: Path to the repository

    Returns:
        GitMetadata with fallback values on error
    """
    repo_path = Path(repo_path).resolve()

    # Check if .git exists
    git_dir = repo_path / ".git"
    if not git_dir.exists():
        return GitMetadata(remote=None, branch=None, commit=None)

    metadata = GitMetadata()

    # Try to get remote URL
    try:
        remote = subprocess.run(
            ["git", "config", "--get", "remote.origin.url"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if remote.returncode == 0:
            metadata.remote = remote.stdout.strip()
    except Exception as e:
        # Silently fail, use None as fallback
        pass

    # Try to get branch name
    try:
        branch = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if branch.returncode == 0:
            metadata.branch = branch.stdout.strip()
    except Exception as e:
        # Silently fail, use None as fallback
        pass

    # Try to get commit SHA
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if commit.returncode == 0:
            metadata.commit = commit.stdout.strip()
    except Exception as e:
        # Silently fail, use None as fallback
        pass

    return metadata
