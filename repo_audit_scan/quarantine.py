"""GitHub-only disposable repository intake; source is never executed."""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse

_GITHUB_RE = re.compile(r"^https://github\.com/[^/]+/[^/]+(?:\.git)?/?$")


def validate_github_source(source: str) -> None:
    if not _GITHUB_RE.match(source) or urlparse(source).username or urlparse(source).password:
        raise ValueError("only credential-free GitHub HTTPS repository URLs are permitted")


def quarantine_repository(source: str, ref: str | None = None, root: str | None = None) -> tuple[Path, dict[str, str]]:
    """Clone without checkout/submodules/hooks/LFS and return disposable staging metadata."""
    validate_github_source(source)
    staging = Path(tempfile.mkdtemp(prefix="auditscan-quarantine-", dir=root))
    try:
        repo = staging / "source"
        subprocess.run([
            "git", "-c", "core.hooksPath=NUL", "clone", "--no-checkout", "--no-recurse-submodules", source, str(repo)
        ], check=True, capture_output=True, text=True, timeout=120)
        wanted = ref or "HEAD"
        resolved = subprocess.run(["git", "-C", str(repo), "rev-parse", f"{wanted}^{{commit}}"], check=True, capture_output=True, text=True, timeout=30).stdout.strip()
        subprocess.run(["git", "-C", str(repo), "-c", "core.hooksPath=NUL", "checkout", "--no-recurse-submodules", resolved], check=True, capture_output=True, text=True, timeout=60)
        digest = hashlib.sha256(resolved.encode()).hexdigest()
        source.chmod(0o555)
        return repo, {"origin": source, "resolved_ref": resolved, "content_digest": digest, "staging_root": str(staging)}
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
