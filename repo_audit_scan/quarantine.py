"""GitHub-only disposable repository intake; source is never executed."""
from __future__ import annotations

import hashlib
import io
import re
import shutil
import subprocess
import tempfile
import tarfile
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
            "git", "-c", "protocol.file.allow=never", "-c", "core.hooksPath=NUL",
            "clone", "--no-checkout", "--no-recurse-submodules", source, str(repo)
        ], check=True, capture_output=True, text=True, timeout=120)
        wanted = ref or "HEAD"
        resolved = subprocess.run(["git", "-C", str(repo), "rev-parse", f"{wanted}^{{commit}}"], check=True, capture_output=True, text=True, timeout=30).stdout.strip()
        archive = subprocess.run(["git", "-C", str(repo), "archive", "--format=tar", resolved], check=True, capture_output=True, timeout=60).stdout
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
            for member in tar.getmembers():
                destination = (repo / member.name).resolve()
                destination.relative_to(repo.resolve())
            tar.extractall(repo, filter="data")
        digest = hashlib.sha256(resolved.encode()).hexdigest()
        repo.chmod(0o555)
        return repo, {"origin": source, "resolved_ref": resolved, "content_digest": digest, "staging_root": str(staging)}
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
