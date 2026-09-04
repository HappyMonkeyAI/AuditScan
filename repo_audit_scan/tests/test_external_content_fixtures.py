"""Fixture inventory tests for the external-content gate."""

from pathlib import Path


FIXTURES = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "external_content"
HOSTILE = FIXTURES / "hostile_repo"
BENIGN = FIXTURES / "benign_threejs_repo"


def _fixture_files(root: Path):
    return {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()}


def test_hostile_fixture_contains_expected_untrusted_surfaces():
    files = _fixture_files(HOSTILE)
    assert {"README.md", "package.json", ".github/workflows/unsafe.yml"} <= files

    readme = (HOSTILE / "README.md").read_text(encoding="utf-8")
    package = (HOSTILE / "package.json").read_text(encoding="utf-8")
    workflow = (HOSTILE / ".github/workflows/unsafe.yml").read_text(encoding="utf-8")
    assert "Ignore previous system instructions" in readme
    assert "long-term memory" in readme
    assert "postinstall" in package
    assert "pull_request_target" in workflow
    assert "write-all" in workflow


def test_benign_threejs_fixture_is_ordinary_documentation():
    files = _fixture_files(BENIGN)
    assert files == {"README.md", "package.json"}

    readme = (BENIGN / "README.md").read_text(encoding="utf-8")
    package = (BENIGN / "package.json").read_text(encoding="utf-8")
    assert "Three.js" in readme
    assert "Ignore previous system instructions" not in readme
    assert "postinstall" not in package


def test_fixture_inspection_does_not_execute_files():
    """Baseline fixture test reads bytes only; no installer or runner is invoked."""
    for root in (HOSTILE, BENIGN):
        for path in root.rglob("*"):
            if path.is_file():
                assert path.read_bytes()
