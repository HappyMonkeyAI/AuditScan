"""
Tests for filesystem walker and repository inventory.
"""

import pytest
from pathlib import Path
from repo_audit_scan.inventory import FilesystemWalker, RepositoryInventory, FileMetadata
from repo_audit_scan.git_utils import extract_git_metadata


@pytest.fixture
def mixed_fixture_path():
    """Path to mixed-language test fixture."""
    return Path(__file__).parent / "fixtures" / "mixed_language_repo"


class TestFilesystemWalker:
    """Tests for FilesystemWalker class."""

    def test_walker_initialization(self, mixed_fixture_path):
        """Walker should initialize with valid path."""
        walker = FilesystemWalker(str(mixed_fixture_path))
        assert walker.root_path == mixed_fixture_path.resolve()

    def test_walker_invalid_path(self):
        """Walker should reject invalid paths."""
        with pytest.raises(FileNotFoundError):
            FilesystemWalker("/nonexistent/path/to/repo")

    def test_walk_mixed_language_repo(self, mixed_fixture_path):
        """Walker should correctly inventory mixed-language repo."""
        walker = FilesystemWalker(str(mixed_fixture_path))
        inventory = walker.walk()

        # Basic inventory properties
        assert inventory.root_path == str(mixed_fixture_path.resolve())
        assert inventory.total_files > 0
        assert inventory.total_size > 0
        assert inventory.skipped_count >= 0

        # Should have files (not all excluded)
        assert len(inventory.files) > 0

        # File paths should be normalized (forward slashes)
        for file_meta in inventory.files:
            assert "/" in file_meta.path or file_meta.path.count(file_meta.path.split("/")[-1]) == 1
            assert "\\" not in file_meta.path

    def test_language_detection(self, mixed_fixture_path):
        """Walker should detect programming languages correctly."""
        walker = FilesystemWalker(str(mixed_fixture_path))
        inventory = walker.walk()

        # Should detect multiple languages
        assert "python" in inventory.detected_languages
        assert "javascript" in inventory.detected_languages
        assert "typescript" in inventory.detected_languages
        assert "php" in inventory.detected_languages
        assert "dockerfile" in inventory.detected_languages

        # Counts should be correct
        assert inventory.detected_languages["python"] >= 1
        assert inventory.detected_languages["javascript"] >= 1
        assert inventory.detected_languages["php"] >= 1

    def test_exclude_patterns(self, mixed_fixture_path):
        """Walker should respect exclude patterns."""
        walker = FilesystemWalker(str(mixed_fixture_path))
        inventory = walker.walk()

        # Check that excluded files are not in inventory
        excluded_paths = {f.path for f in inventory.files}

        # node_modules should be excluded
        assert not any("node_modules" in path for path in excluded_paths)
        # __pycache__ should be excluded
        assert not any("__pycache__" in path for path in excluded_paths)
        # .git should be excluded
        assert not any(".git" in path for path in excluded_paths)

    def test_skip_count(self, mixed_fixture_path):
        """Walker should count skipped files."""
        walker = FilesystemWalker(str(mixed_fixture_path))
        inventory = walker.walk()

        # Should have skipped some files (the excluded ones)
        # At minimum: node_modules/express/index.js, __pycache__/app.pyc, .git/HEAD
        assert inventory.skipped_count >= 3

    def test_inventory_to_dict(self, mixed_fixture_path):
        """Inventory should serialize to dict."""
        walker = FilesystemWalker(str(mixed_fixture_path))
        inventory = walker.walk()

        result = inventory.to_dict()

        # Check structure
        assert "root_path" in result
        assert "total_files" in result
        assert "total_size" in result
        assert "skipped_count" in result
        assert "detected_languages" in result
        assert "detected_frameworks" in result
        assert "files" in result

        # Check types
        assert isinstance(result["root_path"], str)
        assert isinstance(result["total_files"], int)
        assert isinstance(result["total_size"], int)
        assert isinstance(result["detected_languages"], dict)
        assert isinstance(result["detected_frameworks"], list)
        assert isinstance(result["files"], list)

        # Files should have correct structure
        for file_data in result["files"]:
            assert "path" in file_data
            assert "size" in file_data
            assert "language" in file_data
            assert "is_binary" in file_data

    def test_binary_file_detection(self, mixed_fixture_path):
        """Walker should detect binary files."""
        walker = FilesystemWalker(str(mixed_fixture_path))
        inventory = walker.walk()

        # All files in this fixture are text, so is_binary should all be False
        binary_count = sum(1 for f in inventory.files if f.is_binary)
        assert binary_count == 0  # Text-only fixture

    def test_file_size_tracking(self, mixed_fixture_path):
        """Walker should correctly track file sizes."""
        walker = FilesystemWalker(str(mixed_fixture_path))
        inventory = walker.walk()

        # total_size should be sum of all file sizes
        calculated_total = sum(f.size for f in inventory.files)
        assert inventory.total_size == calculated_total

        # Each file should have size > 0
        for file_meta in inventory.files:
            assert file_meta.size > 0

    def test_framework_detection(self, mixed_fixture_path):
        """Walker should detect frameworks."""
        walker = FilesystemWalker(str(mixed_fixture_path))
        inventory = walker.walk()

        # Should detect express from package.json
        assert "express" in inventory.detected_frameworks or "npm" in inventory.detected_frameworks

    def test_max_file_size_cap(self, tmp_path):
        """Walker should skip files over size limit."""
        # Create a test file larger than the limit
        large_file = tmp_path / "large.txt"
        large_file.write_text("x" * (11 * 1024 * 1024))  # 11 MB

        small_file = tmp_path / "small.txt"
        small_file.write_text("hello")

        # Walk with 10 MB limit
        walker = FilesystemWalker(str(tmp_path), max_file_size=10 * 1024 * 1024)
        inventory = walker.walk()

        # Should include small file, exclude large file
        paths = {f.path for f in inventory.files}
        assert "small.txt" in paths
        assert "large.txt" not in paths
        assert inventory.skipped_count >= 1


class TestGitMetadata:
    """Tests for Git metadata extraction."""

    def test_extract_metadata_non_git_repo(self, tmp_path):
        """Should gracefully handle non-git directories."""
        metadata = extract_git_metadata(str(tmp_path))

        # Should return GitMetadata with None values
        assert metadata.remote is None
        assert metadata.branch is None
        assert metadata.commit is None

    def test_git_metadata_to_dict(self, tmp_path):
        """GitMetadata should serialize to dict with fallback."""
        metadata = extract_git_metadata(str(tmp_path))
        result = metadata.to_dict()

        # Should have fallback values
        assert result["remote"] == "unknown"
        assert result["branch"] == "unknown"
        assert result["commit"] == "unknown"

    def test_git_metadata_from_fixture(self, mixed_fixture_path):
        """Should extract git metadata from fixture."""
        metadata = extract_git_metadata(str(mixed_fixture_path))

        # Fixture has minimal .git, so values will be None
        # but extraction should not error
        result = metadata.to_dict()
        assert "remote" in result
        assert "branch" in result
        assert "commit" in result


class TestIntegration:
    """Integration tests combining walker and git metadata."""

    def test_full_scan_workflow(self, mixed_fixture_path):
        """Should complete full scan workflow without error."""
        # Walk filesystem
        walker = FilesystemWalker(str(mixed_fixture_path))
        inventory = walker.walk()

        # Extract git metadata
        git_metadata = extract_git_metadata(str(mixed_fixture_path))

        # Both should succeed
        assert inventory.total_files > 0
        assert git_metadata is not None

        # Should have diverse language detection
        assert len(inventory.detected_languages) >= 3  # Python, JS, PHP

    def test_inventory_json_serializable(self, mixed_fixture_path):
        """Inventory should be JSON-serializable."""
        import json

        walker = FilesystemWalker(str(mixed_fixture_path))
        inventory = walker.walk()

        # Should convert to dict and JSON without error
        data = inventory.to_dict()
        json_str = json.dumps(data)

        # Should be valid JSON
        parsed = json.loads(json_str)
        assert parsed["total_files"] == inventory.total_files
