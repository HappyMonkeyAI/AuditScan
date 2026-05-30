"""
Tests for language adapters, registry, and loader.

Covers Python, JavaScript, Java, C#, and PHP/WordPress adapters.
"""

from pathlib import Path

import pytest
from repo_audit_scan.adapters_final import (
    LanguageAdapter,
    PythonAdapter,
    JavaScriptAdapter,
    JavaAdapter,
    CSharpAdapter,
    PhpAdapter,
    ScanContext,
)
from repo_audit_scan.adapter_registry import (
    AdapterRegistry,
    get_registry,
    resolve_adapter,
    resolve_language,
)
from repo_audit_scan.rules import Rule
from repo_audit_scan.models import Severity


@pytest.fixture
def registry():
    """Fresh adapter registry."""
    return AdapterRegistry()


@pytest.fixture
def python_rule():
    """Sample Python rule."""
    return Rule(
        rule_id="py-secrets-001",
        category="secrets",
        title="Hardcoded API Key",
        description="Detect hardcoded API keys in Python",
        severity=Severity.CRITICAL,
        checks=[{
            "type": "regex",
            "pattern": r"api[_-]?key\s*=\s*['\"]([a-zA-Z0-9\-_]+)['\"]",
        }],
        remediation_guidance="Move to environment variables",
    )


@pytest.fixture
def javascript_rule():
    """Sample JavaScript rule."""
    return Rule(
        rule_id="js-secrets-001",
        category="secrets",
        title="Hardcoded Secret in JS",
        description="Detect hardcoded secrets in JavaScript",
        severity=Severity.CRITICAL,
        checks=[{
            "type": "regex",
            "pattern": r"const\s+secret\s*=\s*['\"]([a-zA-Z0-9\-_]+)['\"]",
        }],
        remediation_guidance="Use environment variables",
    )


class TestLanguageAdapter:
    """Tests for LanguageAdapter base class."""

    def test_python_adapter_properties(self):
        """Python adapter should have correct properties."""
        adapter = PythonAdapter()
        assert adapter.language == "python"
        assert isinstance(adapter.supported_frameworks, list)
        assert len(adapter.supported_frameworks) > 0
        assert "django" in adapter.supported_frameworks

    def test_javascript_adapter_properties(self):
        """JavaScript adapter should have correct properties."""
        adapter = JavaScriptAdapter()
        assert adapter.language == "javascript"
        assert len(adapter.supported_frameworks) > 0
        assert "react" in adapter.supported_frameworks

    def test_python_adapter_detects_py_files(self):
        """Python adapter should detect .py files."""
        adapter = PythonAdapter()
        assert adapter.detect_language("app.py") is True
        assert adapter.detect_language("config.py") is True
        assert adapter.detect_language("main.js") is False

    def test_javascript_adapter_detects_js_files(self):
        """JavaScript adapter should detect .js/.ts files."""
        adapter = JavaScriptAdapter()
        assert adapter.detect_language("app.js") is True
        assert adapter.detect_language("component.tsx") is True
        assert adapter.detect_language("styles.css") is False

    def test_java_adapter_detects_java_files(self):
        """Java adapter should detect .java files."""
        adapter = JavaAdapter()
        assert adapter.detect_language("Main.java") is True
        assert adapter.detect_language("Service.java") is True
        assert adapter.detect_language("app.py") is False

    def test_csharp_adapter_detects_cs_files(self):
        """C# adapter should detect .cs files."""
        adapter = CSharpAdapter()
        assert adapter.detect_language("Program.cs") is True
        assert adapter.detect_language("Controller.cs") is True
        assert adapter.detect_language("app.java") is False


class TestAdapterSupportsRule:
    """Tests for rule support detection."""

    def test_python_adapter_supports_python_rules(self):
        """Python adapter should support Python rules."""
        adapter = PythonAdapter()
        rule = Rule(
            rule_id="py-001",
            category="secrets",
            title="Python Secret",
            description="Hardcoded secret in Python code",
            severity=Severity.HIGH,
        )
        assert adapter.supports_rule(rule) is True

    def test_python_adapter_excludes_java_rules(self):
        """Python adapter should not support Java-specific rules."""
        adapter = PythonAdapter()
        rule = Rule(
            rule_id="java-001",
            category="secrets",
            title="Java Secret",
            description="Hardcoded secret in Java with Spring Framework",
            severity=Severity.HIGH,
        )
        assert adapter.supports_rule(rule) is False

    def test_javascript_adapter_supports_js_rules(self):
        """JavaScript adapter should support JS rules."""
        adapter = JavaScriptAdapter()
        rule = Rule(
            rule_id="js-001",
            category="secrets",
            title="JS Secret",
            description="Hardcoded secret in JavaScript",
            severity=Severity.HIGH,
        )
        assert adapter.supports_rule(rule) is True

    def test_javascript_adapter_excludes_python_rules(self):
        """JavaScript adapter should not support Python-specific rules."""
        adapter = JavaScriptAdapter()
        rule = Rule(
            rule_id="py-001",
            category="secrets",
            title="Python Secret",
            description="Django hardcoded secret in Python",
            severity=Severity.HIGH,
        )
        assert adapter.supports_rule(rule) is False


class TestAdapterScan:
    """Tests for adapter scanning."""

    def test_python_adapter_scan_finds_hardcoded_secret(self, python_rule):
        """Python adapter should find hardcoded API keys."""
        adapter = PythonAdapter()
        context = ScanContext(
            file_path="config.py",
            file_content='api_key = "sk-1234567890"\nother_var = "value"',
            language="python",
        )

        results = adapter.scan(context, python_rule)

        assert len(results) > 0
        assert results[0].rule_id == "py-secrets-001"
        assert len(results[0].evidence) > 0
        assert results[0].evidence[0].file_path == "config.py"

    def test_python_adapter_scan_handles_no_matches(self, python_rule):
        """Python adapter should return empty list when no matches."""
        adapter = PythonAdapter()
        context = ScanContext(
            file_path="clean.py",
            file_content="x = 1\ny = 2\nz = 3",
            language="python",
        )

        results = adapter.scan(context, python_rule)
        assert len(results) == 0

    def test_javascript_adapter_scan_finds_secret(self, javascript_rule):
        """JavaScript adapter should find hardcoded secrets."""
        adapter = JavaScriptAdapter()
        context = ScanContext(
            file_path="app.js",
            file_content='const secret = "mysecretvalue"\nconst public = "ok"',
            language="javascript",
        )

        results = adapter.scan(context, javascript_rule)

        assert len(results) > 0
        assert results[0].rule_id == "js-secrets-001"

    def test_scan_with_rule_without_checks(self):
        """Adapter should handle rules without checks."""
        adapter = PythonAdapter()
        rule = Rule(
            rule_id="test-001",
            category="test",
            title="Test",
            description="Test rule",
            severity=Severity.MEDIUM,
            checks=[],  # No checks
        )
        context = ScanContext(
            file_path="test.py",
            file_content="code here",
            language="python",
        )

        results = adapter.scan(context, rule)
        assert len(results) == 0

    def test_scan_with_invalid_regex(self):
        """Adapter should handle invalid regex patterns gracefully."""
        adapter = PythonAdapter()
        rule = Rule(
            rule_id="invalid-001",
            category="test",
            title="Bad Regex",
            description="Rule with invalid regex",
            severity=Severity.MEDIUM,
            checks=[{
                "type": "regex",
                "pattern": r"[invalid(regex",  # Invalid regex
            }],
        )
        context = ScanContext(
            file_path="test.py",
            file_content="normal code",
            language="python",
        )

        results = adapter.scan(context, rule)
        assert len(results) == 0  # Should handle gracefully


PHP_FIXTURE_DIR = (
    Path(__file__).resolve().parents[2]
    / "tests"
    / "fixtures"
    / "php_wordpress_ajax_no_capability"
)


@pytest.fixture
def wp_ajax_rule():
    """WordPress AJAX missing-guard rule (SPEC AC-001)."""
    return Rule(
        rule_id="wp-ajax-001",
        category="access-control",
        title="WordPress AJAX handler missing nonce/capability check",
        description="WordPress PHP AJAX handler without nonce or capability check",
        severity=Severity.HIGH,
        checks=[{"type": "wp_ajax_missing_guard"}],
        remediation_guidance="Add check_ajax_referer() and current_user_can()",
    )


@pytest.fixture
def php_sqli_rule():
    """PHP SQL injection rule (SPEC AC-002)."""
    return Rule(
        rule_id="php-002",
        category="injection",
        title="PHP SQL injection",
        description="Detects SQL injection in PHP due to string concatenation",
        severity=Severity.CRITICAL,
        checks=[{
            "type": "regex",
            "pattern": r"\$query\s*=\s*['\"]SELECT.*['\"]\s*\.",
        }],
        remediation_guidance="Use prepared statements / $wpdb->prepare()",
    )


class TestPhpAdapter:
    """Tests for the PHP/WordPress adapter (T-007)."""

    def test_php_adapter_properties(self):
        adapter = PhpAdapter()
        assert adapter.language == "php"
        assert "wordpress" in adapter.supported_frameworks
        assert "laravel" in adapter.supported_frameworks

    def test_php_adapter_detects_php_files(self):
        adapter = PhpAdapter()
        assert adapter.detect_language("plugin.php") is True
        assert adapter.detect_language("template.phtml") is True
        assert adapter.detect_language("legacy.php5") is True
        assert adapter.detect_language("app.py") is False
        assert adapter.detect_language("index.js") is False

    def test_php_adapter_supports_php_rules(self):
        adapter = PhpAdapter()
        rule = Rule(
            rule_id="php-002",
            category="injection",
            title="PHP SQL injection",
            description="Detects SQL injection in PHP code",
            severity=Severity.CRITICAL,
        )
        assert adapter.supports_rule(rule) is True

    def test_php_adapter_excludes_other_language_rules(self):
        adapter = PhpAdapter()
        rule = Rule(
            rule_id="py-001",
            category="secrets",
            title="Python secret",
            description="Hardcoded secret in Python with Django",
            severity=Severity.HIGH,
        )
        assert adapter.supports_rule(rule) is False

    def test_other_adapters_exclude_php_rules(self):
        """A PHP-marked rule should not be claimed by non-PHP adapters."""
        php_rule = Rule(
            rule_id="php-005",
            category="injection",
            title="PHP eval",
            description="Detects PHP eval() usage",
            severity=Severity.CRITICAL,
        )
        assert PythonAdapter().supports_rule(php_rule) is False
        assert JavaScriptAdapter().supports_rule(php_rule) is False
        assert JavaAdapter().supports_rule(php_rule) is False
        assert CSharpAdapter().supports_rule(php_rule) is False

    def test_php_sqli_scan_finds_injection(self, php_sqli_rule):
        """AC-002: PHP SQL string interpolation yields an injection finding."""
        adapter = PhpAdapter()
        context = ScanContext(
            file_path="db.php",
            file_content='<?php $query = "SELECT * FROM users WHERE id = " . $_GET["id"];',
            language="php",
        )
        results = adapter.scan(context, php_sqli_rule)
        assert len(results) == 1
        assert results[0].rule_id == "php-002"
        assert results[0].severity == Severity.CRITICAL
        assert results[0].evidence[0].line_number == 1

    def test_wp_ajax_missing_guard_flags_unguarded(self, wp_ajax_rule):
        """AC-001: unguarded AJAX handler produces an access-control finding."""
        adapter = PhpAdapter()
        content = (PHP_FIXTURE_DIR / "vulnerable-plugin.php").read_text()
        context = ScanContext(
            file_path="vulnerable-plugin.php",
            file_content=content,
            language="php",
        )
        results = adapter.scan(context, wp_ajax_rule)
        assert len(results) == 1
        assert results[0].rule_id == "wp-ajax-001"
        assert results[0].category == "access-control"
        assert len(results[0].evidence) >= 1
        assert results[0].evidence[0].line_number > 0

    def test_wp_ajax_guard_present_no_finding(self, wp_ajax_rule):
        """A handler guarded by nonce + capability check must not be flagged."""
        adapter = PhpAdapter()
        content = (PHP_FIXTURE_DIR / "safe-plugin.php").read_text()
        context = ScanContext(
            file_path="safe-plugin.php",
            file_content=content,
            language="php",
        )
        results = adapter.scan(context, wp_ajax_rule)
        assert results == []

    def test_wp_ajax_inline_capability_only_no_finding(self, wp_ajax_rule):
        """A capability check alone satisfies the guard (lacks nonce OR capability)."""
        adapter = PhpAdapter()
        content = (
            "<?php\n"
            "add_action('wp_ajax_do_thing', 'do_thing');\n"
            "function do_thing() {\n"
            "    if (!current_user_can('manage_options')) { wp_die(); }\n"
            "    echo 'ok';\n"
            "}\n"
        )
        context = ScanContext(
            file_path="cap.php", file_content=content, language="php"
        )
        assert adapter.scan(context, wp_ajax_rule) == []

    def test_wp_ajax_guard_in_comment_still_flagged(self, wp_ajax_rule):
        """A guard token that appears only in a comment must not mask the finding."""
        adapter = PhpAdapter()
        content = (
            "<?php\n"
            "add_action('wp_ajax_do_thing', 'do_thing');\n"
            "function do_thing() {\n"
            "    // TODO: add current_user_can('manage_options') check here\n"
            "    echo $_POST['x'];\n"
            "}\n"
        )
        context = ScanContext(
            file_path="commented.php", file_content=content, language="php"
        )
        results = adapter.scan(context, wp_ajax_rule)
        assert len(results) == 1

    def test_wp_ajax_substring_identifier_not_a_guard(self, wp_ajax_rule):
        """A non-guard identifier containing a guard token must not count as a guard."""
        adapter = PhpAdapter()
        content = (
            "<?php\n"
            "add_action('wp_ajax_do_thing', 'do_thing');\n"
            "function do_thing() {\n"
            "    current_user_can_view_things();\n"  # not a real guard
            "    echo $_POST['x'];\n"
            "}\n"
        )
        context = ScanContext(
            file_path="substring.php", file_content=content, language="php"
        )
        results = adapter.scan(context, wp_ajax_rule)
        assert len(results) == 1

    def test_registry_resolves_php(self, registry):
        assert registry.resolve_language("plugin.php") == "php"
        adapter = registry.resolve_adapter("wp-content/plugins/x/plugin.php")
        assert adapter is not None
        assert adapter.language == "php"

    def test_supported_extensions_includes_php(self, registry):
        extensions = registry.supported_extensions()
        assert extensions.get(".php") == "php"
        assert extensions.get(".phtml") == "php"


class TestExtractEvidence:
    """Tests for evidence extraction."""

    def test_extract_evidence_finds_matches(self):
        """Should extract evidence from matches."""
        adapter = PythonAdapter()
        content = 'api_key = "secret123"\npassword = "pass456"'
        pattern = r"[a-z_]+ = \"([^\"]+)\""

        evidence = adapter.extract_evidence("test.py", content, pattern)

        assert len(evidence) >= 2
        assert evidence[0].file_path == "test.py"
        assert evidence[0].line_number > 0
        assert evidence[0].column_number >= 0

    def test_extract_evidence_line_numbers(self):
        """Evidence should have correct line numbers."""
        adapter = PythonAdapter()
        content = "line1\nline2\napi_key = 'secret'\nline4"
        pattern = r"api_key"

        evidence = adapter.extract_evidence("test.py", content, pattern)

        assert len(evidence) == 1
        assert evidence[0].line_number == 3

    def test_extract_evidence_multiline_context(self):
        """Evidence should include context lines."""
        adapter = PythonAdapter()
        content = "line1\nline2\napi_key = 'secret'\nline4\nline5"
        pattern = r"api_key"

        evidence = adapter.extract_evidence("test.py", content, pattern, context_lines=1)

        assert len(evidence) == 1
        assert "line2" in evidence[0].code_snippet
        assert "api_key" in evidence[0].code_snippet
        assert "line4" in evidence[0].code_snippet


class TestAdapterRegistry:
    """Tests for adapter registry."""

    def test_registry_initialization(self, registry):
        """Registry should initialize with built-in adapters."""
        assert registry.count_adapters() >= 4
        assert registry.get_adapter("python") is not None
        assert registry.get_adapter("javascript") is not None

    def test_get_adapter_by_language(self, registry):
        """Should retrieve adapter by language name."""
        python_adapter = registry.get_adapter("python")
        assert python_adapter is not None
        assert python_adapter.language == "python"

    def test_get_nonexistent_adapter(self, registry):
        """Should return None for unsupported language."""
        adapter = registry.get_adapter("ruby")
        assert adapter is None

    def test_resolve_language_from_file(self, registry):
        """Should resolve language from file path."""
        assert registry.resolve_language("app.py") == "python"
        assert registry.resolve_language("index.js") == "javascript"
        assert registry.resolve_language("Main.java") == "java"
        assert registry.resolve_language("Program.cs") == "csharp"

    def test_resolve_language_case_insensitive(self, registry):
        """Language resolution should be case-insensitive."""
        assert registry.resolve_language("APP.PY") == "python"
        assert registry.resolve_language("INDEX.JS") == "javascript"

    def test_resolve_language_unknown_extension(self, registry):
        """Should return None for unknown extensions."""
        assert registry.resolve_language("file.unknown") is None
        assert registry.resolve_language("config.yaml") is None

    def test_resolve_adapter_from_file(self, registry):
        """Should resolve adapter from file path."""
        adapter = registry.resolve_adapter("app.py")
        assert adapter is not None
        assert adapter.language == "python"

    def test_supported_languages(self, registry):
        """Should list supported languages."""
        languages = registry.supported_languages()
        assert isinstance(languages, list)
        assert len(languages) >= 4
        assert "python" in languages
        assert "javascript" in languages

    def test_supported_extensions(self, registry):
        """Should map extensions to languages."""
        extensions = registry.supported_extensions()
        assert isinstance(extensions, dict)
        assert extensions.get(".py") == "python"
        assert extensions.get(".js") == "javascript"
        assert extensions.get(".java") == "java"
        assert extensions.get(".cs") == "csharp"

    def test_register_custom_adapter(self, registry):
        """Should register custom adapter."""
        class CustomAdapter(LanguageAdapter):
            @property
            def language(self) -> str:
                return "custom"

            @property
            def supported_frameworks(self):
                return []

            def detect_language(self, file_path: str) -> bool:
                return file_path.endswith(".custom")

            def supports_rule(self, rule) -> bool:
                return True

            def scan(self, context, rule):
                return []

        custom = CustomAdapter()
        registry.register_adapter(custom)

        assert registry.get_adapter("custom") is not None
        assert registry.resolve_language("file.custom") == "custom"

    def test_get_frameworks_for_language(self, registry):
        """Should get frameworks for language."""
        frameworks = registry.get_frameworks_for_language("python")
        assert isinstance(frameworks, list)
        assert "django" in frameworks
        assert "flask" in frameworks

    def test_registry_serialization(self, registry):
        """Registry should serialize to dict."""
        data = registry.to_dict()
        assert "adapters" in data
        assert "count" in data
        assert "extensions" in data
        assert data["count"] >= 4


class TestGlobalRegistry:
    """Tests for global registry functions."""

    def test_get_global_registry(self):
        """Should get global registry instance."""
        reg = get_registry()
        assert reg is not None
        assert isinstance(reg, AdapterRegistry)

    def test_resolve_language_global(self):
        """Should resolve language using global registry."""
        language = resolve_language("test.py")
        assert language == "python"

        language = resolve_language("test.js")
        assert language == "javascript"

    def test_resolve_adapter_global(self):
        """Should resolve adapter using global registry."""
        adapter = resolve_adapter("test.py")
        assert adapter is not None
        assert adapter.language == "python"

        adapter = resolve_adapter("test.java")
        assert adapter is not None
        assert adapter.language == "java"


class TestIntegration:
    """Integration tests for adapter system."""

    def test_full_scan_workflow(self):
        """Full workflow: detect language, resolve adapter, scan."""
        # Setup
        registry = get_registry()
        python_rule = Rule(
            rule_id="test-001",
            category="secrets",
            title="Test Secret",
            description="Test rule",
            severity=Severity.HIGH,
            checks=[{
                "type": "regex",
                "pattern": r"password\s*=\s*['\"]([^'\"]+)['\"]",
            }],
        )

        # Detect language
        language = registry.resolve_language("app.py")
        assert language == "python"

        # Resolve adapter
        adapter = registry.resolve_adapter("app.py")
        assert adapter is not None

        # Scan
        context = ScanContext(
            file_path="app.py",
            file_content='password = "hardcoded123"',
            language="python",
        )
        results = adapter.scan(context, python_rule)

        assert len(results) > 0
        assert results[0].rule_id == "test-001"

    def test_scan_multiple_files(self):
        """Should scan multiple files with appropriate adapters."""
        registry = get_registry()
        rule = Rule(
            rule_id="test-001",
            category="secrets",
            title="Secret",
            description="Test",
            severity=Severity.HIGH,
            checks=[{
                "type": "regex",
                "pattern": r"secret",
            }],
        )

        files = [
            ("app.py", "my_secret = 'value'"),
            ("index.js", "const secret = 'value'"),
            ("Main.java", "String secret = \"value\";"),
        ]

        for file_path, content in files:
            adapter = registry.resolve_adapter(file_path)
            assert adapter is not None

            context = ScanContext(
                file_path=file_path,
                file_content=content,
                language=adapter.language,
            )
            results = adapter.scan(context, rule)

            # Should find at least one match (if rule applies)
            assert isinstance(results, list)

    def test_unsupported_file_type(self):
        """Should handle unsupported file types gracefully."""
        registry = get_registry()
        adapter = registry.resolve_adapter("README.md")

        assert adapter is None  # Markdown not supported
