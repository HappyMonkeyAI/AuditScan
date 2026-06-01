"""
Language-specific scanner adapters - FINAL CLEAN IMPLEMENTATION.

Provides:
- LanguageAdapter: Abstract base class for language-specific scanning
- Adapter implementations for Python, JavaScript, Java, C#
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Dict, Optional
import re

from repo_audit_scan.models import RuleResult, Evidence, Severity, Confidence
from repo_audit_scan.rules import Rule


@dataclass
class ScanContext:
    """Context for a scan operation."""
    file_path: str
    file_content: str
    language: str
    framework: Optional[str] = None
    encoding: str = "utf-8"


class LanguageAdapter(ABC):
    """Abstract base class for language-specific scanners."""

    @property
    @abstractmethod
    def language(self) -> str:
        """Language name (e.g., 'python', 'javascript', 'java')."""
        pass

    @property
    @abstractmethod
    def supported_frameworks(self) -> List[str]:
        """List of frameworks this adapter recognizes."""
        pass

    @abstractmethod
    def detect_language(self, file_path: str) -> bool:
        """Determine if this adapter handles the given file."""
        pass

    @abstractmethod
    def supports_rule(self, rule: Rule) -> bool:
        """Check if this adapter can execute the given rule."""
        pass

    @abstractmethod
    def scan(self, context: ScanContext, rule: Rule) -> List[RuleResult]:
        """Execute a rule against a file."""
        pass

    def extract_evidence(
        self,
        file_path: str,
        file_content: str,
        pattern: str,
        context_lines: int = 2,
    ) -> List[Evidence]:
        """Extract evidence using a regex pattern."""
        evidence_list = []
        lines = file_content.split('\n')

        for match in re.finditer(pattern, file_content, re.MULTILINE):
            line_num = file_content[:match.start()].count('\n') + 1
            line_start = file_content.rfind('\n', 0, match.start()) + 1
            col_num = match.start() - line_start

            start_line = max(0, line_num - context_lines - 1)
            end_line = min(len(lines), line_num + context_lines)
            snippet_lines = lines[start_line:end_line]
            code_snippet = '\n'.join(snippet_lines)

            evidence = Evidence(
                file_path=file_path,
                line_number=line_num,
                column_number=col_num,
                code_snippet=code_snippet,
                context=f"Pattern match at line {line_num}",
            )
            evidence_list.append(evidence)

        return evidence_list


def _scan_regex_checks(
    adapter: "LanguageAdapter",
    context: ScanContext,
    rule: Rule,
) -> List[RuleResult]:
    """Run a rule's regex checks against a file, returning at most one result.

    Shared helper so adapters do not duplicate the regex-scan loop. Returns the
    first check that produces evidence (matching existing adapter behavior).
    """
    if not rule.checks:
        return []

    for check_item in rule.checks:
        if not isinstance(check_item, dict):
            continue
        if check_item.get("type") != "regex":
            continue
        pattern_value = check_item.get("pattern")
        if not pattern_value:
            continue
        try:
            evidence_list = adapter.extract_evidence(
                context.file_path,
                context.file_content,
                pattern_value,
            )
        except re.error:
            continue
        if evidence_list:
            return [
                RuleResult(
                    rule_id=rule.rule_id,
                    rule_title=rule.title,
                    category=rule.category,
                    severity=rule.severity,
                    confidence=Confidence.HIGH,
                    evidence=evidence_list,
                    remediation_guidance=rule.remediation_guidance or "",
                )
            ]
    return []


class PythonAdapter(LanguageAdapter):
    """Adapter for Python code."""

    @property
    def language(self) -> str:
        return "python"

    @property
    def supported_frameworks(self) -> List[str]:
        return ["django", "flask", "fastapi", "pyramid", "tornado", "aiohttp"]

    def detect_language(self, file_path: str) -> bool:
        return file_path.lower().endswith('.py')

    def supports_rule(self, rule: Rule) -> bool:
        if rule.description:
            language_markers = ['java', 'javascript', 'typescript', 'c#', 'csharp', 'go', 'rust', 'swift', 'php', 'docker', 'ci/cd', 'ci-cd']
            desc_lower = rule.description.lower()
            for marker in language_markers:
                if marker in desc_lower and 'python' not in desc_lower:
                    return False
        if (rule.rule_id or "").lower().startswith(("docker-", "cicd-", "ci-")):
            return False
        return True

    def scan(self, context: ScanContext, rule: Rule) -> List[RuleResult]:
        """Scan Python file using rule checks."""
        results = []

        if not rule.checks:
            return results

        for check_item in rule.checks:
            if not isinstance(check_item, dict):
                continue

            check_type_value = check_item.get("type")
            if check_type_value != "regex":
                continue

            pattern_value = check_item.get("pattern")
            if not pattern_value:
                continue

            try:
                evidence_list = self.extract_evidence(
                    context.file_path,
                    context.file_content,
                    pattern_value,
                )

                if evidence_list:
                    result = RuleResult(
                        rule_id=rule.rule_id,
                        rule_title=rule.title,
                        category=rule.category,
                        severity=rule.severity,
                        confidence=Confidence.HIGH,
                        evidence=evidence_list,
                        remediation_guidance=rule.remediation_guidance or "",
                    )
                    results.append(result)
                    break
            except re.error:
                pass

        return results


class PhpAdapter(LanguageAdapter):
    """Adapter for PHP code, including WordPress and other PHP frameworks.

    Handles standard ``regex`` rule checks (shared with other adapters) and a
    WordPress-aware ``wp_ajax_missing_guard`` check that flags AJAX handlers
    registered without a nonce or capability guard (SPEC AC-001).

    Known MVP limitations of the ``wp_ajax_missing_guard`` heuristic:
    - Only string-literal callbacks are inspected (``'fn'``). Array/closure or
      ``Class::method`` callbacks are not yet analysed.
    - Guard detection is a static heuristic: it confirms a nonce/capability
      function is *called* in the handler body, not that the guard is logically
      effective. Findings are therefore emitted at MEDIUM confidence.
    """

    #: Hook registrations that expose an AJAX endpoint.
    _AJAX_REGISTRATION = re.compile(
        r"""add_action\(\s*['"]wp_ajax(?:_nopriv)?_[A-Za-z0-9_\-]+['"]\s*,\s*"""
        r"""['"](?P<callback>[A-Za-z0-9_]+)['"]""",
    )
    #: Strips PHP line and block comments so guard tokens hidden in comments
    #: do not mask a genuinely unguarded handler (false negative).
    _COMMENT = re.compile(r"//[^\n]*|#[^\n]*|/\*.*?\*/", re.DOTALL)
    #: Nonce / request-verification guards.
    _NONCE_GUARDS = ("check_ajax_referer", "wp_verify_nonce", "check_admin_referer")
    #: Capability / authentication guards.
    _CAP_GUARDS = ("current_user_can", "is_user_logged_in", "map_meta_cap")

    @property
    def language(self) -> str:
        return "php"

    @property
    def supported_frameworks(self) -> List[str]:
        return ["wordpress", "laravel", "symfony", "drupal", "codeigniter"]

    def detect_language(self, file_path: str) -> bool:
        return file_path.lower().endswith(
            (".php", ".phtml", ".php3", ".php4", ".php5")
        )

    def supports_rule(self, rule: Rule) -> bool:
        if rule.description:
            language_markers = [
                "python", "javascript", "typescript", "java",
                "c#", "csharp", "go", "rust", "swift",
                "docker", "ci/cd", "ci-cd",
            ]
            desc_lower = rule.description.lower()
            for marker in language_markers:
                if marker in desc_lower and "php" not in desc_lower:
                    return False
        if (rule.rule_id or "").lower().startswith(("docker-", "cicd-", "ci-")):
            return False
        return True

    def scan(self, context: ScanContext, rule: Rule) -> List[RuleResult]:
        """Scan a PHP file with regex checks and WordPress-specific checks."""
        if not rule.checks:
            return []

        check_types = {
            c.get("type") for c in rule.checks if isinstance(c, dict)
        }
        if "wp_ajax_missing_guard" in check_types:
            return self._scan_wp_ajax_guard(context, rule)

        return _scan_regex_checks(self, context, rule)

    def _function_body(self, content: str, callback: str) -> Optional[str]:
        """Return the source slice for ``callback``'s definition, if present.

        Scoped from the function declaration to the next top-level ``function``
        declaration (or end of file). Returns None when the callback is not
        defined in this file (e.g. a class method or external definition).
        """
        decl = re.search(r"function\s+" + re.escape(callback) + r"\s*\(", content)
        if decl is None:
            return None
        start = decl.start()
        nxt = re.search(r"\n\s*function\s+\w+\s*\(", content[decl.end():])
        end = decl.end() + nxt.start() if nxt else len(content)
        return content[start:end]

    def _has_guard(self, body: str) -> bool:
        """True when the handler body *calls* a nonce or capability guard.

        Comments are stripped first, and each guard must appear as a call
        expression (``guard(``) so that tokens hidden in comments or embedded
        in unrelated identifiers (e.g. ``current_user_can_view``) do not count.
        """
        code = self._COMMENT.sub(" ", body).lower()
        guards = self._NONCE_GUARDS + self._CAP_GUARDS
        return any(
            re.search(re.escape(guard) + r"\s*\(", code) for guard in guards
        )

    def _scan_wp_ajax_guard(
        self, context: ScanContext, rule: Rule
    ) -> List[RuleResult]:
        """Flag WordPress AJAX handlers registered without a nonce/capability guard."""
        content = context.file_content
        lines = content.split("\n")
        evidence_list: List[Evidence] = []

        for match in self._AJAX_REGISTRATION.finditer(content):
            callback = match.group("callback")
            body = self._function_body(content, callback)
            # When the callback body is not found in this file, fall back to a
            # file-level guard check to avoid false positives on split files.
            guard_scope = body if body is not None else content
            if self._has_guard(guard_scope):
                continue

            line_num = content[: match.start()].count("\n") + 1
            start_line = max(0, line_num - 3)
            end_line = min(len(lines), line_num + 2)
            evidence_list.append(
                Evidence(
                    file_path=context.file_path,
                    line_number=line_num,
                    column_number=match.start()
                    - (content.rfind("\n", 0, match.start()) + 1),
                    code_snippet="\n".join(lines[start_line:end_line]),
                    context=(
                        f"AJAX handler '{callback}' registered without a nonce "
                        f"or capability check"
                    ),
                )
            )

        if not evidence_list:
            return []

        return [
            RuleResult(
                rule_id=rule.rule_id,
                rule_title=rule.title,
                category=rule.category,
                severity=rule.severity,
                # Heuristic static check (callback body may be defined elsewhere
                # or the guard may be logically bypassed): MEDIUM, not HIGH.
                confidence=Confidence.MEDIUM,
                evidence=evidence_list,
                remediation_guidance=rule.remediation_guidance or "",
            )
        ]


class JavaScriptAdapter(LanguageAdapter):
    """Adapter for JavaScript and TypeScript code."""

    @property
    def language(self) -> str:
        return "javascript"

    @property
    def supported_frameworks(self) -> List[str]:
        return [
            "react", "vue", "angular", "express", "next.js", "nuxt",
            "nest.js", "koa", "hapi", "fastify", "svelte", "ember"
        ]

    def detect_language(self, file_path: str) -> bool:
        file_lower = file_path.lower()
        return file_lower.endswith(('.js', '.jsx', '.ts', '.tsx'))

    def supports_rule(self, rule: Rule) -> bool:
        if rule.description:
            language_markers = ['python', 'java', 'c#', 'csharp', 'go', 'rust', 'php', 'docker', 'ci/cd', 'ci-cd']
            desc_lower = rule.description.lower()
            for marker in language_markers:
                if marker in desc_lower and 'javascript' not in desc_lower and 'typescript' not in desc_lower:
                    return False
        if (rule.rule_id or "").lower().startswith(("docker-", "cicd-", "ci-")):
            return False
        return True

    def scan(self, context: ScanContext, rule: Rule) -> List[RuleResult]:
        """Scan JavaScript/TypeScript file."""
        results = []

        if not rule.checks:
            return results

        for check_item in rule.checks:
            if not isinstance(check_item, dict):
                continue

            check_type_value = check_item.get("type")
            if check_type_value != "regex":
                continue

            pattern_value = check_item.get("pattern")
            if not pattern_value:
                continue

            try:
                evidence_list = self.extract_evidence(
                    context.file_path,
                    context.file_content,
                    pattern_value,
                )

                if evidence_list:
                    result = RuleResult(
                        rule_id=rule.rule_id,
                        rule_title=rule.title,
                        category=rule.category,
                        severity=rule.severity,
                        confidence=Confidence.HIGH,
                        evidence=evidence_list,
                        remediation_guidance=rule.remediation_guidance or "",
                    )
                    results.append(result)
                    break
            except re.error:
                pass

        return results


class JavaAdapter(LanguageAdapter):
    """Adapter for Java code."""

    @property
    def language(self) -> str:
        return "java"

    @property
    def supported_frameworks(self) -> List[str]:
        return ["spring", "spring-boot", "hibernate", "maven", "gradle"]

    def detect_language(self, file_path: str) -> bool:
        return file_path.lower().endswith('.java')

    def supports_rule(self, rule: Rule) -> bool:
        if rule.description:
            language_markers = ['python', 'javascript', 'c#', 'csharp', 'go', 'rust', 'php', 'docker', 'ci/cd', 'ci-cd']
            desc_lower = rule.description.lower()
            for marker in language_markers:
                if marker in desc_lower and 'java' not in desc_lower:
                    return False
        if (rule.rule_id or "").lower().startswith(("docker-", "cicd-", "ci-")):
            return False
        return True

    def scan(self, context: ScanContext, rule: Rule) -> List[RuleResult]:
        """Scan Java file."""
        results = []

        if not rule.checks:
            return results

        for check_item in rule.checks:
            if not isinstance(check_item, dict):
                continue

            check_type_value = check_item.get("type")
            if check_type_value != "regex":
                continue

            pattern_value = check_item.get("pattern")
            if not pattern_value:
                continue

            try:
                evidence_list = self.extract_evidence(
                    context.file_path,
                    context.file_content,
                    pattern_value,
                )

                if evidence_list:
                    result = RuleResult(
                        rule_id=rule.rule_id,
                        rule_title=rule.title,
                        category=rule.category,
                        severity=rule.severity,
                        confidence=Confidence.HIGH,
                        evidence=evidence_list,
                        remediation_guidance=rule.remediation_guidance or "",
                    )
                    results.append(result)
                    break
            except re.error:
                pass

        return results


class CSharpAdapter(LanguageAdapter):
    """Adapter for C# code."""

    @property
    def language(self) -> str:
        return "csharp"

    @property
    def supported_frameworks(self) -> List[str]:
        return [".net", ".net-core", "asp.net", "entity-framework", "mvc"]

    def detect_language(self, file_path: str) -> bool:
        return file_path.lower().endswith('.cs')

    def supports_rule(self, rule: Rule) -> bool:
        if rule.description:
            language_markers = ['python', 'javascript', 'java', 'go', 'rust', 'php', 'docker', 'ci/cd', 'ci-cd']
            desc_lower = rule.description.lower()
            for marker in language_markers:
                if marker in desc_lower and 'c#' not in desc_lower and 'csharp' not in desc_lower:
                    return False
        if (rule.rule_id or "").lower().startswith(("docker-", "cicd-", "ci-")):
            return False
        return True

    def scan(self, context: ScanContext, rule: Rule) -> List[RuleResult]:
        """Scan C# file."""
        results = []

        if not rule.checks:
            return results

        for check_item in rule.checks:
            if not isinstance(check_item, dict):
                continue

            check_type_value = check_item.get("type")
            if check_type_value != "regex":
                continue

            pattern_value = check_item.get("pattern")
            if not pattern_value:
                continue

            try:
                evidence_list = self.extract_evidence(
                    context.file_path,
                    context.file_content,
                    pattern_value,
                )

                if evidence_list:
                    result = RuleResult(
                        rule_id=rule.rule_id,
                        rule_title=rule.title,
                        category=rule.category,
                        severity=rule.severity,
                        confidence=Confidence.HIGH,
                        evidence=evidence_list,
                        remediation_guidance=rule.remediation_guidance or "",
                    )
                    results.append(result)
                    break
            except re.error:
                pass

        return results


class CICDAdapter(LanguageAdapter):
    """Adapter for CI/CD pipeline definitions (GitHub Actions and friends).

    Unlike language adapters, CI/CD files are identified by path/filename, not
    a source extension. Scans pipeline YAML/Groovy for the SPEC ci_cd detector
    set: unsafe triggers (``pull_request_target``), broad token permissions,
    unpinned actions, secret exposure, and untrusted-input shell interpolation.

    Scope: this adapter only runs CI/CD-category rules (``ci-cd`` category or a
    ``cicd``/``ci-`` rule id), so universal *language* rules are left to the
    language adapters. CI-specific secret detection is provided by ``cicd-005``
    (secrets echoed to logs) and ``cicd-006`` (hardcoded secret literals) rather
    than by importing the language-tagged ``secrets`` rules, which would add
    noise on pipeline YAML.

    Known MVP limitations (regex heuristics; documented, not bugs):
    - Detection covers ``.github/workflows/*.yml``, ``.gitlab-ci.yml``,
      ``.circleci/config.yml``, ``azure-pipelines.yml``, ``.travis.yml`` and
      ``Jenkinsfile``; composite/reusable ``action.yml`` files and
      ``docker://`` action references are not yet analysed.
    - Broad-permission detection (``cicd-002``) flags ``write-all`` only, not
      granular over-scoping (``contents: write``, ``id-token: write``) which is
      often legitimate.
    - Script-injection detection (``cicd-004``) covers ``github.event.*`` and is
      context-insensitive — it will also flag the recommended ``env:`` var
      mitigation, so treat its findings as triage candidates.
    """

    #: Exact filenames that denote a CI/CD pipeline regardless of directory.
    _CI_FILENAMES = {
        ".gitlab-ci.yml", ".gitlab-ci.yaml", ".travis.yml", ".travis.yaml",
        "azure-pipelines.yml", "azure-pipelines.yaml",
        "bitbucket-pipelines.yml", "bitbucket-pipelines.yaml",
    }

    @property
    def language(self) -> str:
        return "ci-cd"

    @property
    def supported_frameworks(self) -> List[str]:
        return [
            "github-actions", "gitlab-ci", "circleci",
            "jenkins", "azure-pipelines", "travis",
        ]

    def detect_language(self, file_path: str) -> bool:
        path = file_path.replace("\\", "/")
        lower = path.lower()
        name = path.rsplit("/", 1)[-1]
        # Jenkins pipeline files: "Jenkinsfile" or "Jenkinsfile.<env>".
        if name == "Jenkinsfile" or name.startswith("Jenkinsfile."):
            return True
        if name in self._CI_FILENAMES:
            return True
        is_yaml = lower.endswith((".yml", ".yaml"))
        if is_yaml and "/.github/workflows/" in f"/{lower}":
            return True
        if is_yaml and "/.circleci/" in f"/{lower}" and name.startswith("config."):
            return True
        return False

    def supports_rule(self, rule: Rule) -> bool:
        rule_id = (rule.rule_id or "").lower()
        category = (rule.category or "").lower()
        return (
            category in ("ci-cd", "cicd", "ci/cd", "supply-chain")
            or rule_id.startswith("cicd")
            or rule_id.startswith("ci-")
        )

    def scan(self, context: ScanContext, rule: Rule) -> List[RuleResult]:
        """Scan a CI/CD pipeline file using the rule's regex checks."""
        return _scan_regex_checks(self, context, rule)


class DockerAdapter(LanguageAdapter):
    """Adapter for Dockerfiles and docker-compose manifests."""

    _NON_ROOT_USER = re.compile(r"^\s*USER\s+([^\s#]+)", re.IGNORECASE | re.MULTILINE)

    @property
    def language(self) -> str:
        return "docker"

    @property
    def supported_frameworks(self) -> List[str]:
        return ["docker", "docker-compose"]

    def detect_language(self, file_path: str) -> bool:
        path = file_path.replace("\\", "/")
        name = path.rsplit("/", 1)[-1].lower()
        if name == "dockerfile" or name.startswith("dockerfile."):
            return True
        if name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
            return True
        return False

    def supports_rule(self, rule: Rule) -> bool:
        rule_id = (rule.rule_id or "").lower()
        category = (rule.category or "").lower()
        return (
            rule_id.startswith("docker-")
            or category in ("container-security", "deployment", "configuration")
            or "docker" in (rule.description or "").lower()
        )

    def scan(self, context: ScanContext, rule: Rule) -> List[RuleResult]:
        # docker-002 currently has no regex check payload in the bundled rule
        # set. Implement this detector in adapter logic until rules are fully
        # externalized with typed check primitives.
        if (rule.rule_id or "").lower() == "docker-002":
            return self._scan_non_root_user(context, rule)
        return _scan_regex_checks(self, context, rule)

    def _scan_non_root_user(self, context: ScanContext, rule: Rule) -> List[RuleResult]:
        content = context.file_content
        user_match = self._NON_ROOT_USER.search(content)
        if user_match:
            user_value = user_match.group(1).strip().strip("'\"")
            if user_value and user_value.lower() not in {"root", "0"}:
                return []

        evidence = Evidence(
            file_path=context.file_path,
            line_number=1,
            column_number=0,
            code_snippet=context.file_content.splitlines()[0] if context.file_content.splitlines() else "",
            context="Container definition lacks explicit non-root USER directive",
        )
        return [
            RuleResult(
                rule_id=rule.rule_id,
                rule_title=rule.title,
                category=rule.category,
                severity=rule.severity,
                confidence=Confidence.MEDIUM,
                evidence=[evidence],
                remediation_guidance=rule.remediation_guidance or "",

            )
        ]
