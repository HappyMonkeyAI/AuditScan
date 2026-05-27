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

        for match in re.finditer(pattern, file_content):
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
            language_markers = ['java', 'javascript', 'typescript', 'c#', 'csharp', 'go', 'rust', 'swift']
            desc_lower = rule.description.lower()
            for marker in language_markers:
                if marker in desc_lower and 'python' not in desc_lower:
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
            language_markers = ['python', 'java', 'c#', 'csharp', 'go', 'rust', 'php']
            desc_lower = rule.description.lower()
            for marker in language_markers:
                if marker in desc_lower and 'javascript' not in desc_lower and 'typescript' not in desc_lower:
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
            language_markers = ['python', 'javascript', 'c#', 'csharp', 'go', 'rust', 'php']
            desc_lower = rule.description.lower()
            for marker in language_markers:
                if marker in desc_lower and 'java' not in desc_lower:
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
            language_markers = ['python', 'javascript', 'java', 'go', 'rust', 'php']
            desc_lower = rule.description.lower()
            for marker in language_markers:
                if marker in desc_lower and 'c#' not in desc_lower and 'csharp' not in desc_lower:
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
