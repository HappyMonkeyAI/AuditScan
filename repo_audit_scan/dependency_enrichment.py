"""Dependency lockfile scanning and optional advisory enrichment."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple
from urllib import request

from repo_audit_scan.error import EnrichmentError
from repo_audit_scan.models import Confidence, Evidence, RuleResult, Severity
from repo_audit_scan.rules import Rule, RuleRegistry


@dataclass(frozen=True)
class PackageCoordinate:
    """A dependency discovered from local lockfiles."""

    name: str
    version: str
    source_file: str
    line_number: Optional[int] = None


@dataclass(frozen=True)
class Advisory:
    """Enriched advisory metadata for a package."""

    id: str
    summary: str
    severity: Severity
    url: Optional[str] = None


KNOWN_VULNERABLE_CONSTRAINTS: Dict[str, str] = {
    "lodash": "4.17.21",
    "requests": "2.32.0",
    "pyyaml": "6.0.1",
}


def scan_dependencies(
    repo_path: Path,
    registry: RuleRegistry,
    enrich_dependencies: bool = False,
    fail_open: bool = True,
    enrichment_provider: Optional[Callable[[Iterable[PackageCoordinate]], Dict[str, List[Advisory]]]] = None,
) -> Tuple[List[RuleResult], Dict[str, object]]:
    """Scan lockfiles for vulnerable/outdated dependency signals."""
    packages = discover_packages(repo_path)
    if not packages:
        return [], {"mode": "none", "packages_scanned": 0, "enriched": False, "errors": []}

    vulnerable_rule = registry.get_by_id("general-001") or _fallback_rule(
        rule_id="general-001",
        title="Known vulnerable dependency",
        category="dependency",
        severity=Severity.HIGH,
    )
    outdated_rule = registry.get_by_id("general-002") or _fallback_rule(
        rule_id="general-002",
        title="Outdated dependency",
        category="dependency",
        severity=Severity.MEDIUM,
    )

    findings: List[RuleResult] = []
    for package in packages:
        min_safe = KNOWN_VULNERABLE_CONSTRAINTS.get(package.name.lower())
        if min_safe and _is_version_less_than(package.version, min_safe):
            findings.append(
                RuleResult(
                    rule_id=vulnerable_rule.rule_id,
                    rule_title=vulnerable_rule.title,
                    category=vulnerable_rule.category,
                    severity=vulnerable_rule.severity,
                    confidence=Confidence.HIGH,
                    evidence=[_package_evidence(package, label="lockfile-only")],
                    remediation_guidance=f"Upgrade {package.name} to >= {min_safe}.",
                )
            )
        elif _looks_outdated(package.version):
            findings.append(
                RuleResult(
                    rule_id=outdated_rule.rule_id,
                    rule_title=outdated_rule.title,
                    category=outdated_rule.category,
                    severity=outdated_rule.severity,
                    confidence=Confidence.MEDIUM,
                    evidence=[_package_evidence(package, label="lockfile-only")],
                    remediation_guidance=f"Review and upgrade {package.name} from {package.version}.",
                )
            )

    enriched = False
    errors: List[str] = []
    if enrich_dependencies and _network_enrichment_enabled():
        provider = enrichment_provider or _default_enrichment_provider
        try:
            advisories_by_package = provider(packages)
            for package in packages:
                advisories = advisories_by_package.get(package.name.lower(), [])
                for advisory in advisories:
                    findings.append(
                        RuleResult(
                            rule_id=vulnerable_rule.rule_id,
                            rule_title=vulnerable_rule.title,
                            category=vulnerable_rule.category,
                            severity=advisory.severity,
                            confidence=Confidence.HIGH,
                            evidence=[_package_evidence(package, label=f"enriched:{advisory.id}")],
                            remediation_guidance=advisory.summary,
                        )
                    )
            enriched = True
        except Exception as exc:  # noqa: BLE001
            if not fail_open:
                raise EnrichmentError(str(exc)) from exc
            errors.append(str(exc))

    metadata = {
        "mode": "lockfile-only" if not enriched else "enriched",
        "packages_scanned": len(packages),
        "enriched": enriched,
        "errors": errors,
    }
    return findings, metadata


def discover_packages(repo_path: Path) -> List[PackageCoordinate]:
    """Discover package coordinates from common lockfiles/manifests."""
    packages: List[PackageCoordinate] = []
    packages.extend(_parse_requirements(repo_path / "requirements.txt", repo_path))
    packages.extend(_parse_package_lock(repo_path / "package-lock.json", repo_path))
    packages.extend(_parse_composer_lock(repo_path / "composer.lock", repo_path))
    return packages


def _parse_requirements(path: Path, repo_root: Path) -> List[PackageCoordinate]:
    if not path.exists():
        return []
    output: List[PackageCoordinate] = []
    for index, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "==" not in stripped:
            continue
        name, version = stripped.split("==", 1)
        output.append(
            PackageCoordinate(
                name=name.strip(),
                version=version.strip(),
                source_file=str(path.relative_to(repo_root)),
                line_number=index,
            )
        )
    return output


def _parse_package_lock(path: Path, repo_root: Path) -> List[PackageCoordinate]:
    if not path.exists():
        return []
    raw = path.read_text(encoding="utf-8", errors="replace")
    payload = json.loads(raw)
    packages: List[PackageCoordinate] = []
    deps = payload.get("dependencies", {})
    for name, dep in deps.items():
        version = str(dep.get("version", "")).strip()
        if not version:
            continue
        line_number = _find_line(raw, f"\"{name}\"")
        packages.append(
            PackageCoordinate(
                name=name,
                version=version,
                source_file=str(path.relative_to(repo_root)),
                line_number=line_number,
            )
        )
    return packages


def _parse_composer_lock(path: Path, repo_root: Path) -> List[PackageCoordinate]:
    if not path.exists():
        return []
    raw = path.read_text(encoding="utf-8", errors="replace")
    payload = json.loads(raw)
    packages: List[PackageCoordinate] = []
    for item in payload.get("packages", []):
        name = str(item.get("name", "")).strip()
        version = str(item.get("version", "")).strip().lstrip("v")
        if not name or not version:
            continue
        line_number = _find_line(raw, f"\"{name}\"")
        packages.append(
            PackageCoordinate(
                name=name,
                version=version,
                source_file=str(path.relative_to(repo_root)),
                line_number=line_number,
            )
        )
    return packages


def _find_line(text: str, needle: str) -> Optional[int]:
    for index, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return index
    return None


def _package_evidence(package: PackageCoordinate, label: str) -> Evidence:
    return Evidence(
        file_path=package.source_file,
        line_number=package.line_number,
        code_snippet=f"{package.name}=={package.version}",
        context=f"dependency-signal:{label}",
    )


def _fallback_rule(rule_id: str, title: str, category: str, severity: Severity) -> Rule:
    return Rule(
        rule_id=rule_id,
        category=category,
        title=title,
        description=title,
        severity=severity,
        checks=[],
        remediation_guidance="Upgrade dependency to a safe version.",
    )


def _looks_outdated(version: str) -> bool:
    parts = _parse_version(version)
    return bool(parts) and parts[0] == 0


def _is_version_less_than(left: str, right: str) -> bool:
    return _parse_version(left) < _parse_version(right)


def _parse_version(value: str) -> Tuple[int, ...]:
    matches = re.findall(r"\d+", value)
    if not matches:
        return (0,)
    return tuple(int(item) for item in matches[:4])


def _network_enrichment_enabled() -> bool:
    value = os.getenv("REPO_AUDIT_DEP_ENRICHMENT", "false").strip().lower()
    return value in {"1", "true", "yes", "on"}


def _default_enrichment_provider(packages: Iterable[PackageCoordinate]) -> Dict[str, List[Advisory]]:
    """Best-effort OSV lookups, sending only package coordinates."""
    advisories: Dict[str, List[Advisory]] = {}
    for package in packages:
        query_payload = json.dumps(
            {
                "package": {"name": package.name},
                "version": package.version,
            }
        ).encode("utf-8")
        req = request.Request(
            "https://api.osv.dev/v1/query",
            data=query_payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with request.urlopen(req, timeout=5) as response:  # noqa: S310
            data = json.loads(response.read().decode("utf-8"))
        vulns = data.get("vulns", []) if isinstance(data, dict) else []
        if not vulns:
            continue
        mapped: List[Advisory] = []
        for vuln in vulns:
            vuln_id = str(vuln.get("id", "OSV-UNKNOWN"))
            summary = str(vuln.get("summary") or vuln.get("details") or "Known vulnerable dependency.")
            mapped.append(Advisory(id=vuln_id, summary=summary, severity=Severity.HIGH, url=None))
        advisories[package.name.lower()] = mapped
    return advisories
