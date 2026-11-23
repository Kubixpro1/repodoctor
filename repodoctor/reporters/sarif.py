"""SARIF (Static Analysis Results Interchange Format) reporter.

Produces fully valid SARIF 2.1.0 output compatible with GitHub Code Scanning
and other static-analysis platforms.

Properties
----------
* Schema: https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/schemas/sarif-schema-2.1.0.json
* Artifact paths are repository-relative.
* Rule definitions are stable and include severity-based ``security-severity``.
* Secret values are never emitted (redacted by the base reporter).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from repodoctor import __version__
from repodoctor.reporters.base import ReporterBase
from repodoctor.rules import ScanReport, Severity

# Map repodoctor severities to SARIF levels.
SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# GitHub Code Scanning maps ``security-severity`` (CVSS 0-10) to a display
# severity. Use a consistent mapping so critical findings surface prominently.
SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.0",
    Severity.HIGH: "7.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/schemas/sarif-schema-2.1.0.json"
)

# Stable rule definitions. Each rule has a fixed id and metadata so that
# GitHub Code Scanning can group results and display help.
RULE_DEFINITIONS: dict[str, dict[str, Any]] = {
    "governance_files": {
        "name": "Governance Files",
        "fullDescription": {
            "text": "Checks for the presence of essential repository governance files."
        },
        "help": {"text": "Add missing governance files (LICENSE, README.md, SECURITY.md, etc.)."},
        "tags": ["governance"],
        "security-severity": "5.0",
    },
    "extended_governance": {
        "name": "Extended Governance",
        "fullDescription": {
            "text": "Checks for extended governance artifacts (CODEOWNERS, issue templates, etc.)."
        },
        "tags": ["governance"],
        "security-severity": "3.0",
    },
    "readme_quality": {
        "name": "README Quality",
        "fullDescription": {"text": "Checks README.md for essential sections."},
        "tags": ["documentation"],
        "security-severity": "1.0",
    },
    "secrets": {
        "name": "Secrets Detection",
        "fullDescription": {
            "text": "Detects hardcoded secrets, API keys, tokens, and credentials."
        },
        "help": {
            "text": "Remove the secret from the file and rotate exposed credentials. "
            "Secret values are redacted in this report."
        },
        "tags": ["security", "secrets"],
        "security-severity": "9.0",
    },
    "dependencies": {
        "name": "Dependencies",
        "fullDescription": {
            "text": "Analyzes dependency manifests for vulnerabilities, outdated packages, and conflicts."
        },
        "tags": ["security", "dependencies"],
        "security-severity": "7.0",
    },
    "ci_cd": {
        "name": "CI/CD",
        "fullDescription": {"text": "Checks for CI/CD configuration and test steps."},
        "tags": ["ci"],
        "security-severity": "3.0",
    },
    "github_security": {
        "name": "GitHub Security",
        "fullDescription": {"text": "Analyzes GitHub Actions workflows for security gaps."},
        "tags": ["security", "github-actions"],
        "security-severity": "7.0",
    },
    "license": {
        "name": "License",
        "fullDescription": {
            "text": "Validates the presence and recognizability of a LICENSE file."
        },
        "tags": ["licensing"],
        "security-severity": "3.0",
    },
    "tests": {
        "name": "Tests",
        "fullDescription": {"text": "Checks for the presence of test files and directories."},
        "tags": ["testing"],
        "security-severity": "1.0",
    },
    "git_hygiene": {
        "name": "Git Hygiene",
        "fullDescription": {"text": "Checks Git repository health (commits, remotes, tags)."},
        "tags": ["version-control"],
        "security-severity": "1.0",
    },
    "large_files": {
        "name": "Large Files & Artifacts",
        "fullDescription": {"text": "Flags unusually large files and committed build artifacts."},
        "tags": ["repository-health"],
        "security-severity": "1.0",
    },
    "build_artifacts": {
        "name": "Build System",
        "fullDescription": {"text": "Detects build system configuration files."},
        "tags": ["build"],
        "security-severity": "1.0",
    },
}


def _relative_uri(path: Path | None, root: Path) -> str | None:
    """Return a repository-relative URI for *path*."""
    if path is None:
        return None
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


class SARIFReporter(ReporterBase):
    """SARIF 2.1.0 report for integration with code-scanning platforms."""

    format_name = "sarif"

    def format(self, report: ScanReport, history_comparison: dict[str, Any] | None = None) -> str:
        root = report.target
        results: list[dict[str, Any]] = []

        for finding in report.all_findings:
            location: dict[str, Any] | None = None
            if finding.file_path:
                region: dict[str, Any] = {"startLine": finding.line_number or 1}
                if finding.line_number:
                    region["startColumn"] = 1
                    region["endColumn"] = 1
                location = {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": _relative_uri(finding.file_path, root) or "",
                        },
                        "region": region,
                    }
                }

            result: dict[str, Any] = {
                "ruleId": finding.rule_id,
                "level": SARIF_LEVEL.get(finding.severity, "note"),
                "message": {"text": finding.description or finding.title},
                "locations": [location] if location else [],
            }
            # Include a stable fingerprint so GitHub can deduplicate across runs.
            result["fingerprints"] = {
                "primary": f"{finding.rule_id}:{finding.file_path}:{finding.line_number}:{finding.title}"
            }
            results.append(result)

        # Collect unique rules from findings and registered definitions.
        seen_rule_ids: set[str] = set()
        sarif_rules: list[dict[str, Any]] = []

        def add_rule(rule_id: str, rule_name: str) -> None:
            if rule_id in seen_rule_ids:
                return
            seen_rule_ids.add(rule_id)
            definition = RULE_DEFINITIONS.get(rule_id, {})
            sarif_rules.append(
                {
                    "id": rule_id,
                    "name": rule_name or rule_id,
                    "fullDescription": definition.get(
                        "fullDescription", {"text": rule_name or rule_id}
                    ),
                    "help": definition.get("help"),
                    "properties": {
                        "precision": "high",
                        "tags": definition.get("tags", []),
                        "security-severity": definition.get(
                            "security-severity",
                            SECURITY_SEVERITY.get(
                                Severity(finding_severity(rule_id, report)), "1.0"
                            ),
                        ),
                    },
                }
            )

        def finding_severity(rule_id: str, report: ScanReport) -> Severity:
            for finding in report.all_findings:
                if finding.rule_id == rule_id:
                    return finding.severity
            return Severity.INFO

        for finding in report.all_findings:
            add_rule(finding.rule_id, _rule_name(finding.rule_id, report))
        for rule in report.rules:
            add_rule(rule.rule_id, rule.rule_name)

        sarif = {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "repodoctor",
                            "version": __version__,
                            "informationUri": "https://github.com/repodoctor/repodoctor",
                            "rules": sarif_rules,
                        }
                    },
                    "results": results,
                }
            ],
        }

        if history_comparison is not None:
            # History info is not part of core SARIF; attach under a
            # namespaced property on the run so it does not break validation.
            run = sarif["runs"][0]
            run["properties"] = {"repodoctor.history": history_comparison}  # type: ignore[index]

        import json

        return json.dumps(sarif, indent=2) + "\n"


def _rule_name(rule_id: str, report: ScanReport) -> str:
    for rule in report.rules:
        if rule.rule_id == rule_id:
            return rule.rule_name
    return rule_id
