"""Scanner for repository governance and documentation files."""

from __future__ import annotations

from pathlib import Path

from repodoctor.rules import RuleResult
from repodoctor.scanners.base import ScannerBase, Severity


class GovernanceFilesScanner(ScannerBase):
    """Checks for the presence of essential repository governance files."""

    rule_id = "governance_files"
    rule_name = "Governance Files"

    # Map of filename -> (severity, title, description, suggestion)
    GOVERNANCE_FILES: dict[str, tuple[Severity, str, str, str]] = {
        "LICENSE": (
            Severity.HIGH,
            "Missing LICENSE file",
            "No LICENSE file found. Without an explicit license, the repository "
            "defaults to all-rights-reserved copyright, which limits reuse.",
            "Add a LICENSE file with an OSI-approved license (MIT, Apache-2.0, BSD, etc.).",
        ),
        "README.md": (
            Severity.HIGH,
            "Missing README.md",
            "No README.md found. A README is the primary entry point for users and contributors.",
            "Add a README.md with project description, installation, and usage instructions.",
        ),
        "CONTRIBUTING.md": (
            Severity.MEDIUM,
            "Missing CONTRIBUTING.md",
            "No CONTRIBUTING.md found. Contribution guidelines help external "
            "contributors understand how to participate.",
            "Add a CONTRIBUTING.md with contribution workflow, coding standards, and review process.",
        ),
        "CODE_OF_CONDUCT.md": (
            Severity.MEDIUM,
            "Missing CODE_OF_CONDUCT.md",
            "No CODE_OF_CONDUCT.md found. A code of conduct sets community "
            "expectations and is required by many platforms.",
            "Add a CODE_OF_CONDUCT.md (e.g. the Contributor Covenant).",
        ),
        "SECURITY.md": (
            Severity.MEDIUM,
            "Missing SECURITY.md",
            "No SECURITY.md found. A security policy tells researchers how to "
            "report vulnerabilities responsibly.",
            "Add a SECURITY.md with supported versions and vulnerability reporting instructions.",
        ),
        "CHANGELOG.md": (
            Severity.LOW,
            "Missing CHANGELOG.md",
            "No CHANGELOG.md found. A changelog helps users track changes between releases.",
            "Add a CHANGELOG.md following Keep a Changelog conventions.",
        ),
        ".gitignore": (
            Severity.LOW,
            "Missing .gitignore",
            "No .gitignore found. Without one, build artifacts and local config "
            "may be accidentally committed.",
            "Add a .gitignore appropriate for your language and toolchain.",
        ),
    }

    def _scan(self, root: Path) -> RuleResult:  # noqa: ARG002
        result = RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            enabled=True,
            passed=True,
        )

        for filename, (severity, title, description, suggestion) in self.GOVERNANCE_FILES.items():
            file_path = root / filename
            if file_path.is_file():
                continue

            finding = self._finding(
                title=title,
                description=description,
                severity=severity,
                file_path=file_path,
                suggestion=suggestion,
            )
            result.findings.append(finding)

        result.passed = len(result.findings) == 0
        return result


class ReadmeQualityScanner(ScannerBase):
    """Checks README.md for essential sections."""

    rule_id = "readme_quality"
    rule_name = "README Quality"

    ESSENTIAL_SECTIONS: list[tuple[str, str]] = [
        ("installation", "Installation"),
        ("usage", "Usage"),
        ("license", "License"),
    ]

    def _scan(self, root: Path) -> RuleResult:  # noqa: ARG002
        result = RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            enabled=True,
            passed=True,
        )

        readme = root / "README.md"
        if not readme.is_file():
            # GovernanceFilesScanner already flags the missing README.
            result.passed = True
            return result

        content = readme.read_text(encoding="utf-8", errors="replace").lower()

        for section_key, section_title in self.ESSENTIAL_SECTIONS:
            # Look for a heading containing the section keyword.
            import re

            # Double braces escape the regex quantifier in f-strings.
            pattern = rf"#{{1,6}}\s+.*{re.escape(section_key)}"
            if not re.search(pattern, content):
                finding = self._finding(
                    title=f"README missing '{section_title}' section",
                    description=(
                        f"The README does not appear to have a '{section_title}' section. "
                        f"Users expect clear {section_key.lower()} instructions."
                    ),
                    severity=Severity.LOW,
                    file_path=readme,
                    suggestion=f"Add a '{section_title}' section to README.md.",
                )
                result.findings.append(finding)

        result.passed = len(result.findings) == 0
        return result
