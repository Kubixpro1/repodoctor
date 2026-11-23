"""Extended repository governance scanner.

Checks for additional governance artifacts that help a project run like a
professional open-source project:

* CODEOWNERS — clarifies review responsibilities.
* Issue templates — guide contributors to file useful reports.
* Pull request templates — standardize contributions.
* Maintainer documentation — explains how the project is governed.
* Versioning policy — documents how releases are versioned.
* README quality (delegated to :class:`repodoctor.scanners.files.ReadmeQualityScanner`).
"""

from __future__ import annotations

from pathlib import Path

from repodoctor.rules import RuleResult, Severity
from repodoctor.scanners.base import ScannerBase

CODEOWNERS = Path("CODEOWNERS")
ISSUE_TEMPLATE_DIR = Path(".github") / "ISSUE_TEMPLATE"
PULL_REQUEST_TEMPLATE = Path(".github") / "PULL_REQUEST_TEMPLATE.md"
MAINTAINER_DOCS = [Path("MAINTAINERS.md"), Path("GOVERNANCE.md")]


class ExtendedGovernanceScanner(ScannerBase):
    """Checks for extended governance and project documentation files."""

    rule_id = "extended_governance"
    rule_name = "Extended Governance"

    def _scan(self, root: Path) -> RuleResult:  # noqa: ARG002
        result = RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            enabled=True,
            passed=True,
        )

        checks = [
            (
                CODEOWNERS,
                "Missing CODEOWNERS file",
                "No CODEOWNERS file was found. CODEOWNERS designates individuals "
                "or teams responsible for reviewing changes to specific parts of "
                "the repository.",
                Severity.MEDIUM,
                "Add a CODEOWNERS file to clarify code review ownership.",
            ),
            (
                PULL_REQUEST_TEMPLATE,
                "Missing pull request template",
                "No pull request template was found at .github/PULL_REQUEST_TEMPLATE.md. "
                "A template helps contributors provide consistent information.",
                Severity.LOW,
                "Add .github/PULL_REQUEST_TEMPLATE.md with sections for description, "
                "testing, and checklist items.",
            ),
        ]

        for path, title, description, severity, suggestion in checks:
            if not (root / path).is_file():
                result.findings.append(
                    self._finding(
                        title=title,
                        description=description,
                        severity=severity,
                        file_path=root / path,
                        suggestion=suggestion,
                    )
                )

        # --- Issue templates --------------------------------------------
        issue_templates: list[Path] = []
        issue_dir = root / ISSUE_TEMPLATE_DIR
        if issue_dir.is_dir():
            try:
                issue_templates = sorted(
                    p
                    for p in issue_dir.iterdir()
                    if p.is_file() and p.suffix.lower() in (".md", ".yml", ".yaml")
                )
            except OSError:
                issue_templates = []

        if not issue_templates:
            result.findings.append(
                self._finding(
                    title="Missing issue templates",
                    description=(
                        "No issue templates were found under .github/ISSUE_TEMPLATE/. "
                        "Templates guide reporters to include the information "
                        "maintainers need."
                    ),
                    severity=Severity.MEDIUM,
                    suggestion=(
                        "Add issue templates (e.g. bug_report.md, "
                        "feature_request.md) under .github/ISSUE_TEMPLATE/. "
                    ),
                )
            )

        # --- Maintainer documentation ------------------------------------
        if not any((root / p).is_file() for p in MAINTAINER_DOCS):
            result.findings.append(
                self._finding(
                    title="Missing maintainer documentation",
                    description=(
                        "No maintainer documentation (MAINTAINERS.md or "
                        "GOVERNANCE.md) was found. Maintainer docs explain how "
                        "the project is governed, how releases are cut, and how "
                        "new maintainers are onboarded."
                    ),
                    severity=Severity.LOW,
                    suggestion=(
                        "Add MAINTAINERS.md describing the maintainer team, "
                        "release process, and governance model."
                    ),
                )
            )

        # --- Versioning policy ------------------------------------------
        if not self._has_versioning_policy(root):
            result.findings.append(
                self._finding(
                    title="No documented versioning policy",
                    description=(
                        "No versioning policy (e.g. Semantic Versioning) was "
                        "found in README.md, CONTRIBUTING.md, or a dedicated "
                        "VERSIONING document. Users cannot tell how breaking "
                        "changes are communicated."
                    ),
                    severity=Severity.MEDIUM,
                    suggestion=(
                        "Document your versioning policy (e.g. Semantic "
                        "Versioning) in README.md or CONTRIBUTING.md."
                    ),
                )
            )

        result.passed = result.critical_count == 0 and result.high_count == 0
        return result

    @staticmethod
    def _has_versioning_policy(root: Path) -> bool:
        """Return True if a versioning policy is referenced in common docs."""
        candidates = [root / "README.md", root / "CONTRIBUTING.md"]
        candidates.extend(MAINTAINER_DOCS)
        for path in candidates:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            lowered = text.lower()
            if "semantic versioning" in lowered or "semver" in lowered:
                return True
            if "versioning policy" in lowered:
                return True
        return False
