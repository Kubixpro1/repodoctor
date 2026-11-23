"""Scanner for CI/CD configuration."""

from __future__ import annotations

from pathlib import Path

from repodoctor.rules import RuleResult
from repodoctor.scanners.base import ScannerBase, Severity
from repodoctor.utils import read_file_safely


class CIScanner(ScannerBase):
    """Checks for CI/CD configuration and basic workflow health."""

    rule_id = "ci_cd"
    rule_name = "CI/CD"

    CI_CONFIG_FILES: list[str] = [
        ".github/workflows/ci.yml",
        ".github/workflows/ci.yaml",
        ".github/workflows/main.yml",
        ".github/workflows/main.yaml",
        ".gitlab-ci.yml",
        ".circleci/config.yml",
        "Jenkinsfile",
        ".travis.yml",
        "azure-pipelines.yml",
        "buildkite.yml",
    ]

    def _scan(self, root: Path) -> RuleResult:  # noqa: ARG002
        result = RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            enabled=True,
            passed=True,
        )

        found = [f for f in self.CI_CONFIG_FILES if (root / f).is_file()]

        if not found:
            finding = self._finding(
                title="No CI/CD configuration found",
                description=(
                    "No CI/CD configuration was detected. Continuous integration "
                    "helps catch regressions and run tests automatically on every change."
                ),
                severity=Severity.MEDIUM,
                suggestion=(
                    "Add a CI configuration file (e.g. .github/workflows/ci.yml for "
                    "GitHub Actions) that runs tests on push and pull requests."
                ),
            )
            result.findings.append(finding)
        else:
            # Check if the CI config actually runs tests (best-effort heuristic).
            for ci_file in found:
                content = read_file_safely(root / ci_file) or ""
                if not any(
                    kw in content.lower()
                    for kw in ["test", "pytest", "npm test", "cargo test", "go test", "mvn test"]
                ):
                    finding = self._finding(
                        title=f"CI config '{ci_file}' may not run tests",
                        description=(
                            f"The CI configuration at {ci_file} does not appear to "
                            "include a test step. Running tests in CI is essential."
                        ),
                        severity=Severity.LOW,
                        file_path=root / ci_file,
                        suggestion="Add a test step to your CI workflow.",
                    )
                    result.findings.append(finding)

        result.passed = len(result.findings) == 0
        return result
