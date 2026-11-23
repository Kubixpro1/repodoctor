"""Scanner for test presence and configuration."""

from __future__ import annotations

from pathlib import Path

from repodoctor.rules import RuleResult
from repodoctor.scanners.base import ScannerBase, Severity
from repodoctor.utils import iter_files


class TestsScanner(ScannerBase):
    """Checks for the presence of tests and test configuration."""

    rule_id = "tests"
    rule_name = "Tests"

    TEST_DIRS: list[str] = ["tests", "test", "testing", "__tests__", "__test__"]
    TEST_FILE_PATTERNS: list[str] = [
        "test_*.py",
        "*_test.py",
        "*_test.go",
        "*_test.js",
        "*_test.ts",
        "*.test.js",
        "*.test.ts",
    ]

    def _scan(self, root: Path) -> RuleResult:  # noqa: ARG002
        result = RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            enabled=True,
            passed=True,
        )

        # Check for test directories.
        has_test_dir = any((root / d).is_dir() for d in self.TEST_DIRS)

        # Check for test files.
        test_files = list(iter_files(root, patterns=self.TEST_FILE_PATTERNS))

        if not has_test_dir and not test_files:
            finding = self._finding(
                title="No tests found",
                description=(
                    "No test files or test directories were detected. Automated tests "
                    "are essential for maintaining code quality and preventing regressions."
                ),
                severity=Severity.MEDIUM,
                suggestion=(
                    "Add a test suite (e.g. pytest for Python, Jest for Node.js, "
                    "cargo test for Rust) and place it in a tests/ directory."
                ),
            )
            result.findings.append(finding)

        result.passed = len(result.findings) == 0
        return result
