"""Scanner for specific build-system configuration and missing build files."""

from __future__ import annotations

from pathlib import Path

from repodoctor.rules import RuleResult
from repodoctor.scanners.base import ScannerBase, Severity

# Build system -> (config file, build command hint, test command hint)
BUILD_SYSTEMS: dict[str, dict[str, list[str] | str]] = {
    "python": {
        "config_files": ["pyproject.toml", "setup.py", "setup.cfg"],
        "build_hint": "python -m build",
        "test_hint": "pytest",
    },
    "node": {
        "config_files": ["package.json"],
        "build_hint": "npm run build",
        "test_hint": "npm test",
    },
    "rust": {
        "config_files": ["Cargo.toml"],
        "build_hint": "cargo build",
        "test_hint": "cargo test",
    },
    "go": {
        "config_files": ["go.mod"],
        "build_hint": "go build ./...",
        "test_hint": "go test ./...",
    },
    "dotnet": {
        "config_files": ["*.csproj", "*.sln"],
        "build_hint": "dotnet build",
        "test_hint": "dotnet test",
    },
}


class BuildArtifactsScanner(ScannerBase):
    """Checks for build system configuration and build/test commands."""

    rule_id = "build_artifacts"
    rule_name = "Build System"

    def _scan(self, root: Path) -> RuleResult:  # noqa: ARG002
        from repodoctor.rules import RuleResult

        result = RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            enabled=True,
            passed=True,
        )

        detected_systems: list[str] = []
        for system, info in BUILD_SYSTEMS.items():
            for pattern in info["config_files"]:
                matches = list(root.glob(pattern))
                if matches:
                    detected_systems.append(system)
                    break

        if not detected_systems:
            finding = self._finding(
                title="No build system detected",
                description=(
                    "No recognized build configuration (pyproject.toml, package.json, "
                    "Cargo.toml, go.mod, .csproj, etc.) was detected. Without a build "
                    "system, users cannot easily compile or install the project."
                ),
                severity=Severity.MEDIUM,
                suggestion="Add a build configuration file appropriate for your language.",
            )
            result.findings.append(finding)

        result.passed = len(result.findings) == 0
        return result
