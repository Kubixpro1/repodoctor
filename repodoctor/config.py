"""Configuration management for repodoctor."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_CONFIG: dict[str, Any] = {
    "severity_threshold": "info",
    "output_format": "text",
    "exclude_dirs": [
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "dist",
        "build",
    ],
    "exclude_files": [".DS_Store", "Thumbs.db", "*.lock", "*.pyc", "*.pyo"],
    "exclude": [],  # CLI/ad-hoc path globs to exclude
    "offline": False,  # Skip network-based dependency checks
    "max_file_size": 2_000_000,  # bytes
    "rules": {
        "governance_files": True,
        "secrets": True,
        "dependencies": True,
        "ci_cd": True,
        "license": True,
        "tests": True,
        "readme_quality": True,
        "git_hygiene": True,
        "large_files": True,
        "build_artifacts": True,
        "github_security": True,
        "dependency_licenses": True,
    },
    "rule_overrides": {},
    # Dependency intelligence options
    "dependency_checks": {
        "outdated": True,
        "vulnerabilities": True,
        "licenses": True,
        "conflicts": True,
        "missing_lockfile": True,
    },
    # GitHub security analysis options
    "github_security": {
        "check_workflow_permissions": True,
        "check_unpinned_actions": True,
        "check_pull_request_target": True,
        "check_dependabot": True,
        "check_branch_protection": True,
    },
}


@dataclass
class RepodoctorConfig:
    """Configuration for a repodoctor run."""

    severity_threshold: str = DEFAULT_CONFIG["severity_threshold"]
    output_format: str = DEFAULT_CONFIG["output_format"]
    exclude_dirs: list[str] = field(default_factory=lambda: list(DEFAULT_CONFIG["exclude_dirs"]))
    exclude_files: list[str] = field(default_factory=lambda: list(DEFAULT_CONFIG["exclude_files"]))
    exclude: list[str] = field(default_factory=lambda: list(DEFAULT_CONFIG["exclude"]))
    offline: bool = DEFAULT_CONFIG["offline"]
    max_file_size: int = DEFAULT_CONFIG["max_file_size"]
    rules: dict[str, bool] = field(default_factory=lambda: dict(DEFAULT_CONFIG["rules"]))
    rule_overrides: dict[str, dict[str, Any]] = field(
        default_factory=lambda: dict(DEFAULT_CONFIG["rule_overrides"])
    )
    dependency_checks: dict[str, bool] = field(
        default_factory=lambda: dict(DEFAULT_CONFIG["dependency_checks"])
    )
    github_security: dict[str, bool] = field(
        default_factory=lambda: dict(DEFAULT_CONFIG["github_security"])
    )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RepodoctorConfig:
        """Build a config from a dictionary, merging with defaults."""
        merged_rules = dict(DEFAULT_CONFIG["rules"])
        merged_rules.update(data.get("rules", {}))
        merged_overrides = dict(DEFAULT_CONFIG["rule_overrides"])
        merged_overrides.update(data.get("rule_overrides", {}))
        merged_deps = dict(DEFAULT_CONFIG["dependency_checks"])
        merged_deps.update(data.get("dependency_checks", {}))
        merged_gh = dict(DEFAULT_CONFIG["github_security"])
        merged_gh.update(data.get("github_security", {}))
        return cls(
            severity_threshold=data.get("severity_threshold", DEFAULT_CONFIG["severity_threshold"]),
            output_format=data.get("output_format", DEFAULT_CONFIG["output_format"]),
            exclude_dirs=data.get("exclude_dirs", DEFAULT_CONFIG["exclude_dirs"]),
            exclude_files=data.get("exclude_files", DEFAULT_CONFIG["exclude_files"]),
            exclude=data.get("exclude", DEFAULT_CONFIG["exclude"]),
            offline=data.get("offline", DEFAULT_CONFIG["offline"]),
            max_file_size=data.get("max_file_size", DEFAULT_CONFIG["max_file_size"]),
            rules=merged_rules,
            rule_overrides=merged_overrides,
            dependency_checks=merged_deps,
            github_security=merged_gh,
        )

    @classmethod
    def load(cls, path: Path | None = None) -> RepodoctorConfig:
        """Load configuration from a JSON file, falling back to defaults.

        Looks for ``repodoctor.json`` in the current directory by default.
        """
        if path is None:
            path = Path("repodoctor.json")

        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                return cls.from_dict(data)
            except (OSError, json.JSONDecodeError):
                pass

        return cls()

    def is_rule_enabled(self, rule_name: str) -> bool:
        """Return True if a rule is enabled."""
        return self.rules.get(rule_name, True)

    def is_offline(self) -> bool:
        """Return True if network-based checks should be skipped."""
        return bool(self.offline)

    def dependency_check_enabled(self, check: str) -> bool:
        """Return True if a dependency check category is enabled."""
        return bool(self.dependency_checks.get(check, True))

    def github_check_enabled(self, check: str) -> bool:
        """Return True if a GitHub security check category is enabled."""
        return bool(self.github_security.get(check, True))
