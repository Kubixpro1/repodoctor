"""Pytest fixtures for repodoctor tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from repodoctor.config import RepodoctorConfig
from repodoctor.rules import Finding, ScanReport, Severity

STRIPE_TEST_SECRET = "sk_" + "live_" + "1234567890abcdef1234567890"


@pytest.fixture
def tmp_repo(tmp_path: Path) -> Path:
    """Create a temporary directory that acts as a repository root."""
    return tmp_path


@pytest.fixture
def healthy_repo(tmp_path: Path) -> Path:
    """Create a repo with all governance files and no issues."""
    (tmp_path / "LICENSE").write_text("MIT License\n")
    (tmp_path / "README.md").write_text(
        "# Test Project\n\n## Installation\n\npip install test\n\n## Usage\n\n# usage\n\n## License\n\nMIT\n"
    )
    (tmp_path / "CONTRIBUTING.md").write_text("# Contributing\n")
    (tmp_path / "CODE_OF_CONDUCT.md").write_text("# Code of Conduct\n")
    (tmp_path / "SECURITY.md").write_text("# Security\n")
    (tmp_path / "CHANGELOG.md").write_text("# Changelog\n")
    (tmp_path / ".gitignore").write_text("*.pyc\n__pycache__/\n")
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "test"\n')
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_basic.py").write_text("def test_ok():\n    assert True\n")
    return tmp_path


@pytest.fixture
def unhealthy_repo(tmp_path: Path) -> Path:
    """Create a repo missing governance files with a secret."""
    (tmp_path / "README.md").write_text("# Test\n")
    (tmp_path / "secret.py").write_text(f'API_KEY = "{STRIPE_TEST_SECRET}"\n')
    return tmp_path


@pytest.fixture
def config() -> RepodoctorConfig:
    """Return a default configuration."""
    return RepodoctorConfig()


@pytest.fixture
def sample_finding() -> Finding:
    """Return a sample finding."""
    return Finding(
        rule_id="test_rule",
        title="Test Finding",
        description="A test description",
        severity=Severity.HIGH,
        suggestion="Fix this issue",
    )


@pytest.fixture
def sample_report(tmp_path: Path) -> ScanReport:
    """Return a sample scan report with findings."""
    report = ScanReport(target=tmp_path)
    finding = Finding(
        rule_id="test_rule",
        title="Test Finding",
        description="A test description",
        severity=Severity.HIGH,
        suggestion="Fix this issue",
    )
    report.all_findings.append(finding)
    return report
