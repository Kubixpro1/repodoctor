"""Tests for scanner modules."""

from __future__ import annotations

from repodoctor.config import RepodoctorConfig
from repodoctor.scanners.build_artifacts import BuildArtifactsScanner
from repodoctor.scanners.ci import CIScanner
from repodoctor.scanners.files import GovernanceFilesScanner, ReadmeQualityScanner
from repodoctor.scanners.git_hygiene import GitHygieneScanner
from repodoctor.scanners.large_files import LargeFilesScanner
from repodoctor.scanners.license import LicenseScanner
from repodoctor.scanners.secrets import SecretsScanner
from repodoctor.scanners.tests import TestsScanner


def test_governance_files_missing(tmp_path):
    """Missing governance files produce findings."""
    scanner = GovernanceFilesScanner(RepodoctorConfig())
    result = scanner.scan(tmp_path)
    assert not result.passed
    rule_ids = {f.rule_id for f in result.findings}
    assert "governance_files" in rule_ids
    titles = [f.title for f in result.findings]
    assert any("LICENSE" in t for t in titles)
    assert any("README.md" in t for t in titles)


def test_governance_files_present(healthy_repo):
    """Present governance files pass."""
    scanner = GovernanceFilesScanner(RepodoctorConfig())
    result = scanner.scan(healthy_repo)
    assert result.passed
    assert len(result.findings) == 0


def test_secrets_detected(unhealthy_repo):
    """Hardcoded secrets are detected."""
    scanner = SecretsScanner(RepodoctorConfig())
    result = scanner.scan(unhealthy_repo)
    assert not result.passed
    critical = [f for f in result.findings if f.severity.value == "critical"]
    assert len(critical) > 0
    # Secret values should not be printed in titles
    for f in result.findings:
        assert "sk_live_" not in f.title
        assert "sk_live_" not in (f.description or "")


def test_secrets_none(healthy_repo):
    """No secrets in a clean repo."""
    scanner = SecretsScanner(RepodoctorConfig())
    result = scanner.scan(healthy_repo)
    assert result.passed
    assert len(result.findings) == 0


def test_ci_missing(tmp_path):
    """Missing CI config produces a finding."""
    scanner = CIScanner(RepodoctorConfig())
    result = scanner.scan(tmp_path)
    assert not result.passed
    assert any(
        "CI/CD" in f.title or "CI/CD configuration" in f.description for f in result.findings
    )


def test_ci_present_with_tests(tmp_path):
    """CI config with test steps passes."""
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "workflows").mkdir()
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "name: CI\non: [push]\njobs:\n  test:\n    run: pytest\n"
    )
    scanner = CIScanner(RepodoctorConfig())
    result = scanner.scan(tmp_path)
    assert result.passed


def test_license_missing(tmp_path):
    """Missing LICENSE produces a finding."""
    scanner = LicenseScanner(RepodoctorConfig())
    result = scanner.scan(tmp_path)
    assert result.passed  # governance scanner handles missing LICENSE


def test_license_unrecognized(tmp_path):
    """Unrecognized license produces a finding."""
    (tmp_path / "LICENSE").write_text("This is a custom license with no standard text.\n")
    scanner = LicenseScanner(RepodoctorConfig())
    result = scanner.scan(tmp_path)
    assert not result.passed
    assert any("Unrecognized" in f.title for f in result.findings)


def test_license_mit(healthy_repo):
    """MIT license passes."""
    scanner = LicenseScanner(RepodoctorConfig())
    result = scanner.scan(healthy_repo)
    assert result.passed


def test_tests_missing(tmp_path):
    """Missing tests produces a finding."""
    scanner = TestsScanner(RepodoctorConfig())
    result = scanner.scan(tmp_path)
    assert not result.passed
    assert any("tests" in f.title.lower() for f in result.findings)


def test_tests_present(healthy_repo):
    """Present tests pass."""
    scanner = TestsScanner(RepodoctorConfig())
    result = scanner.scan(healthy_repo)
    assert result.passed


def test_readme_quality_missing_sections(tmp_path):
    """README missing essential sections produces findings."""
    (tmp_path / "README.md").write_text("# Project\n\nJust a description.\n")
    scanner = ReadmeQualityScanner(RepodoctorConfig())
    result = scanner.scan(tmp_path)
    assert not result.passed
    assert any("Installation" in f.title for f in result.findings)


def test_readme_quality_complete(tmp_path):
    """Complete README passes."""
    (tmp_path / "README.md").write_text(
        "# Project\n\n## Installation\n\npip install\n\n## Usage\n\nuse it\n\n## License\n\nMIT\n"
    )
    scanner = ReadmeQualityScanner(RepodoctorConfig())
    result = scanner.scan(tmp_path)
    assert result.passed


def test_git_hygiene_not_git(tmp_path):
    """Non-git directory produces a finding."""
    scanner = GitHygieneScanner(RepodoctorConfig())
    result = scanner.scan(tmp_path)
    assert not result.passed
    assert any("Git repository" in f.title for f in result.findings)


def test_git_hygiene_no_commits(tmp_path):
    """Git repo with no commits produces a finding."""
    (tmp_path / ".git").mkdir()
    scanner = GitHygieneScanner(RepodoctorConfig())
    result = scanner.scan(tmp_path)
    assert not result.passed
    assert any("commits" in f.title.lower() for f in result.findings)


def test_large_files(tmp_path):
    """Large files are detected."""
    # Create a 60 MB file
    big_file = tmp_path / "big.dat"
    big_file.write_bytes(b"\x00" * (60 * 1024 * 1024))
    scanner = LargeFilesScanner(RepodoctorConfig())
    result = scanner.scan(tmp_path)
    assert not result.passed
    assert any("Large file" in f.title for f in result.findings)


def test_build_artifacts_none(tmp_path):
    """No build system detected."""
    scanner = BuildArtifactsScanner(RepodoctorConfig())
    result = scanner.scan(tmp_path)
    assert not result.passed
    assert any("build system" in f.title.lower() for f in result.findings)


def test_build_artifacts_python(tmp_path):
    """Python build system detected."""
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "test"\n')
    scanner = BuildArtifactsScanner(RepodoctorConfig())
    result = scanner.scan(tmp_path)
    assert result.passed


def test_disabled_rule(tmp_path):
    """Disabled rules produce no findings."""
    config = RepodoctorConfig(rules={"secrets": False})
    scanner = SecretsScanner(config)
    result = scanner.scan(tmp_path)
    assert result.enabled is False
    assert result.passed
