"""Tests for the GitHub security scanner."""

from __future__ import annotations

from pathlib import Path

from repodoctor.config import RepodoctorConfig
from repodoctor.scanners.gh_security import GitHubSecurityScanner


def _write_workflow(tmp_path: Path, name: str, content: str) -> Path:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    p = wf_dir / name
    p.write_text(content)
    return p


def test_no_workflows_informational(tmp_path):
    scanner = GitHubSecurityScanner(RepodoctorConfig())
    result = scanner.scan(tmp_path)
    assert any("No GitHub Actions workflows" in f.title for f in result.findings)


def test_missing_permissions_flagged(tmp_path):
    _write_workflow(tmp_path, "ci.yml", "name: CI\njobs:\n  build:\n    runs-on: ubuntu-latest\n")
    scanner = GitHubSecurityScanner(RepodoctorConfig())
    result = scanner.scan(tmp_path)
    assert any("missing permissions" in f.title.lower() for f in result.findings)


def test_write_all_permissions_flagged(tmp_path):
    _write_workflow(
        tmp_path,
        "ci.yml",
        "permissions:\n  write-all: true\njobs:\n  build:\n    runs-on: ubuntu-latest\n",
    )
    scanner = GitHubSecurityScanner(RepodoctorConfig())
    result = scanner.scan(tmp_path)
    assert any("write-all" in f.title.lower() for f in result.findings)


def test_unpinned_third_party_action_flagged(tmp_path):
    _write_workflow(
        tmp_path,
        "ci.yml",
        "jobs:\n  build:\n    uses: actions/checkout\n    runs-on: ubuntu-latest\n",
    )
    scanner = GitHubSecurityScanner(RepodoctorConfig())
    result = scanner.scan(tmp_path)
    assert any("Unpinned action" in f.title for f in result.findings)


def test_pinned_action_not_flagged(tmp_path):
    _write_workflow(
        tmp_path,
        "ci.yml",
        "jobs:\n  build:\n    uses: actions/checkout@v4\n    runs-on: ubuntu-latest\n",
    )
    scanner = GitHubSecurityScanner(RepodoctorConfig())
    result = scanner.scan(tmp_path)
    assert not any("Unpinned action" in f.title for f in result.findings)


def test_pull_request_target_with_write_flagged(tmp_path):
    _write_workflow(
        tmp_path,
        "ci.yml",
        "on: pull_request_target\njobs:\n  build:\n    permissions:\n      contents: write\n    runs-on: ubuntu-latest\n",
    )
    scanner = GitHubSecurityScanner(RepodoctorConfig())
    result = scanner.scan(tmp_path)
    assert any("pull_request_target" in f.title.lower() for f in result.findings)


def test_missing_dependabot_flagged(tmp_path):
    _write_workflow(tmp_path, "ci.yml", "jobs:\n  build:\n    runs-on: ubuntu-latest\n")
    scanner = GitHubSecurityScanner(RepodoctorConfig())
    result = scanner.scan(tmp_path)
    assert any("Dependabot" in f.title for f in result.findings)


def test_missing_security_policy_flagged(tmp_path):
    _write_workflow(tmp_path, "ci.yml", "jobs:\n  build:\n    runs-on: ubuntu-latest\n")
    scanner = GitHubSecurityScanner(RepodoctorConfig())
    result = scanner.scan(tmp_path)
    assert any("security policy" in f.title.lower() for f in result.findings)


def test_branch_protection_reported_unknown(tmp_path):
    _write_workflow(tmp_path, "ci.yml", "jobs:\n  build:\n    runs-on: ubuntu-latest\n")
    scanner = GitHubSecurityScanner(RepodoctorConfig())
    result = scanner.scan(tmp_path)
    assert any("unknown" in f.title.lower() for f in result.findings)
