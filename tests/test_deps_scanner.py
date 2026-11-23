"""Tests for the DependenciesScanner dependency intelligence."""

from __future__ import annotations

from repodoctor.config import RepodoctorConfig
from repodoctor.scanners.deps import DependenciesScanner


def test_no_manifest_produces_info_finding(tmp_path):
    scanner = DependenciesScanner(RepodoctorConfig())
    result = scanner.scan(tmp_path)
    assert result.passed
    assert any("No dependency manifest" in f.title for f in result.findings)


def test_missing_lockfile_flagged(tmp_path):
    (tmp_path / "package.json").write_text('{"name": "x", "dependencies": {}}\n')
    scanner = DependenciesScanner(RepodoctorConfig())
    result = scanner.scan(tmp_path)
    assert any("Missing lockfile" in f.title for f in result.findings)


def test_version_conflict_flagged(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==1.0.0\n")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = ["requests==2.0.0"]\n'
    )
    scanner = DependenciesScanner(RepodoctorConfig())
    result = scanner.scan(tmp_path)
    assert any("version conflict" in f.title.lower() for f in result.findings)


def test_offline_skips_vulnerability_scan(tmp_path, monkeypatch):
    """Offline mode must not run network audit tools."""
    (tmp_path / "requirements.txt").write_text("requests==2.28.1\n")
    config = RepodoctorConfig()
    config.offline = True
    scanner = DependenciesScanner(config)
    result = scanner.scan(tmp_path)
    assert result.metadata.get("vulnerability_scan") == "skipped_offline"


def test_dependency_inventory_recorded(tmp_path):
    (tmp_path / "package.json").write_text('{"name": "x", "dependencies": {"lodash": "1.0.0"}}\n')
    scanner = DependenciesScanner(RepodoctorConfig())
    result = scanner.scan(tmp_path)
    inv = result.metadata.get("dependency_inventory", {})
    assert inv.get("dependency_count", 0) >= 1
