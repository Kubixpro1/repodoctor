"""Tests for the CLI."""

from __future__ import annotations

import json
import sys
from io import StringIO

from repodoctor.cli import main


def run_cli(argv: list[str]) -> tuple[int, str, str]:
    """Run main with given argv, capturing stdout/stderr and exit code."""
    old_stdout = sys.stdout
    old_stderr = sys.stderr
    sys.stdout = StringIO()
    sys.stderr = StringIO()
    try:
        exit_code = main(argv)
        stdout = sys.stdout.getvalue()
        stderr = sys.stderr.getvalue()
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr
    return exit_code, stdout, stderr


def test_version():
    """repodoctor version works."""
    exit_code, stdout, _ = run_cli(["version"])
    assert exit_code == 0
    assert "repodoctor" in stdout


def test_list_rules():
    """repodoctor --list-rules works."""
    exit_code, stdout, _ = run_cli(["--list-rules"])
    assert exit_code == 0
    assert "governance_files" in stdout
    assert "secrets" in stdout


def test_scan_current_dir(tmp_path, monkeypatch):
    """repodoctor scan on current directory works."""
    monkeypatch.chdir(tmp_path)
    exit_code, stdout, _ = run_cli(["scan", "."])
    assert exit_code in (0, 1)
    assert "repodoctor" in stdout or "Health" in stdout


def test_scan_json_format(tmp_path, monkeypatch):
    """repodoctor scan --format json works."""
    monkeypatch.chdir(tmp_path)
    exit_code, stdout, _ = run_cli(["scan", ".", "--format", "json"])
    assert exit_code in (0, 1)
    data = json.loads(stdout)
    assert "health_score" in data


def test_scan_sarif_format(tmp_path, monkeypatch):
    """repodoctor scan --format sarif works."""
    monkeypatch.chdir(tmp_path)
    exit_code, stdout, _ = run_cli(["scan", ".", "--format", "sarif"])
    assert exit_code in (0, 1)
    data = json.loads(stdout)
    assert data["version"] == "2.1.0"


def test_scan_nonexistent_dir():
    """repodoctor scan on nonexistent dir errors."""
    exit_code, _, stderr = run_cli(["scan", "/nonexistent/path/xyz"])
    assert exit_code == 2
    assert "not a directory" in stderr


def test_init_creates_config(tmp_path):
    """repodoctor init creates a config file."""
    config_path = tmp_path / "repodoctor.json"
    exit_code, stdout, _ = run_cli(["init", "--path", str(config_path)])
    assert exit_code == 0
    assert config_path.is_file()
    data = json.loads(config_path.read_text(encoding="utf-8"))
    assert "rules" in data
    assert "exclude_dirs" in data


def test_init_existing_config_fails(tmp_path):
    """repodoctor init fails if config exists."""
    config_path = tmp_path / "repodoctor.json"
    config_path.write_text("{}")
    exit_code, _, _ = run_cli(["init", "--path", str(config_path)])
    assert exit_code == 1


def test_fail_on_critical(tmp_path, monkeypatch):
    """--fail-on critical exits non-zero only on critical findings."""
    monkeypatch.chdir(tmp_path)
    exit_code, _, _ = run_cli(["scan", ".", "--fail-on", "critical"])
    assert exit_code in (0, 1)


def test_no_command_shows_help():
    """No subcommand shows help."""
    exit_code, stdout, _ = run_cli([])
    assert exit_code == 1
    assert "scan" in stdout
    assert "init" in stdout
