"""Tests for CLI additions: offline, exclude, quiet, verbose, fail-on."""

from __future__ import annotations

import json

from repodoctor.cli import main

STRIPE_TEST_SECRET = "sk_" + "live_" + "1234567890abcdef1234567890"


def run_cli(argv):
    import sys
    from io import StringIO

    old_stdout, old_stderr = sys.stdout, sys.stderr
    sys.stdout = StringIO()
    sys.stderr = StringIO()
    try:
        code = main(argv)
        out = sys.stdout.getvalue()
        err = sys.stderr.getvalue()
    finally:
        sys.stdout, sys.stderr = old_stdout, old_stderr
    return code, out, err


def test_offline_flag(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    code, out, err = run_cli(["scan", ".", "--offline"])
    assert code in (0, 1)


def test_exclude_flag(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    code, out, err = run_cli(["scan", ".", "--exclude", "tests/"])
    assert code in (0, 1)


def test_exclude_flag_actually_excludes(tmp_path, monkeypatch):
    """--exclude must prevent matching files from being scanned."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "secrets").mkdir()
    (tmp_path / "secrets" / "leak.py").write_text(f'KEY = "{STRIPE_TEST_SECRET}"\n')
    (tmp_path / "safe.py").write_text("x = 1\n")

    import json

    # Without exclusion, the secret is detected.
    code1, out1, _ = run_cli(["scan", ".", "--format", "json"])
    data1 = json.loads(out1)
    secret_findings_1 = [
        f for r in data1["rules"] for f in r["findings"] if r["rule_id"] == "secrets"
    ]
    assert len(secret_findings_1) > 0

    # With exclusion, it is not.
    code2, out2, _ = run_cli(["scan", ".", "--exclude", "secrets/", "--format", "json"])
    data2 = json.loads(out2)
    secret_findings_2 = [
        f for r in data2["rules"] for f in r["findings"] if r["rule_id"] == "secrets"
    ]
    assert len(secret_findings_2) == 0


def test_quiet_flag(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    code, out, err = run_cli(["--quiet", "scan", "."])
    assert code in (0, 1)


def test_verbose_flag(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    code, out, err = run_cli(["--verbose", "scan", "."])
    assert code in (0, 1)


def test_fail_on_high(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    code, _, _ = run_cli(["scan", ".", "--fail-on", "high"])
    assert code in (0, 1)


def test_version_command():
    code, out, _ = run_cli(["version"])
    assert code == 0
    assert "repodoctor" in out


def test_list_rules_includes_new_scanners():
    code, out, _ = run_cli(["--list-rules"])
    assert code == 0
    assert "github_security" in out
    assert "extended_governance" in out


def test_json_output_valid_and_redacted(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # Create a file with a secret-like line so redaction is exercised.
    (tmp_path / "config.py").write_text(f'API_KEY = "{STRIPE_TEST_SECRET}"\n')
    code, out, _ = run_cli(["scan", ".", "--format", "json"])
    data = json.loads(out)
    assert "health_score" in data
    # No raw secret in JSON output.
    assert STRIPE_TEST_SECRET not in out


def test_sarif_output_valid(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    code, out, _ = run_cli(["scan", ".", "--format", "sarif"])
    data = json.loads(out)
    assert data["version"] == "2.1.0"
    assert "$schema" in data
    assert "runs" in data
    # Artifact paths should be repository-relative, not absolute.
    for run in data["runs"]:
        for result in run.get("results", []):
            for loc in result.get("locations", []):
                uri = loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
                assert not uri.startswith("/"), uri
                assert ":\\" not in uri, uri
