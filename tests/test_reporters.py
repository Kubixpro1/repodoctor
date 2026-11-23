"""Tests for reporter modules."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from repodoctor.reporters.json import JSONReporter
from repodoctor.reporters.markdown import MarkdownReporter
from repodoctor.reporters.sarif import SARIFReporter
from repodoctor.reporters.text import TextReporter
from repodoctor.rules import Finding, ScanReport, Severity


@pytest.fixture
def report_with_findings(tmp_path: Path) -> ScanReport:
    """Report with a mix of findings."""
    report = ScanReport(target=tmp_path)
    report.all_findings.append(
        Finding(
            rule_id="governance_files",
            title="Missing LICENSE file",
            description="No LICENSE file found.",
            severity=Severity.HIGH,
            file_path=tmp_path / "LICENSE",
            suggestion="Add a LICENSE file.",
        )
    )
    report.all_findings.append(
        Finding(
            rule_id="secrets",
            title="Possible exposed API Key",
            description="A potential api key was detected.",
            severity=Severity.CRITICAL,
            file_path=tmp_path / "config.py",
            line_number=42,
            suggestion="Move to environment variable.",
        )
    )
    report.all_findings.append(
        Finding(
            rule_id="governance_files",
            title="Consider adding a CODEOWNERS file",
            description="A CODEOWNERS file would clarify review responsibilities.",
            severity=Severity.INFO,
            file_path=tmp_path / "CODEOWNERS",
            suggestion="Add a CODEOWNERS file to designate reviewers.",
        )
    )
    return report


def test_text_reporter(report_with_findings):
    """Text reporter produces readable output."""
    output = TextReporter().format(report_with_findings)
    assert "repodoctor" in output
    assert "Health Score" in output
    assert "Missing LICENSE file" in output
    assert "Possible exposed API Key" in output
    assert "💡" in output  # suggestions


def test_text_reporter_no_findings(tmp_path):
    """Text reporter with no findings."""
    report = ScanReport(target=tmp_path)
    output = TextReporter().format(report)
    assert "No issues found" in output


def test_json_reporter(report_with_findings):
    """JSON reporter produces valid JSON."""
    output = JSONReporter().format(report_with_findings)
    data = json.loads(output)
    assert "health_score" in data
    assert "total_findings" in data
    assert data["total_findings"] == 3
    assert "rules" in data
    assert data["findings_by_severity"]["critical"] == 1
    assert data["findings_by_severity"]["high"] == 1
    assert data["findings_by_severity"]["info"] == 1


def test_json_reporter_schema_stable(report_with_findings):
    """JSON output has stable keys."""
    output = JSONReporter().format(report_with_findings)
    data = json.loads(output)
    required_keys = {
        "target",
        "health_score",
        "total_rules",
        "passed_rules",
        "failed_rules",
        "total_findings",
        "findings_by_severity",
        "rules",
    }
    assert required_keys.issubset(set(data.keys()))


def test_sarif_reporter(report_with_findings):
    """SARIF reporter produces valid SARIF."""
    output = SARIFReporter().format(report_with_findings)
    data = json.loads(output)
    assert data["version"] == "2.1.0"
    assert "$schema" in data
    assert len(data["runs"]) == 1
    assert "results" in data["runs"][0]
    assert len(data["runs"][0]["results"]) == 3


def test_sarif_reporter_levels(report_with_findings):
    """SARIF maps severities correctly."""
    output = SARIFReporter().format(report_with_findings)
    data = json.loads(output)
    results = data["runs"][0]["results"]
    levels = {r["level"] for r in results}
    assert "error" in levels  # critical + high
    assert "note" in levels  # info


def test_markdown_reporter(report_with_findings):
    """Markdown reporter produces markdown."""
    output = MarkdownReporter().format(report_with_findings)
    assert "# repodoctor" in output
    assert "Health Score" in output
    assert "Missing LICENSE file" in output


def test_reporter_write_to_file(tmp_path, report_with_findings):
    """Reporter can write to a file."""
    out_path = tmp_path / "report.json"
    JSONReporter().write(report_with_findings, out_path)
    assert out_path.is_file()
    data = json.loads(out_path.read_text(encoding="utf-8"))
    assert data["total_findings"] == 3


def test_text_reporter_orphan_findings(tmp_path):
    """Text reporter handles findings not in report.rules (orphan findings)."""
    report = ScanReport(target=tmp_path)
    # Add a finding without a corresponding RuleResult in report.rules
    report.all_findings.append(
        Finding(
            rule_id="orphan_rule",
            title="Orphan Finding",
            description="A finding with no rule result entry.",
            severity=Severity.MEDIUM,
            suggestion="Add the rule result.",
        )
    )
    output = TextReporter().format(report)
    assert "Orphan Finding" in output
    assert "orphan_rule" in output


def test_markdown_reporter_orphan_findings(tmp_path):
    """Markdown reporter handles findings not in report.rules."""
    report = ScanReport(target=tmp_path)
    report.all_findings.append(
        Finding(
            rule_id="orphan_rule",
            title="Orphan Finding",
            description="A finding with no rule result entry.",
            severity=Severity.INFO,
            suggestion="Add the rule result.",
        )
    )
    output = MarkdownReporter().format(report)
    assert "Orphan Finding" in output
    assert "orphan_rule" in output


def test_sarif_reporter_orphan_findings(tmp_path):
    """SARIF reporter includes orphan findings in results and rules."""
    report = ScanReport(target=tmp_path)
    report.all_findings.append(
        Finding(
            rule_id="orphan_rule",
            title="Orphan Finding",
            description="A finding with no rule result entry.",
            severity=Severity.HIGH,
            suggestion="Add the rule result.",
        )
    )
    output = SARIFReporter().format(report)
    data = json.loads(output)
    assert len(data["runs"][0]["results"]) == 1
    assert data["runs"][0]["results"][0]["ruleId"] == "orphan_rule"
    assert data["runs"][0]["results"][0]["level"] == "error"
    # The orphan rule should also appear in the rules section
    rule_ids = {r["id"] for r in data["runs"][0]["tool"]["driver"]["rules"]}
    assert "orphan_rule" in rule_ids
