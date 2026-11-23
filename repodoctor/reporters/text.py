"""Human-readable text reporter."""

from __future__ import annotations

from typing import Any

from repodoctor.reporters.base import ReporterBase
from repodoctor.rules import ScanReport, Severity

SEVERITY_ICONS: dict[Severity, str] = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


class TextReporter(ReporterBase):
    """Plain-text, human-friendly report."""

    format_name = "text"

    def format(self, report: ScanReport, history_comparison: dict[str, Any] | None = None) -> str:  # noqa: C901
        lines: list[str] = []

        target = report.target
        if not target.is_absolute():
            target = target.resolve()

        lines.append("=" * 60)
        lines.append("repodoctor — Repository Health Report")
        lines.append("=" * 60)
        lines.append("")
        lines.append(f"Target:      {target}")
        lines.append(f"Health Score: {report.health_score()}/100")
        lines.append(f"Rules:       {report.passed_rules}/{report.total_rules} passed")
        lines.append(f"Findings:    {report.total_findings} total")
        lines.append("")
        lines.append("Findings by severity:")
        lines.append(f"  🔴 Critical: {report.critical_count}")
        lines.append(f"  🟠 High:     {report.high_count}")
        lines.append(f"  🟡 Medium:   {report.medium_count}")
        lines.append(f"  🔵 Low:      {report.low_count}")
        lines.append(f"  ⚪ Info:     {report.info_count}")
        lines.append("")

        if report.total_findings == 0:
            lines.append("✅ No issues found. Your repository looks healthy!")
            lines.append("")

        # Group findings by rule_id for display.
        findings_by_rule: dict[str, list] = {}
        for finding in report.all_findings:
            findings_by_rule.setdefault(finding.rule_id, []).append(finding)

        # Build a lookup of rule names.
        rule_names: dict[str, str] = {}
        for rule in report.rules:
            rule_names[rule.rule_id] = rule.rule_name
        for finding in report.all_findings:
            if finding.rule_id not in rule_names:
                rule_names[finding.rule_id] = finding.rule_id

        lines.append("-" * 60)
        lines.append("Detailed Findings")
        lines.append("-" * 60)
        lines.append("")

        for rule_id, findings in findings_by_rule.items():
            rule_name = rule_names.get(rule_id, rule_id)
            lines.append(f"## {rule_name} ({rule_id})")

            rule_errors: dict[str, str] = {}
            for rule in report.rules:
                if rule.rule_id == rule_id and rule.error:
                    rule_errors[rule_id] = rule.error

            if rule_errors:
                lines.append(f"  ⚠️  Scanner error: {rule_errors[rule_id]}")

            if not findings:
                lines.append("  ✅ Passed — no issues.")
            else:
                for finding in findings:
                    icon = SEVERITY_ICONS.get(finding.severity, "⚪")
                    lines.append(f"  {icon} [{finding.severity.value.upper()}] {finding.title}")
                    if finding.description:
                        lines.append(f"      {finding.description}")
                    if finding.explanation:
                        lines.append(f"      📖 {finding.explanation}")
                    if finding.why_it_matters:
                        lines.append(f"      ❗ {finding.why_it_matters}")
                    if finding.file_path:
                        lines.append(f"      File: {finding.file_path}")
                    if finding.line_number:
                        lines.append(f"      Line: {finding.line_number}")
                    if finding.recommended_fix:
                        lines.append(f"      💡 Fix: {finding.recommended_fix}")
                    elif finding.suggestion:
                        lines.append(f"      💡 Fix: {finding.suggestion}")
                    if finding.example_fix:
                        lines.append(f"      🛠️  Example: {finding.example_fix}")
                    lines.append("")
            lines.append("")

        lines.append("-" * 60)
        lines.append("Recommendations")
        lines.append("-" * 60)

        seen_suggestions: set[str] = set()
        for finding in report.all_findings:
            fix = finding.recommended_fix or finding.suggestion
            if fix and fix not in seen_suggestions:
                seen_suggestions.add(fix)
                lines.append(f"  • {fix}")

        lines.append("")

        if history_comparison:
            lines.append("-" * 60)
            lines.append("Historical Health Tracking")
            lines.append("-" * 60)
            lines.append(f"Previous score: {history_comparison['previous_score']}/100")
            lines.append(f"Current score:  {history_comparison['current_score']}/100")
            lines.append(
                f"Trend: {history_comparison['trend']} "
                f"(delta {history_comparison['score_delta']:+d})"
            )
            if history_comparison["new_count"]:
                lines.append(f"New findings: {history_comparison['new_count']}")
            if history_comparison["resolved_count"]:
                lines.append(f"Resolved findings: {history_comparison['resolved_count']}")
            lines.append("")

        lines.append("=" * 60)
        return "\n".join(lines)
