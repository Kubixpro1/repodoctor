"""Markdown reporter for documentation and GitHub-friendly output."""

from __future__ import annotations

from typing import Any

from repodoctor.reporters.base import ReporterBase
from repodoctor.rules import ScanReport, Severity

SEVERITY_BADGES: dict[Severity, str] = {
    Severity.CRITICAL: "🔴 Critical",
    Severity.HIGH: "🟠 High",
    Severity.MEDIUM: "🟡 Medium",
    Severity.LOW: "🔵 Low",
    Severity.INFO: "⚪ Info",
}


class MarkdownReporter(ReporterBase):
    """Markdown-format report, suitable for documentation, issue comments."""

    format_name = "markdown"

    def format(self, report: ScanReport, history_comparison: dict[str, Any] | None = None) -> str:
        lines: list[str] = []

        target = report.target
        if not target.is_absolute():
            target = target.resolve()

        lines.append("# repodoctor — Repository Health Report")
        lines.append("")
        lines.append(f"**Target:** `{target}`")
        lines.append(f"**Health Score:** {report.health_score()}/100")
        lines.append(f"**Rules:** {report.passed_rules}/{report.total_rules} passed")
        lines.append(f"**Findings:** {report.total_findings} total")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        lines.append(f"| 🔴 Critical | {report.critical_count} |")
        lines.append(f"| 🟠 High | {report.high_count} |")
        lines.append(f"| 🟡 Medium | {report.medium_count} |")
        lines.append(f"| 🔵 Low | {report.low_count} |")
        lines.append(f"| ⚪ Info | {report.info_count} |")
        lines.append("")

        if report.total_findings == 0:
            lines.append("✅ No issues found. Your repository looks healthy!")
            return "\n".join(lines)

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

        lines.append("## Findings")
        lines.append("")

        for rule_id, findings in findings_by_rule.items():
            rule_name = rule_names.get(rule_id, rule_id)
            lines.append(f"### {rule_name} (`{rule_id}`)")
            lines.append("")

            if not findings:
                lines.append("✅ Passed — no issues.")
                lines.append("")
                continue

            lines.append(
                "| Severity | Title | File | Line | Explanation | Why it matters | Recommended fix |"
            )
            lines.append(
                "|----------|-------|------|------|-------------|----------------|-----------------|"
            )
            for finding in findings:
                badge = SEVERITY_BADGES.get(finding.severity, "⚪ Info")
                file_str = f"`{finding.file_path}`" if finding.file_path else "—"
                line_str = str(finding.line_number) if finding.line_number else "—"
                explanation = (finding.explanation or "—").replace("|", "\\|")
                why_it_matters = (finding.why_it_matters or "—").replace("|", "\\|")
                fix = (finding.recommended_fix or finding.suggestion or "—").replace("|", "\\|")
                lines.append(
                    f"| {badge} | {finding.title} | {file_str} | {line_str} | "
                    f"{explanation} | {why_it_matters} | {fix} |"
                )
            lines.append("")

        lines.append("## Recommendations")
        lines.append("")

        seen: set[str] = set()
        for finding in report.all_findings:
            fix = finding.recommended_fix or finding.suggestion
            if fix and fix not in seen:
                seen.add(fix)
                lines.append(f"- {fix}")

        lines.append("")

        if history_comparison:
            lines.append("## Historical Health Tracking")
            lines.append("")
            lines.append(f"- Previous score: {history_comparison['previous_score']}/100")
            lines.append(f"- Current score: {history_comparison['current_score']}/100")
            lines.append(
                f"- Trend: {history_comparison['trend']} "
                f"(delta {history_comparison['score_delta']:+d})"
            )
            if history_comparison["new_count"]:
                lines.append(f"- New findings: {history_comparison['new_count']}")
            if history_comparison["resolved_count"]:
                lines.append(f"- Resolved findings: {history_comparison['resolved_count']}")
            lines.append("")

        return "\n".join(lines)
