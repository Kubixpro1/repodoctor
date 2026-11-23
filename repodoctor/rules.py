"""Data models for repodoctor findings and rules.

The models are designed to be safe by default: :class:`Finding` never stores
raw secret values, and :meth:`Finding.to_dict` scrubs any metadata that looks
like a secret before serialization.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from repodoctor.redaction import scrub_metadata


class Severity(str, Enum):
    """Finding severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Numeric weights used to compute the repository health score.
SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.INFO: 1,
    Severity.LOW: 3,
    Severity.MEDIUM: 7,
    Severity.HIGH: 15,
    Severity.CRITICAL: 25,
}

MAX_HEALTH_SCORE = 100


@dataclass
class Finding:
    """A single finding produced by a scanner rule.

    Findings are *safe by default*: secret values must never be stored in
    ``metadata`` or any string field. Use :func:`repodoctor.redaction.redact`
    and :func:`repodoctor.redaction.sanitize_line` when a diagnostic needs to
    reference a line that may contain a secret.
    """

    rule_id: str
    title: str
    description: str
    severity: Severity
    file_path: Path | None = None
    line_number: int | None = None
    suggestion: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    # --- Smart remediation fields -------------------------------------
    explanation: str | None = None
    """Plain-language explanation of what the issue is."""
    why_it_matters: str | None = None
    """Why the issue matters for repository health or security."""
    recommended_fix: str | None = None
    """Concrete recommended fix (defaults to ``suggestion`` when absent)."""
    example_fix: str | None = None
    """Example remediation, e.g. a code snippet or config snippet."""
    confidence: float = 1.0
    """Scanner confidence in this finding (0.0-1.0), used to surface likely
    false positives."""
    redacted: bool = False
    """True if the finding was derived from material that was redacted."""

    def to_dict(self) -> dict[str, Any]:
        """Serialize the finding to a dictionary, scrubbing any secrets.

        Raw secret values are never emitted. Any metadata value that looks
        like a secret is replaced with ``"[REDACTED]"``.
        """
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "file_path": str(self.file_path) if self.file_path else None,
            "line_number": self.line_number,
            "suggestion": self.suggestion,
            "recommended_fix": self.recommended_fix or self.suggestion,
            "explanation": self.explanation,
            "why_it_matters": self.why_it_matters,
            "example_fix": self.example_fix,
            "confidence": self.confidence,
            "redacted": self.redacted,
            "metadata": scrub_metadata(self.metadata or {}),
        }

    @property
    def fix(self) -> str | None:
        """Backward-compatible alias for the recommended fix."""
        return self.recommended_fix or self.suggestion


@dataclass
class RuleResult:
    """Result of running a single rule."""

    rule_id: str
    rule_name: str
    enabled: bool
    passed: bool
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    """Optional scanner-specific metadata (e.g. dependency inventory)."""

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "enabled": self.enabled,
            "passed": self.passed,
            "finding_count": self.finding_count,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "info_count": self.info_count,
            "metadata": scrub_metadata(self.metadata or {}),
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
        }


@dataclass
class ScanReport:
    """Complete scan report for a repository."""

    target: Path
    rules: list[RuleResult] = field(default_factory=list)
    all_findings: list[Finding] = field(default_factory=list)

    @property
    def total_rules(self) -> int:
        return len(self.rules)

    @property
    def passed_rules(self) -> int:
        return sum(1 for r in self.rules if r.passed)

    @property
    def failed_rules(self) -> int:
        return sum(1 for r in self.rules if not r.passed)

    @property
    def total_findings(self) -> int:
        return len(self.all_findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.all_findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.all_findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.all_findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.all_findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.all_findings if f.severity == Severity.INFO)

    def health_score(self) -> int:
        """Compute a repository health score from 0 to 100.

        The score starts at 100 and is reduced by weighted findings.
        """
        penalty = 0
        for finding in self.all_findings:
            penalty += SEVERITY_WEIGHTS.get(finding.severity, 1)

        score = MAX_HEALTH_SCORE - penalty
        return max(0, min(MAX_HEALTH_SCORE, score))

    def to_dict(self) -> dict[str, Any]:
        # Build a complete set of rules, including any rule_ids found in
        # all_findings that don't have a corresponding RuleResult entry.
        rules_by_id: dict[str, RuleResult] = {r.rule_id: r for r in self.rules}
        for finding in self.all_findings:
            if finding.rule_id not in rules_by_id:
                rules_by_id[finding.rule_id] = RuleResult(
                    rule_id=finding.rule_id,
                    rule_name=finding.rule_id,
                    enabled=True,
                    passed=False,
                    findings=[finding],
                )

        ordered_rules = list(rules_by_id.values())

        return {
            "target": str(self.target),
            "health_score": self.health_score(),
            "total_rules": len(ordered_rules),
            "passed_rules": sum(1 for r in ordered_rules if r.passed),
            "failed_rules": sum(1 for r in ordered_rules if not r.passed),
            "total_findings": self.total_findings,
            "findings_by_severity": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
            },
            "rules": [r.to_dict() for r in ordered_rules],
        }
