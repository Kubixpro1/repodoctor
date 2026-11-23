"""Base class for all repodoctor scanners."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from repodoctor.config import RepodoctorConfig
from repodoctor.rules import Finding, RuleResult, Severity


class ScannerBase:
    """Base class for repository scanners.

    Subclasses should implement :meth:`scan` and set ``rule_id`` and
    ``rule_name`` class attributes.
    """

    rule_id: str = ""
    rule_name: str = ""

    def __init__(self, config: RepodoctorConfig) -> None:
        self.config = config

    def is_enabled(self) -> bool:
        """Return True if this scanner's rule is enabled in config."""
        return self.config.is_rule_enabled(self.rule_id)

    def scan(self, root: Path) -> RuleResult:
        """Scan *root* and return a :class:`RuleResult`.

        The base implementation handles the enabled/disabled check and
        delegates to :meth:`_scan` for the actual work.
        """
        result = RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            enabled=self.is_enabled(),
            passed=False,
        )

        if not self.is_enabled():
            result.passed = True
            return result

        try:
            result = self._scan(root)
        except Exception as exc:  # pragma: no cover - defensive
            result.error = f"Scanner error: {exc!s}"
            result.passed = False

        return result

    def _scan(self, root: Path) -> RuleResult:  # noqa: ARG002
        """Actual scanning logic. Must be implemented by subclasses."""
        raise NotImplementedError

    def _finding(
        self,
        title: str,
        description: str,
        severity: Severity = Severity.INFO,
        file_path: Path | None = None,
        line_number: int | None = None,
        suggestion: str | None = None,
        explanation: str | None = None,
        why_it_matters: str | None = None,
        recommended_fix: str | None = None,
        example_fix: str | None = None,
        confidence: float = 1.0,
        metadata: dict[str, Any] | None = None,
        redacted: bool = False,
    ) -> Finding:
        """Helper to create a :class:`Finding` linked to this scanner."""
        return Finding(
            rule_id=self.rule_id,
            title=title,
            description=description,
            severity=severity,
            file_path=file_path,
            line_number=line_number,
            suggestion=suggestion,
            explanation=explanation,
            why_it_matters=why_it_matters,
            recommended_fix=recommended_fix or suggestion,
            example_fix=example_fix,
            confidence=confidence,
            metadata=metadata or {},
            redacted=redacted,
        )
