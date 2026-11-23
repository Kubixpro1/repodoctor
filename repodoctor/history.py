"""Historical health tracking.

Stores previous scan summaries locally (under ``<repo>/.repodoctor/history/``)
so users can compare health scores across scans, detect newly introduced or
resolved problems, and track dependency changes.

Only scan *summaries* are stored — never source code, file contents, or
secret values.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, cast

from repodoctor.rules import ScanReport

HISTORY_DIR_NAME = ".repodoctor"
HISTORY_SUBDIR = "history"
MAX_HISTORY_ENTRIES = 50


class HistoryStore:
    """Manages on-disk historical scan summaries for a single repository."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.history_dir = root / HISTORY_DIR_NAME / HISTORY_SUBDIR

    def enabled(self) -> bool:
        """Return True if history tracking is possible for this repo."""
        try:
            self.history_dir.mkdir(parents=True, exist_ok=True)
            return True
        except OSError:
            return False

    def _target_id(self) -> str:
        """A stable, non-sensitive identifier for the scan target."""
        return hashlib.sha256(str(self.root.resolve()).encode()).hexdigest()[:16]

    def _entry_path(self, timestamp: str) -> Path:
        return self.history_dir / f"{timestamp}.json"

    def _list_entries(self) -> list[Path]:
        if not self.history_dir.is_dir():
            return []
        try:
            return sorted(self.history_dir.glob("*.json"))
        except OSError:
            return []

    def save(self, summary: dict[str, Any]) -> str | None:
        """Save a scan summary and return the entry timestamp, or None on failure."""
        if not self.enabled():
            return None
        from datetime import datetime, timezone

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        entry = dict(summary)
        entry["timestamp"] = timestamp
        entry["target_id"] = self._target_id()
        try:
            self._entry_path(timestamp).write_text(json.dumps(entry, indent=2), encoding="utf-8")
        except OSError:
            return None
        self._prune()
        return timestamp

    def _prune(self) -> None:
        """Keep only the most recent MAX_HISTORY_ENTRIES entries."""
        entries = self._list_entries()
        if len(entries) > MAX_HISTORY_ENTRIES:
            for old in entries[: len(entries) - MAX_HISTORY_ENTRIES]:
                try:
                    old.unlink()
                except OSError:
                    pass

    def load_previous(self) -> dict[str, Any] | None:
        """Load the most recent previous summary (excluding the current one)."""
        entries = self._list_entries()
        if len(entries) < 2:
            return None
        try:
            return cast("dict[str, Any]", json.loads(entries[-2].read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            return None

    def load_all(self) -> list[dict[str, Any]]:
        """Load all historical summaries, newest first."""
        entries = self._list_entries()
        summaries: list[dict[str, Any]] = []
        for path in reversed(entries):
            try:
                summaries.append(json.loads(path.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError):
                continue
        return summaries


def build_summary(report: ScanReport, inventory: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build a secret-free summary dict from a :class:`~repodoctor.rules.ScanReport`.

    The summary contains only aggregate data and rule-level metadata — no
    file contents or secret values.
    """
    findings_summary = []
    for f in report.all_findings:
        findings_summary.append(
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity.value,
                "file": str(f.file_path) if f.file_path else None,
                "line": f.line_number,
                "confidence": f.confidence,
            }
        )

    return {
        "health_score": report.health_score(),
        "total_findings": report.total_findings,
        "findings_by_severity": {
            "critical": report.critical_count,
            "high": report.high_count,
            "medium": report.medium_count,
            "low": report.low_count,
            "info": report.info_count,
        },
        "rules": [
            {
                "rule_id": r.rule_id,
                "rule_name": r.rule_name,
                "enabled": r.enabled,
                "passed": r.passed,
                "finding_count": r.finding_count,
            }
            for r in report.rules
        ],
        "findings": findings_summary,
        "dependency_inventory": inventory or {},
    }


def compare(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Compare a previous summary with the current one.

    Returns a dict with score delta, newly introduced findings, resolved
    findings, and dependency changes.
    """
    prev_findings = _finding_keys(previous.get("findings", []))
    curr_findings = _finding_keys(current.get("findings", []))

    new_findings = [f for f in current.get("findings", []) if _key(f) not in prev_findings]
    resolved_findings = [f for f in previous.get("findings", []) if _key(f) not in curr_findings]

    prev_score = previous.get("health_score", 0)
    curr_score = current.get("health_score", 0)

    dep_changes = _dependency_changes(
        previous.get("dependency_inventory", {}),
        current.get("dependency_inventory", {}),
    )

    return {
        "score_delta": curr_score - prev_score,
        "previous_score": prev_score,
        "current_score": curr_score,
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "new_count": len(new_findings),
        "resolved_count": len(resolved_findings),
        "dependency_changes": dep_changes,
        "trend": (
            "improving"
            if curr_score > prev_score
            else "declining"
            if curr_score < prev_score
            else "stable"
        ),
    }


def _key(f: dict) -> tuple:
    return (
        f.get("rule_id"),
        f.get("title"),
        f.get("file"),
        f.get("line"),
    )


def _finding_keys(findings: list[dict]) -> set:
    return {_key(f) for f in findings}


def _dependency_changes(prev: dict, curr: dict) -> dict[str, Any]:
    prev_count = prev.get("dependency_count", 0)
    curr_count = curr.get("dependency_count", 0)
    return {
        "previous_count": prev_count,
        "current_count": curr_count,
        "change": curr_count - prev_count,
        "new_missing_lockfiles": [
            m
            for m in curr.get("missing_lockfiles", [])
            if m not in prev.get("missing_lockfiles", [])
        ],
        "resolved_missing_lockfiles": [
            m
            for m in prev.get("missing_lockfiles", [])
            if m not in curr.get("missing_lockfiles", [])
        ],
    }
