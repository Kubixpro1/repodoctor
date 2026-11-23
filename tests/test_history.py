"""Tests for historical health tracking."""

from __future__ import annotations

from pathlib import Path

from repodoctor.history import HistoryStore, build_summary, compare
from repodoctor.rules import Finding, ScanReport, Severity

STRIPE_TEST_SECRET = "sk_" + "live_" + "1234567890abcdef1234567890"


def _make_report(target: Path, score: int) -> ScanReport:
    report = ScanReport(target=target)
    report.all_findings.append(
        Finding(
            rule_id="secrets",
            title="Possible exposed API Key",
            description="A potential api key was detected.",
            severity=Severity.HIGH,
            file_path=target / "config.py",
            line_number=1,
        )
    )
    # Adjust score via findings is complex; tests compare summaries directly.
    return report


def test_history_store_save_and_load(tmp_path):
    store = HistoryStore(tmp_path)
    assert store.enabled()
    summary = build_summary(_make_report(tmp_path, 80))
    timestamp = store.save(summary)
    assert timestamp is not None
    assert (tmp_path / ".repodoctor" / "history" / f"{timestamp}.json").is_file()


def test_history_does_not_store_source_or_secrets(tmp_path):
    store = HistoryStore(tmp_path)
    report = _make_report(tmp_path, 80)
    report.all_findings[0].metadata = {
        "secret_type": "Stripe API Key",
        "line": STRIPE_TEST_SECRET,
    }
    summary = build_summary(report)
    store.save(summary)
    saved = (tmp_path / ".repodoctor" / "history").glob("*.json")
    content = next(saved).read_text()
    assert "sk_live_1234567890" not in content


def test_compare_detects_new_and_resolved():
    previous = {
        "health_score": 80,
        "findings": [
            {"rule_id": "a", "title": "Old Issue", "file": "x.py", "line": 1},
        ],
        "dependency_inventory": {"dependency_count": 3, "missing_lockfiles": []},
    }
    current = {
        "health_score": 70,
        "findings": [
            {"rule_id": "b", "title": "New Issue", "file": "y.py", "line": 2},
        ],
        "dependency_inventory": {"dependency_count": 5, "missing_lockfiles": []},
    }
    comp = compare(previous, current)
    assert comp["score_delta"] == -10
    assert comp["previous_score"] == 80
    assert comp["current_score"] == 70
    assert comp["trend"] == "declining"
    assert comp["new_count"] == 1
    assert comp["new_findings"][0]["title"] == "New Issue"
    assert comp["resolved_count"] == 1
    assert comp["resolved_findings"][0]["title"] == "Old Issue"


def test_compare_stable_trend():
    previous = {"health_score": 80, "findings": [], "dependency_inventory": {}}
    current = {"health_score": 80, "findings": [], "dependency_inventory": {}}
    comp = compare(previous, current)
    assert comp["trend"] == "stable"
    assert comp["score_delta"] == 0


def test_compare_improving_trend():
    previous = {"health_score": 70, "findings": [], "dependency_inventory": {}}
    current = {"health_score": 90, "findings": [], "dependency_inventory": {}}
    comp = compare(previous, current)
    assert comp["trend"] == "improving"
    assert comp["score_delta"] == 20
