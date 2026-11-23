"""JSON reporter for machine-readable output."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from repodoctor.reporters.base import ReporterBase
from repodoctor.rules import ScanReport


def _relative_path(path: Path | None, root: Path) -> str | None:
    """Return a repository-relative path for *path*, or None."""
    if path is None:
        return None
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        # Path is outside the root — return it as-is but sanitized.
        return str(path)


class JSONReporter(ReporterBase):
    """JSON-format report suitable for CI pipelines and tooling."""

    format_name = "json"

    def format(self, report: ScanReport, history_comparison: dict[str, Any] | None = None) -> str:
        data = report.to_dict()
        # Use repository-relative paths for findings.
        root = report.target
        for rule in data.get("rules", []):
            for finding in rule.get("findings", []):
                fp = finding.get("file_path")
                if fp:
                    finding["file_path"] = _relative_path(Path(fp), root)

        if history_comparison is not None:
            data["history"] = history_comparison

        return json.dumps(data, indent=2, sort_keys=False) + "\n"
