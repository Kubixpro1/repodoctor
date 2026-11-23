"""Base class for repodoctor reporters."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from repodoctor.rules import ScanReport


class ReporterBase:
    """Base class for report formatters."""

    format_name: str = ""

    def format(self, report: ScanReport, history_comparison: dict[str, Any] | None = None) -> str:
        """Format a :class:`ScanReport` into a string."""
        raise NotImplementedError

    def write(
        self,
        report: ScanReport,
        path: Path | None = None,
        history_comparison: dict[str, Any] | None = None,
    ) -> None:
        """Write the formatted report to *path* or stdout.

        All output is passed through secret redaction before being written so
        that no secret value can leak through any report format.
        """
        output = self.format(report, history_comparison=history_comparison)
        from repodoctor.redaction import REDACTED, _looks_like_secret

        # Final safety net: redact any secret-like tokens in the rendered output.
        lines = output.splitlines()
        redacted_lines = [REDACTED if _looks_like_secret(line) else line for line in lines]
        output = "\n".join(redacted_lines)
        if output and not output.endswith("\n"):
            output += "\n"

        if path is None:
            print(output, end="")
        else:
            path.write_text(output, encoding="utf-8")
