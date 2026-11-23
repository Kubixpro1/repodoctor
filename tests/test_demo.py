"""End-to-end test for the public demonstration script."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_demo_script_runs_successfully() -> None:
    """The demo creates a temporary target and reports the expected finding."""
    project_root = Path(__file__).resolve().parents[1]
    demo_script = project_root / "examples" / "demo.py"

    result = subprocess.run(
        [sys.executable, str(demo_script)],
        cwd=project_root,
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "RepoDoctor demo" in result.stdout
    assert "Possible exposed Stripe API Key" in result.stdout
    assert "Demo complete" in result.stdout
