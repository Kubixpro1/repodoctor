"""Run an end-to-end demonstration against a temporary repository.

The sample repository intentionally contains common maintenance and security
problems. It is created in a temporary directory and removed after the scan.
"""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from repodoctor.cli import main as repodoctor_main


def create_demo_repository(root: Path) -> None:
    """Create an intentionally unhealthy repository for the demonstration."""
    (root / "README.md").write_text(
        "# Example application\n\nA deliberately incomplete demo repository.\n",
        encoding="utf-8",
    )
    (root / "pyproject.toml").write_text(
        '[project]\nname = "demo-application"\nversion = "0.1.0"\n',
        encoding="utf-8",
    )

    stripe_key = "sk_" + "live_" + "1234567890abcdef1234567890"
    (root / "settings.py").write_text(
        f'STRIPE_API_KEY = "{stripe_key}"\n',
        encoding="utf-8",
    )


def main() -> int:
    """Run RepoDoctor against the temporary demonstration repository."""
    print("RepoDoctor demo: scanning an intentionally unhealthy repository.\n")

    with TemporaryDirectory(prefix="repodoctor-demo-") as directory:
        demo_root = Path(directory)
        create_demo_repository(demo_root)
        scan_exit_code = repodoctor_main(
            ["scan", str(demo_root), "--offline", "--no-history", "--fail-on", "critical"]
        )

    print(
        "\nDemo complete. A non-zero scan result is expected because the sample "
        f"contains a critical finding (exit code: {scan_exit_code})."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
