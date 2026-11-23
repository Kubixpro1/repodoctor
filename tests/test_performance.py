"""Performance benchmarks for large repositories.

These tests ensure file traversal and scanning remain efficient on large
repositories without sacrificing correctness.
"""

from __future__ import annotations

import time

from repodoctor.config import RepodoctorConfig
from repodoctor.scanners.secrets import SecretsScanner
from repodoctor.utils import iter_files


def test_file_traversal_performance(tmp_path):
    """Traversing many files should complete quickly."""
    # Create 2000 small files across 40 directories.
    for i in range(40):
        d = tmp_path / f"dir_{i}"
        d.mkdir()
        for j in range(50):
            (d / f"file_{j}.py").write_text("x = 1\n")

    start = time.monotonic()
    count = sum(1 for _ in iter_files(tmp_path))
    elapsed = time.monotonic() - start

    assert count == 2000
    assert elapsed < 5.0, f"traversal took {elapsed:.2f}s"


def test_secret_scan_performance(tmp_path):
    """Scanning many files should complete quickly."""
    for i in range(200):
        (tmp_path / f"file_{i}.py").write_text("x = 1\n# no secrets here\n")

    scanner = SecretsScanner(RepodoctorConfig())
    start = time.monotonic()
    result = scanner.scan(tmp_path)
    elapsed = time.monotonic() - start

    assert result.passed
    assert elapsed < 10.0, f"scan took {elapsed:.2f}s"
