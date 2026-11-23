"""Shared utilities for repodoctor.

File traversal uses the secure implementation in
:mod:`repodoctor.filesystem` so that symlinks never allow directory traversal
outside the scan root and unreadable files are handled gracefully.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from pathlib import Path

from repodoctor.filesystem import (
    iter_files_secure,
    resolve_safely,
)


def iter_files(
    root: Path,
    patterns: Iterable[str] | None = None,
    ignore_dirs: Iterable[str] | None = None,
    ignore_files: Iterable[str] | None = None,
) -> Iterator[Path]:
    """Yield files under *root*, optionally filtered by glob patterns.

    This is a thin wrapper around :func:`repodoctor.filesystem.iter_files_secure`
    that never follows symlinks, preventing directory traversal outside the
    scan root.

    Args:
        root: Directory to scan.
        patterns: Optional list of glob patterns to include (e.g. ``["*.py", "*.md"]``).
        ignore_dirs: Directory names to skip (e.g. ``[".git", "node_modules"]``).
        ignore_files: File name globs to skip (e.g. ``["*.lock", "*.pyc"]``).

    Yields:
        :class:`pathlib.Path` objects for matching files.
    """
    yield from iter_files_secure(
        root,
        ignore_dirs=ignore_dirs,
        ignore_files=ignore_files,
        include_patterns=patterns,
        follow_symlinks=False,
    )


def symlink_escapes_root(link_path: Path, root: Path) -> bool:
    """Return True if the symlink at *link_path* points outside *root*."""
    from repodoctor.filesystem import _symlink_escapes_root

    return _symlink_escapes_root(link_path, root)


def read_file_safely(path: Path) -> str | None:
    """Read a file as text, returning ``None`` on any error.

    This avoids crashes on binary files, permission errors, or encoding issues.
    """
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return None


def file_exists(path: Path) -> bool:
    """Return True if *path* exists and is a regular file."""
    try:
        return path.is_file()
    except OSError:
        return False


def dir_exists(path: Path) -> bool:
    """Return True if *path* exists and is a directory."""
    try:
        return path.is_dir()
    except OSError:
        return False


def normalize_severity(severity: str) -> str:
    """Normalize a severity string to one of: info, low, medium, high, critical."""
    severity = severity.strip().lower()
    valid = {"info", "low", "medium", "high", "critical"}
    return severity if severity in valid else "info"


def resolve_root(root: Path) -> Path:
    """Resolve *root* to an absolute path, falling back to the original."""
    return resolve_safely(root) or root
