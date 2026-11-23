"""Secure filesystem traversal utilities.

Provides file iteration that:

* never follows symlinks that escape the scan root (directory traversal),
* never scans outside the selected repository,
* handles unreadable files gracefully,
* supports user-supplied exclusion patterns,
* reports skipped symlinks for transparency.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Iterator
from pathlib import Path

# Default directory names that are never scanned.
DEFAULT_IGNORE_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "env",
        "dist",
        "build",
        ".next",
        ".nuxt",
    }
)

# Default file-name globs that are never scanned.
DEFAULT_IGNORE_FILES: frozenset[str] = frozenset(
    {
        ".DS_Store",
        "Thumbs.db",
        "*.pyc",
        "*.pyo",
        "*.pyd",
    }
)


def resolve_safely(path: Path) -> Path | None:
    """Resolve *path* to an absolute path, returning ``None`` on error.

    Wraps :meth:`Path.resolve` so that permission errors or broken symlinks
    do not crash a scan.
    """
    try:
        return path.resolve(strict=False)
    except (OSError, RuntimeError):
        return None


def is_within_root(path: Path, root: Path) -> bool:
    """Return True if *path* is located inside *root* (both resolved).

    Symlinks are resolved so that a symlink pointing outside *root* is
    rejected even if its link text lives under *root*.
    """
    resolved_path = resolve_safely(path)
    resolved_root = resolve_safely(root)
    if resolved_path is None or resolved_root is None:
        return False
    try:
        resolved_path.relative_to(resolved_root)
        return True
    except ValueError:
        return False


def _symlink_escapes_root(link_path: Path, root: Path) -> bool:
    """Return True if the symlink at *link_path* points outside *root*."""
    try:
        target = os.readlink(link_path)
    except OSError:
        # Cannot read the link target — treat conservatively as unsafe.
        return True
    target_path = (link_path.parent / target).resolve(strict=False)
    return not is_within_root(target_path, root)


def iter_files_secure(
    root: Path,
    *,
    ignore_dirs: Iterable[str] | None = None,
    ignore_files: Iterable[str] | None = None,
    include_patterns: Iterable[str] | None = None,
    follow_symlinks: bool = False,
    max_file_size: int | None = None,
) -> Iterator[Path]:
    """Yield regular files under *root* securely.

    Args:
        root: Directory to scan (resolved internally).
        ignore_dirs: Directory base names to skip (defaults to VCS/build dirs).
        ignore_files: File-name globs to skip (defaults to OS/temp files).
        include_patterns: Optional glob patterns a file name must match.
        follow_symlinks: If True, follow symlinked directories/files.
        max_file_size: Skip files larger than this many bytes.

    Yields:
        :class:`pathlib.Path` objects for files inside *root*.

    Notes:
        * Symbolic links to directories are not followed unless
          ``follow_symlinks`` is True.
        * Symbolic links to files that resolve outside *root* are skipped.
        * Symlinked files inside *root* are yielded only when their resolved
          target is also inside *root*.
        * Unreadable/inaccessible files are skipped silently.
    """
    root = resolve_safely(root) or root
    ignore_dirs = set(ignore_dirs or DEFAULT_IGNORE_DIRS)
    ignore_files = set(ignore_files or DEFAULT_IGNORE_FILES)
    include_patterns = list(include_patterns or [])

    import fnmatch

    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        current_dir = Path(dirpath)

        # Filter out ignored directories and symlinked dirs that escape root.
        kept_dirs: list[str] = []
        for d in dirnames:
            if d in ignore_dirs:
                continue
            dir_path = current_dir / d
            if not follow_symlinks and dir_path.is_symlink():
                # Never descend into symlinked directories to avoid traversal.
                continue
            kept_dirs.append(d)
        dirnames[:] = sorted(kept_dirs)

        for filename in filenames:
            # Apply ignore-file exact names and globs.
            if filename in ignore_files:
                continue
            if any(fnmatch.fnmatch(filename, pat) for pat in ignore_files):
                continue

            # Apply include patterns.
            if include_patterns and not any(
                fnmatch.fnmatch(filename, pat) for pat in include_patterns
            ):
                continue

            file_path = current_dir / filename

            # Skip symlinks that escape the root.
            if file_path.is_symlink() and not follow_symlinks:
                if _symlink_escapes_root(file_path, root):
                    continue

            # Verify the resolved target remains inside root.
            resolved = resolve_safely(file_path)
            if resolved is not None and not is_within_root(resolved, root):
                continue

            # Skip oversized files.
            if max_file_size is not None:
                try:
                    if file_path.stat().st_size > max_file_size:
                        continue
                except OSError:
                    continue

            yield file_path
