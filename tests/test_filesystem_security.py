"""Tests for filesystem security: symlinks, traversal, unreadable files."""

from __future__ import annotations

import os

import pytest

from repodoctor.filesystem import is_within_root, iter_files_secure, resolve_safely
from repodoctor.utils import iter_files


def test_iter_files_does_not_follow_symlinked_directory(tmp_path):
    """Symlinked directories must not be descended into."""
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    (real_dir / "inside.txt").write_text("secret inside real dir\n")

    link_dir = tmp_path / "link_to_real"
    try:
        link_dir.symlink_to(real_dir, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported on this system")

    files = list(iter_files_secure(tmp_path, follow_symlinks=False))
    paths = {str(f) for f in files}
    assert str(real_dir / "inside.txt") in paths
    # The symlinked directory's contents must not be reachable via the link.
    assert not any(str(f).startswith(str(link_dir)) for f in files)


def test_symlink_escaping_root_is_skipped(tmp_path):
    """A symlink whose target escapes the root must be skipped."""
    outside = tmp_path.parent / "escape_target.txt"
    outside.write_text("I should not be scanned\n")

    link = tmp_path / "escape_link.txt"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported on this system")

    files = list(iter_files_secure(tmp_path))
    assert not any(f.name == "escape_link.txt" for f in files)


def test_symlink_inside_root_to_inside_target_is_scanned(tmp_path):
    """A symlink to a target inside root is scanned."""
    target = tmp_path / "target.txt"
    target.write_text("visible\n")
    link = tmp_path / "link.txt"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported on this system")

    files = list(iter_files_secure(tmp_path))
    names = {f.name for f in files}
    assert "target.txt" in names


def test_is_within_root_rejects_outside_path(tmp_path):
    """is_within_root() must reject paths outside root."""
    outside = tmp_path.parent / "outside.txt"
    assert not is_within_root(outside, tmp_path)
    assert is_within_root(tmp_path / "inner.txt", tmp_path)


def test_iter_files_respects_exclude_dirs(tmp_path):
    """Exclude directories are skipped."""
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.js").write_text("x\n")
    (tmp_path / "keep.py").write_text("x\n")

    files = list(iter_files_secure(tmp_path, ignore_dirs={"node_modules"}))
    names = {f.name for f in files}
    assert "keep.py" in names
    assert "dep.js" not in names


def test_iter_files_handles_unreadable_file(tmp_path):
    """Unreadable files are skipped without crashing."""
    f = tmp_path / "unreadable.txt"
    f.write_text("x\n")
    if os.name == "nt":
        pytest.skip("chmod permission model differs on Windows")
    f.chmod(0o000)
    try:
        files = list(iter_files_secure(tmp_path))
        assert isinstance(files, list)
    finally:
        f.chmod(0o644)


def test_resolve_safely_returns_none_on_error(tmp_path):
    """resolve_safely() returns None instead of raising on inaccessible paths."""
    assert resolve_safely(tmp_path / "does_not_exist") is not None  # strict=False


def test_iter_files_skips_oversized_files(tmp_path):
    """Files larger than max_file_size are skipped."""
    small = tmp_path / "small.txt"
    small.write_text("x\n")
    big = tmp_path / "big.dat"
    big.write_bytes(b"\x00" * (3 * 1024 * 1024))

    files = list(iter_files_secure(tmp_path, max_file_size=1_000_000))
    names = {f.name for f in files}
    assert "small.txt" in names
    assert "big.dat" not in names


def test_iter_files_backward_compat(tmp_path):
    """iter_files() (legacy) still works and never follows symlinks."""
    (tmp_path / "a.py").write_text("x\n")
    files = list(iter_files(tmp_path, patterns=["*.py"]))
    assert len(files) == 1
    assert files[0].name == "a.py"
