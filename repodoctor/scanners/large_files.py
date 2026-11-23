"""Scanner for large files and accidentally committed build artifacts."""

from __future__ import annotations

from pathlib import Path

from repodoctor.rules import RuleResult
from repodoctor.scanners.base import ScannerBase, Severity
from repodoctor.utils import iter_files

# Files larger than this (bytes) are flagged.
LARGE_FILE_THRESHOLD = 50 * 1024 * 1024  # 50 MB

# Common build artifact / dependency directory names that should not be committed.
BUILD_ARTIFACT_DIRS: set[str] = {
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    ".env",
    "dist",
    "build",
    "target",
    "bin",
    "obj",
    ".gradle",
    ".m2",
    ".cache",
    ".next",
    ".nuxt",
    ".svelte-kit",
}

# File extensions commonly associated with build artifacts or binaries.
ARTIFACT_EXTENSIONS: set[str] = {
    ".o",
    ".obj",
    ".a",
    ".so",
    ".dll",
    ".dylib",
    ".exe",
    ".bin",
    ".pyc",
    ".pyo",
    ".pyd",
    ".class",
    ".jar",
    ".war",
    ".ear",
    ".zip",
    ".tar.gz",
    ".tgz",
    ".whl",
    ".gem",
    ".nupkg",
    ".snupkg",
    ".vsix",
    ".dmg",
    ".iso",
    ".img",
    ".parquet",
    ".pkl",
    ".pickle",
    ".npy",
    ".npz",
    ".h5",
    ".onnx",
    ".pb",
    ".pt",
    ".pth",
    ".ckpt",
    ".safetensors",
    ".model",
}


class LargeFilesScanner(ScannerBase):
    """Detects unusually large files and committed build artifacts."""

    rule_id = "large_files"
    rule_name = "Large Files & Artifacts"

    def _scan(self, root: Path) -> RuleResult:  # noqa: ARG002
        from repodoctor.rules import RuleResult

        result = RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            enabled=True,
            passed=True,
        )

        for file_path in iter_files(
            root,
            ignore_dirs=self.config.exclude_dirs,
            ignore_files=self.config.exclude_files,
        ):
            try:
                size = file_path.stat().st_size
            except OSError:
                continue

            # Large file check.
            if size > LARGE_FILE_THRESHOLD:
                finding = self._finding(
                    title=f"Large file: {file_path.name} ({size / (1024 * 1024):.1f} MB)",
                    description=(
                        f"The file {file_path} is {size / (1024 * 1024):.1f} MB, which exceeds "
                        f"the {LARGE_FILE_THRESHOLD / (1024 * 1024):.0f} MB threshold. Large files "
                        "bloat the repository and slow down clones."
                    ),
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    suggestion=(
                        "Move large files to Git LFS, a release asset page, or an external "
                        "storage service. Remove them from Git history if already committed."
                    ),
                    metadata={"size_bytes": size, "size_mb": round(size / (1024 * 1024), 1)},
                )
                result.findings.append(finding)
                continue

            # Build artifact check by directory name.
            parts = file_path.relative_to(root).parts
            if any(part in BUILD_ARTIFACT_DIRS for part in parts):
                finding = self._finding(
                    title=f"Committed build artifact: {file_path}",
                    description=(
                        f"A file inside a build-artifact directory ({parts[0] if parts else ''}) "
                        "was found. These directories should be gitignored."
                    ),
                    severity=Severity.LOW,
                    file_path=file_path,
                    suggestion=(
                        f"Add '{parts[0] if parts else ''}' to .gitignore and remove it from tracking."
                    ),
                    metadata={"artifact_dir": parts[0] if parts else ""},
                )
                result.findings.append(finding)
                continue

            # Build artifact check by extension.
            if file_path.suffix.lower() in ARTIFACT_EXTENSIONS:
                finding = self._finding(
                    title=f"Possible build artifact: {file_path.name}",
                    description=(
                        f"The file {file_path} has a compiled/binary extension "
                        f"({file_path.suffix}) that is typically a build artifact."
                    ),
                    severity=Severity.LOW,
                    file_path=file_path,
                    suggestion=(
                        f"Add '*.{file_path.suffix.lstrip('.')}' to .gitignore if it is a build output."
                    ),
                    metadata={"extension": file_path.suffix.lower()},
                )
                result.findings.append(finding)

        result.passed = len(result.findings) == 0
        return result
