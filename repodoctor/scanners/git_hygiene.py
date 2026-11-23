"""Scanner for Git repository hygiene."""

from __future__ import annotations

import subprocess
from pathlib import Path

from repodoctor.rules import RuleResult
from repodoctor.scanners.base import ScannerBase, Severity


class GitHygieneScanner(ScannerBase):
    """Checks Git repository hygiene: commits, branches, tags, history."""

    rule_id = "git_hygiene"
    rule_name = "Git Hygiene"

    def _run_git(self, root: Path, args: list[str]) -> str | None:
        """Run a git command and return stdout, or None on failure."""
        try:
            proc = subprocess.run(  # noqa: S603 - intentional git command
                ["git"] + args,
                cwd=str(root),
                capture_output=True,
                text=True,
                timeout=15,
            )
            if proc.returncode != 0:
                return None
            return proc.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return None

    def _scan(self, root: Path) -> RuleResult:  # noqa: ARG002
        from repodoctor.rules import RuleResult

        result = RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            enabled=True,
            passed=True,
        )

        # Is this even a git repository?
        if not (root / ".git").is_dir():
            finding = self._finding(
                title="Not a Git repository",
                description=(
                    "The target directory is not a Git repository. Version control "
                    "is fundamental to open-source collaboration."
                ),
                severity=Severity.HIGH,
                suggestion="Initialize a Git repository (`git init`) and push to a remote host.",
            )
            result.findings.append(finding)
            result.passed = False
            return result

        # Check for commits.
        log = self._run_git(root, ["log", "--oneline", "-1"])
        if not log:
            finding = self._finding(
                title="No commits in repository",
                description=(
                    "The Git repository has no commits. A project with no history "
                    "cannot be evaluated for maintenance activity."
                ),
                severity=Severity.HIGH,
                suggestion="Make an initial commit with the project's core files.",
            )
            result.findings.append(finding)

        # Check for remote.
        remotes = self._run_git(root, ["remote"])
        if not remotes:
            finding = self._finding(
                title="No Git remote configured",
                description=(
                    "No remote repository is configured. Open-source projects "
                    "benefit from a public remote for collaboration and discovery."
                ),
                severity=Severity.MEDIUM,
                suggestion="Add a remote (e.g. `git remote add origin <url>`) and push.",
            )
            result.findings.append(finding)

        # Check for tags/releases.
        tags = self._run_git(root, ["tag"])
        if not tags:
            finding = self._finding(
                title="No release tags",
                description=(
                    "No Git tags were found. Tags mark releases and help users "
                    "identify stable versions."
                ),
                severity=Severity.LOW,
                suggestion="Create a tag for your first release (e.g. `git tag v0.1.0`).",
            )
            result.findings.append(finding)

        result.passed = len(result.findings) == 0
        return result
