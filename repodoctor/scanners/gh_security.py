"""GitHub security analysis scanner.

Inspects a repository's GitHub Actions workflows and repository-level files
for common security gaps:

* Workflow permissions (missing or overly permissive ``permissions``).
* Unpinned third-party actions (``uses`` without a pinned ``@vX`` ref).
* Dangerous ``pull_request_target`` usage (write permissions + untrusted input).
* Missing automated dependency updates (Dependabot config).
* Missing security policy (``SECURITY.md``).
* Branch protection — reported as ``unknown`` when it cannot be verified
  locally (never assumed to be disabled or enabled).

This scanner is **read-only and local**: it never calls the GitHub API, so
branch protection and other server-side settings are reported as unknown
rather than assumed.
"""

from __future__ import annotations

import re
from pathlib import Path

from repodoctor.rules import RuleResult, Severity
from repodoctor.scanners.base import ScannerBase

WORKFLOW_DIR = Path(".github") / "workflows"
DEPENDABOT_CONFIG = Path(".github") / "dependabot.yml"
SECURITY_POLICY = Path("SECURITY.md")


class GitHubSecurityScanner(ScannerBase):
    """Analyzes GitHub-specific security configuration."""

    rule_id = "github_security"
    rule_name = "GitHub Security"

    # Actions considered third-party (not under the ``actions/`` org).
    _THIRD_PARTY_PREFIXES = ("docker://",)

    def _scan(self, root: Path) -> RuleResult:  # noqa: ARG002
        result = RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            enabled=True,
            passed=True,
        )

        workflow_dir = root / WORKFLOW_DIR
        workflow_files: list[Path] = []
        if workflow_dir.is_dir():
            try:
                workflow_files = sorted(
                    p
                    for p in workflow_dir.iterdir()
                    if p.suffix.lower() in (".yml", ".yaml") and p.is_file()
                )
            except OSError:
                workflow_files = []

        if not workflow_files:
            # No GitHub Actions workflows to analyze — informational only.
            finding = self._finding(
                title="No GitHub Actions workflows found",
                description=(
                    "No workflow files were found under .github/workflows/. "
                    "GitHub Actions security cannot be assessed without "
                    "workflow configuration."
                ),
                severity=Severity.INFO,
                suggestion=(
                    "Add GitHub Actions workflows to automate testing, building, and deployment."
                ),
            )
            result.findings.append(finding)

        for wf in workflow_files:
            self._analyze_workflow(root, wf, result)

        # --- Dependabot (automated dependency updates) -------------------
        if not (root / DEPENDABOT_CONFIG).is_file():
            finding = self._finding(
                title="Missing automated dependency updates (Dependabot)",
                description=(
                    "No Dependabot configuration was found at "
                    ".github/dependabot.yml. Automated dependency updates "
                    "help keep dependencies patched against known "
                    "vulnerabilities."
                ),
                severity=Severity.MEDIUM,
                suggestion=(
                    "Add .github/dependabot.yml to enable automated "
                    "dependency version and security updates."
                ),
            )
            result.findings.append(finding)

        # --- Security policy --------------------------------------------
        if not (root / SECURITY_POLICY).is_file():
            # GovernanceFilesScanner also covers SECURITY.md; keep this for
            # GitHub-specific context.
            finding = self._finding(
                title="Missing GitHub security policy (SECURITY.md)",
                description=(
                    "No SECURITY.md was found. GitHub displays a 'Report a "
                    "vulnerability' button only when a security policy "
                    "exists, which guides researchers to report privately."
                ),
                severity=Severity.MEDIUM,
                file_path=root / SECURITY_POLICY,
                suggestion=(
                    "Add SECURITY.md with supported versions and vulnerability "
                    "reporting instructions."
                ),
            )
            result.findings.append(finding)

        # --- Branch protection ------------------------------------------
        # Cannot be determined from a local checkout. Report unknown, never
        # assume it is disabled.
        finding = self._finding(
            title="Branch protection configuration: unknown",
            description=(
                "Branch protection rules are a server-side GitHub setting and "
                "cannot be verified from a local repository clone. They are "
                "reported as unknown rather than assumed to be disabled or "
                "enabled."
            ),
            severity=Severity.INFO,
            suggestion=(
                "Review branch protection rules in GitHub repository settings "
                "(e.g. require pull request reviews, require status checks, "
                "restrict pushes to main)."
            ),
            metadata={"source": "local_scan", "verifiable": False},
        )
        result.findings.append(finding)

        result.passed = result.critical_count == 0 and result.high_count == 0
        return result

    # ------------------------------------------------------------------
    # Workflow analysis
    # ------------------------------------------------------------------

    def _analyze_workflow(self, root: Path, wf: Path, result: RuleResult) -> None:
        try:
            text = wf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        self._check_permissions(wf, text, result)
        self._check_unpinned_actions(wf, text, result)
        self._check_pull_request_target(wf, text, result)

    def _check_permissions(self, wf: Path, text: str, result: RuleResult) -> None:
        """Flag workflows missing a ``permissions`` block or using write-all."""
        has_permissions = bool(re.search(r"^\s*permissions\s*:", text, re.MULTILINE))
        has_write_all = bool(
            re.search(
                r"permissions:\s*\n\s*write-all\s*:\s*true", text, re.IGNORECASE | re.MULTILINE
            )
        )

        if not has_permissions:
            finding = self._finding(
                title=f"Workflow '{wf.name}' missing permissions",
                description=(
                    f"The workflow {wf.name} does not define a ``permissions`` "
                    "block. Jobs inherit the default (often permissive) "
                    "GITHUB_TOKEN, which follows the principle of least "
                    "privilege poorly."
                ),
                severity=Severity.MEDIUM,
                file_path=wf,
                suggestion=(
                    "Add a top-level ``permissions`` block (e.g. "
                    "``contents: read``) and per-job permissions following "
                    "least privilege."
                ),
            )
            result.findings.append(finding)

        if has_write_all:
            finding = self._finding(
                title=f"Workflow '{wf.name}' uses write-all permissions",
                description=(
                    f"The workflow {wf.name} grants ``write-all`` permission, "
                    "giving the GITHUB_TOKEN write access to all repository "
                    "scopes. This is a privilege escalation risk if the "
                    "workflow processes untrusted input."
                ),
                severity=Severity.HIGH,
                file_path=wf,
                suggestion=(
                    "Replace ``write-all: true`` with explicit, minimal permissions for each job."
                ),
            )
            result.findings.append(finding)

    def _check_unpinned_actions(self, wf: Path, text: str, result: RuleResult) -> None:
        """Flag third-party actions not pinned to a specific version."""
        # Match ``uses: owner/repo`` and ``uses: owner/repo@ref`` lines.
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line.startswith("uses:"):
                continue
            _, _, ref = line.partition(":")
            ref = ref.strip().strip('"').strip("'")
            if not ref:
                continue
            # Docker container actions are opaque; flag as unpinned if no digest.
            if ref.startswith("docker://"):
                if "@sha256:" not in ref:
                    self._report_unpinned(wf, raw_line, ref, result)
                continue
            # Local actions (./.github/actions/...) are first-party.
            if ref.startswith("./") or ref.startswith("."):
                continue
            parts = ref.split("/")
            if len(parts) < 2:
                continue
            org_repo = f"{parts[0]}/{parts[1]}"
            # First-party actions/* are maintained by GitHub — still recommend
            # pinning but lower severity.
            is_third_party = not org_repo.startswith("actions/")
            if "@" not in ref:
                self._report_unpinned(wf, raw_line, ref, result, is_third_party)
            else:
                _, _, version_ref = ref.rpartition("@")
                if not self._is_pinned(version_ref):
                    self._report_unpinned(wf, raw_line, ref, result, is_third_party)

    @staticmethod
    def _is_pinned(version_ref: str) -> bool:
        """Return True if a version ref is an immutable pin (sha or major tag)."""
        if version_ref.startswith("sha256:"):
            return True
        if re.fullmatch(r"v\d+", version_ref):
            return True  # e.g. v4 (major pin)
        return False  # branch names, "main", "master", "develop", etc.

    def _report_unpinned(
        self,
        wf: Path,
        raw_line: str,
        ref: str,
        result: RuleResult,
        is_third_party: bool = True,
    ) -> None:
        severity = Severity.HIGH if is_third_party else Severity.MEDIUM
        finding = self._finding(
            title=f"Unpinned action in '{wf.name}': {ref}",
            description=(
                f"The workflow {wf.name} uses action '{ref}' without an "
                "immutable version pin (commit SHA or major version tag). "
                "Unpinned actions can be modified by their author, introducing "
                "supply-chain risk."
            ),
            severity=severity,
            file_path=wf,
            suggestion=(
                f"Pin '{ref}' to a specific version (e.g. "
                f"``{ref.split('@')[0]}@v4`` or a commit SHA)."
            ),
            metadata={"action": ref, "third_party": is_third_party},
            line_number=self._line_number(text_of=raw_line, wf=wf),
        )
        result.findings.append(finding)

    @staticmethod
    def _line_number(text_of: str, wf: Path) -> int | None:
        """Best-effort line number for a raw line within its workflow file."""
        try:
            content = wf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        for idx, line in enumerate(content.splitlines(), start=1):
            if line.strip() == text_of.strip():
                return idx
        return None

    def _check_pull_request_target(self, wf: Path, text: str, result: RuleResult) -> None:
        """Flag dangerous pull_request_target with write permissions."""
        has_pr_target = bool(re.search(r"pull_request_target", text))
        if not has_pr_target:
            return

        has_write_all = bool(re.search(r"write-all\s*:\s*true", text, re.IGNORECASE))
        has_job_permissions_write = bool(
            re.search(
                r"permissions:\s*\n\s*(contents|pull-requests|issues|packages|id-token|actions|checks|deployments|discussions|security-events):\s*write",
                text,
                re.IGNORECASE | re.MULTILINE,
            )
        )

        if has_write_all or has_job_permissions_write:
            finding = self._finding(
                title=f"Dangerous pull_request_target in '{wf.name}'",
                description=(
                    f"The workflow {wf.name} runs on ``pull_request_target`` "
                    "with write permissions. ``pull_request_target`` runs in "
                    "the context of the base branch with a token that can have "
                    "write access, so untrusted input from the PR (e.g. "
                    "``github.event.pull_request.head.sha``) can lead to "
                    "secret exfiltration or repository modification."
                ),
                severity=Severity.CRITICAL,
                file_path=wf,
                suggestion=(
                    "Use ``pull_request`` instead of ``pull_request_target`` "
                    "when possible. If ``pull_request_target`` is required, "
                    "avoid write permissions, never run untrusted scripts from "
                    "the PR head, and use ``workflow run`` artifacts carefully."
                ),
            )
            result.findings.append(finding)
