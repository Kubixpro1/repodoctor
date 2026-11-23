"""Scanner for dependency intelligence.

Performs local dependency analysis (inventory, outdated detection, license
identification, missing lockfiles, version conflicts) and optionally runs
external vulnerability audit tools when network access is permitted.

Network-based checks are **opt-in** and skipped entirely when the scanner is
configured for offline mode (``config.is_offline()``). No repository contents
or secrets are ever transmitted.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from repodoctor.dependency_parser import (
    Dependency,
    DependencyInventory,
    find_version_conflicts,
    parse_all_manifests,
)
from repodoctor.rules import RuleResult, Severity
from repodoctor.scanners.base import ScannerBase

# Audit tools are opt-in and network-dependent. They are only invoked when
# offline mode is disabled.
_AUDIT_TOOL_NOTICE = (
    "Network-based vulnerability check skipped (offline mode or tool not "
    "available). Install the relevant audit tool and run without --offline to "
    "enable vulnerability detection."
)


class DependenciesScanner(ScannerBase):
    """Analyzes dependency manifests and lockfiles for health issues."""

    rule_id = "dependencies"
    rule_name = "Dependencies"

    def _scan(self, root: Path) -> RuleResult:  # noqa: ARG002
        result = RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            enabled=True,
            passed=True,
        )

        inventory: DependencyInventory = parse_all_manifests(root)
        result.metadata["dependency_inventory"] = _inventory_to_dict(inventory)

        # --- No manifest at all -------------------------------------------
        if not inventory.manifest_files and not inventory.lock_files:
            finding = self._finding(
                title="No dependency manifest found",
                description=(
                    "No recognized dependency manifest (requirements.txt, "
                    "package.json, Cargo.toml, go.mod, etc.) was detected. If "
                    "this project has dependencies, they should be declared "
                    "explicitly."
                ),
                severity=Severity.INFO,
                suggestion=(
                    "Add a dependency manifest appropriate for your language "
                    "and lock it with a lockfile."
                ),
            )
            result.findings.append(finding)

        # --- Missing lockfiles --------------------------------------------
        if self.config.dependency_check_enabled("missing_lockfile"):
            for missing in inventory.missing_lockfiles:
                finding = self._finding(
                    title=f"Missing lockfile for {Path(missing).name}",
                    description=(
                        f"The manifest {missing} has no corresponding lockfile. "
                        "Without a lockfile, builds are not reproducible and "
                        "dependency versions can drift unexpectedly."
                    ),
                    severity=Severity.MEDIUM,
                    file_path=Path(missing),
                    suggestion=(
                        "Generate a lockfile (e.g. ``pip freeze > "
                        "requirements.txt``, ``npm install``, "
                        "``cargo build`` or ``poetry lock``) and commit it."
                    ),
                )
                result.findings.append(finding)

        # --- Dependency inventory / version conflicts ---------------------
        if self.config.dependency_check_enabled("conflicts"):
            conflicts = find_version_conflicts(inventory)
            for conflict in conflicts:
                versions = ", ".join(conflict["versions"])
                finding = self._finding(
                    title=f"Dependency version conflict: {conflict['package']}",
                    description=(
                        f"Package '{conflict['package']}' is declared or "
                        f"resolved with multiple versions ({versions}), which "
                        "can lead to unpredictable builds and hard-to-debug "
                        "runtime issues."
                    ),
                    severity=Severity.HIGH,
                    suggestion=(
                        f"Pin '{conflict['package']}' to a single version "
                        "across all manifests and lockfiles."
                    ),
                    metadata={
                        "package": conflict["package"],
                        "versions": conflict["versions"],
                        "sources": conflict["sources"],
                    },
                )
                result.findings.append(finding)

        # --- Outdated dependency detection (local only) -------------------
        if self.config.dependency_check_enabled("outdated"):
            outdated = self._detect_outdated_locally(inventory)
            for dep, locked_version in outdated:
                finding = self._finding(
                    title=f"Outdated dependency: {dep.name} {dep.version}",
                    description=(
                        f"Dependency '{dep.name}' is declared at {dep.version} "
                        f"but the lockfile resolves it to {locked_version}. "
                        "Consider reviewing whether an upgrade is appropriate."
                    ),
                    severity=Severity.LOW,
                    file_path=dep.source_file,
                    suggestion=(
                        f"Review '{dep.name}' and update to the latest "
                        "compatible version, then regenerate the lockfile."
                    ),
                    metadata={
                        "package": dep.name,
                        "declared_version": dep.version,
                        "locked_version": locked_version,
                    },
                )
                result.findings.append(finding)

        # --- License identification ---------------------------------------
        if self.config.dependency_check_enabled("licenses"):
            unlicensed = [
                d
                for d in inventory.declared_only()
                if d.license is None and d.source_file is not None
            ]
            # Report only a sample to avoid noisy output.
            for dep in unlicensed[:10]:
                finding = self._finding(
                    title=f"Unidentified license: {dep.name}",
                    description=(
                        f"License for dependency '{dep.name}' could not be "
                        "identified from its manifest. Unknown licenses create "
                        "legal uncertainty for downstream users."
                    ),
                    severity=Severity.LOW,
                    file_path=dep.source_file,
                    suggestion=(
                        f"Add license metadata for '{dep.name}' or verify its license manually."
                    ),
                    metadata={"package": dep.name},
                )
                result.findings.append(finding)

        # --- Vulnerability detection (network, opt-in) --------------------
        if not self.config.is_offline():
            if self.config.dependency_check_enabled("vulnerabilities"):
                self._run_audit_tools(root, result, inventory)
        else:
            # Record that vulnerability scanning was skipped; not a failure.
            result.metadata["vulnerability_scan"] = "skipped_offline"

        result.passed = (
            result.critical_count == 0
            and result.high_count == 0
            and not inventory.missing_lockfiles
        )
        return result

    # ------------------------------------------------------------------
    # Local outdated detection
    # ------------------------------------------------------------------

    def _detect_outdated_locally(
        self, inventory: DependencyInventory
    ) -> list[tuple[Dependency, str]]:
        """Find declared versions that differ from lockfile resolutions.

        Compares declared versions against resolved lockfile versions for the
        same package. This is purely local and never contacts a registry.
        """
        resolved: dict[str, str] = {}
        for dep in inventory.resolved_only():
            if dep.version:
                # Keep the first resolved version per package.
                resolved.setdefault(dep.name.lower(), dep.version)

        outdated: list[tuple[Dependency, str]] = []
        for dep in inventory.declared_only():
            if not dep.version:
                continue
            locked = resolved.get(dep.name.lower())
            if locked and _versions_differ(dep.version, locked):
                outdated.append((dep, locked))
        return outdated

    # ---------------------------------------------------------------------------
    # Audit tool integration (network, opt-in)
    # ---------------------------------------------------------------------------

    def _run_audit_tools(
        self,
        root: Path,
        result: RuleResult,
        inventory: DependencyInventory,
    ) -> None:
        """Run available dependency audit tools and record findings.

        Skipped entirely when offline mode is enabled.
        """
        if self.config.is_offline():
            return

        has_python = any(
            p.name
            in ("requirements.txt", "requirements.in", "pyproject.toml", "Pipfile", "poetry.lock")
            for p in inventory.manifest_files + inventory.lock_files
        )
        has_node = any(
            p.name in ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml")
            for p in inventory.manifest_files + inventory.lock_files
        )
        has_rust = any(
            p.name in ("Cargo.toml", "Cargo.lock")
            for p in inventory.manifest_files + inventory.lock_files
        )

        if has_python:
            self._try_run(
                result,
                ["pip-audit", "--format=json"],
                cwd=root,
                label="pip-audit",
                severity_map={"high": Severity.HIGH, "critical": Severity.CRITICAL},
                audit_format="pip-audit",
            )
            self._try_run(
                result,
                ["safety", "check", "--json"],
                cwd=root,
                label="safety",
                severity_map={"high": Severity.HIGH, "critical": Severity.CRITICAL},
                audit_format="safety",
            )
        if has_node:
            self._try_run(
                result,
                ["npm", "audit", "--json"],
                cwd=root,
                label="npm audit",
                severity_map={"high": Severity.HIGH, "critical": Severity.CRITICAL},
                audit_format="npm",
            )
        if has_rust:
            self._try_run(
                result,
                ["cargo", "audit", "--format=json"],
                cwd=root,
                label="cargo audit",
                severity_map={"high": Severity.HIGH, "critical": Severity.CRITICAL},
                audit_format="cargo",
            )

    def _try_run(
        self,
        result: RuleResult,
        cmd: list[str],
        cwd: Path,
        label: str,
        severity_map: dict[str, Severity],
        audit_format: str,
    ) -> None:
        """Attempt to run a command and parse JSON output for findings."""
        try:
            proc = subprocess.run(  # noqa: S603 - intentional audit tool invocation
                cmd,
                cwd=str(cwd),
                capture_output=True,
                text=True,
                timeout=60,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            # Tool not installed or timed out — not an error for our scan.
            return

        output = proc.stdout.strip()
        if not output:
            return

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return

        self._parse_audit_output(data, result, label, severity_map, audit_format)

    def _parse_audit_output(
        self,
        data: dict | list,
        result: RuleResult,
        label: str,
        severity_map: dict[str, Severity],
        audit_format: str,
    ) -> None:
        """Parse audit tool output into findings.

        Handles pip-audit, safety, npm audit and cargo audit formats.
        Vulnerability identifiers and package metadata are reported; no
        repository content is transmitted anywhere.
        """
        vulnerabilities: list[dict] = []

        if isinstance(data, dict):
            if "advisories" in data:
                advisories = data["advisories"]
                if isinstance(advisories, dict):
                    vulnerabilities.extend(advisories.values())
                elif isinstance(advisories, list):
                    vulnerabilities.extend(advisories)
            if "vulnerabilities" in data:
                vulns = data["vulnerabilities"]
                if isinstance(vulns, list):
                    vulnerabilities.extend(vulns)
        elif isinstance(data, list):
            vulnerabilities.extend(data)

        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue

            package = (
                vuln.get("package_name")
                or vuln.get("package")
                or (vuln.get("package") or {}).get("name")
                if isinstance(vuln.get("package"), dict)
                else None
            )
            if not package:
                package = vuln.get("module_name") or vuln.get("id") or "unknown"

            version = vuln.get("version") or "unknown"
            advisory_id = (
                vuln.get("id")
                or vuln.get("advisory_id")
                or vuln.get("vulnerability_id")
                or vuln.get("alias")
                or ""
            )

            title = (
                vuln.get("title")
                or vuln.get("advisory")
                or advisory_id
                or (f"Vulnerable dependency via {label}")
            )
            description = (
                vuln.get("description")
                or vuln.get("advisory")
                or (f"A vulnerability was reported in {package} {version}.")
            )

            severity_str = str(vuln.get("severity", "info")).lower()
            severity = severity_map.get(severity_str, Severity.INFO)

            # npm audit severity may be nested under "severity"; pip-audit uses
            # "severity" too, but cargo audit uses "advisory.severity".
            if severity == Severity.INFO and "advisory" in vuln:
                adv = vuln["advisory"]
                if isinstance(adv, dict):
                    severity = severity_map.get(
                        str(adv.get("severity", "info")).lower(), Severity.INFO
                    )

            finding = self._finding(
                title=f"{title} ({package} {version})",
                description=description,
                severity=severity,
                suggestion=(
                    f"Update {package} to a patched version. See advisory "
                    f"{advisory_id} if available."
                ),
                metadata={
                    "tool": label,
                    "package": package,
                    "version": version,
                    "advisory_id": advisory_id,
                    "audit_format": audit_format,
                },
            )
            result.findings.append(finding)


def _versions_differ(declared: str, locked: str) -> bool:
    """Return True if two version strings are not equal after normalization."""
    return _normalize_version(declared) != _normalize_version(locked)


def _normalize_version(version: str) -> str:
    """Normalize a version for comparison (strip operators and whitespace)."""
    return re.sub(r"^(==|>=|<=|>|<|~=|!=)\s*", "", version or "").strip()


def _inventory_to_dict(inventory: DependencyInventory) -> dict:
    """Serialize a DependencyInventory for metadata output."""
    return {
        "manifest_files": [str(p) for p in inventory.manifest_files],
        "lock_files": [str(p) for p in inventory.lock_files],
        "missing_lockfiles": list(inventory.missing_lockfiles),
        "dependency_count": len(inventory.dependencies),
        "declared_count": len(inventory.declared_only()),
        "transitive_count": len(inventory.resolved_only()),
        "errors": list(inventory.errors),
    }
