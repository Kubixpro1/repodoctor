"""Scanner for license validation."""

from __future__ import annotations

from pathlib import Path

from repodoctor.rules import RuleResult
from repodoctor.scanners.base import ScannerBase, Severity
from repodoctor.utils import read_file_safely

# SPDX identifiers for common OSI-approved licenses.
OSI_APPROVED_LICENSES: set[str] = {
    "MIT",
    "Apache-2.0",
    "Apache-2",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "BSD-4-Clause",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "ISC",
    "MPL-2.0",
    "Unlicense",
    "0BSD",
}

# Common license file headers / names we can detect by content.
LICENSE_PATTERNS: dict[str, list[str]] = {
    "MIT": ["the MIT License", "MIT License", "Permission is hereby granted, free of charge"],
    "Apache-2.0": ["Apache License", "Version 2.0, January 2004"],
    "BSD-3-Clause": ["Redistribution and use in source and binary forms", "BSD License"],
    "BSD-2-Clause": ["Redistribution and use in source and binary forms", "BSD 2-Clause"],
    "GPL-3.0": ["GNU GENERAL PUBLIC LICENSE", "Version 3"],
    "GPL-2.0": ["GNU GENERAL PUBLIC LICENSE", "Version 2"],
    "ISC": ["ISC License"],
    "MPL-2.0": ["Mozilla Public License", "Version 2.0"],
}


class LicenseScanner(ScannerBase):
    """Validates the presence and recognizability of a LICENSE file."""

    rule_id = "license"
    rule_name = "License"

    def _scan(self, root: Path) -> RuleResult:  # noqa: ARG002
        result = RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            enabled=True,
            passed=True,
        )

        license_file = root / "LICENSE"
        if not license_file.is_file():
            # GovernanceFilesScanner already flags missing LICENSE.
            result.passed = True
            return result

        content = read_file_safely(license_file) or ""
        content_upper = content.upper()

        detected = None
        for spdx_id, patterns in LICENSE_PATTERNS.items():
            if any(p.upper() in content_upper for p in patterns):
                detected = spdx_id
                break

        if detected is None:
            finding = self._finding(
                title="Unrecognized or non-standard LICENSE file",
                description=(
                    "A LICENSE file exists but its contents do not match a "
                    "commonly recognized OSI-approved license. This may create "
                    "legal uncertainty for downstream users."
                ),
                severity=Severity.MEDIUM,
                file_path=license_file,
                suggestion=(
                    "Use a standard OSI-approved license (MIT, Apache-2.0, "
                    "BSD-3-Clause, GPL-3.0, etc.) and include its full text."
                ),
                metadata={"detected": False},
            )
            result.findings.append(finding)
        else:
            if detected not in OSI_APPROVED_LICENSES:
                finding = self._finding(
                    title=f"License '{detected}' may not be OSI-approved",
                    description=(
                        f"The detected license ({detected}) is not in the list of "
                        "commonly recognized OSI-approved licenses."
                    ),
                    severity=Severity.LOW,
                    file_path=license_file,
                    suggestion="Consider using a widely adopted OSI-approved license.",
                    metadata={"detected": detected},
                )
                result.findings.append(finding)

        result.passed = len(result.findings) == 0
        return result
