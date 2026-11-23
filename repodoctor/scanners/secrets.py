"""Scanner for exposed secrets and credentials in repository files.

Security properties
-------------------
* Secret values are **never** stored in finding metadata or emitted in any
  report format. Only the file, line number, and secret *type* are reported.
* Raw source lines are replaced with a redaction placeholder.
* Generic patterns are tuned to reduce false positives (e.g. ``projectId`` in
  Firebase config is public configuration, not a secret).
* Symlinks that escape the scan root are never scanned.
"""

from __future__ import annotations

import re
from pathlib import Path

from repodoctor.filesystem import iter_files_secure
from repodoctor.rules import RuleResult, Severity
from repodoctor.scanners.base import ScannerBase


class SecretsScanner(ScannerBase):
    """Scans files for hardcoded secrets, API keys, tokens, and credentials."""

    rule_id = "secrets"
    rule_name = "Secrets Detection"

    # (name, regex, severity, confidence)
    # Confidence reflects how likely a match is a real secret vs. a false
    # positive. High-confidence patterns match structured tokens (prefix +
    # entropy). Lower-confidence patterns match generic key=value assignments.
    SECRET_PATTERNS: list[tuple[str, str, Severity, float]] = [
        # --- High confidence: structured tokens with known prefixes ----------
        ("AWS Access Key ID", r"AKIA[0-9A-Z]{16}", Severity.CRITICAL, 0.99),
        (
            "AWS Secret Access Key",
            r"(?i)aws[_-]?secret[_-]?access[_-]?key[\"'\s:=]+[0-9a-zA-Z/+]{40}",
            Severity.CRITICAL,
            0.9,
        ),
        ("GitHub Personal Access Token", r"ghp_[0-9a-zA-Z]{36,}", Severity.CRITICAL, 0.99),
        ("GitHub OAuth App Token", r"gho_[0-9a-zA-Z]{36,}", Severity.CRITICAL, 0.99),
        ("GitHub Fine-grained Token", r"github_pat_[0-9a-zA-Z_]{60,}", Severity.CRITICAL, 0.99),
        ("GitHub App Token", r"ghu_[0-9a-zA-Z]{36,}", Severity.CRITICAL, 0.99),
        ("Slack Token", r"xox[baprs]-[0-9a-zA-Z-]{10,}", Severity.CRITICAL, 0.95),
        ("Stripe API Key", r"(sk|pk)_(live|test)_[0-9a-zA-Z]{24,}", Severity.CRITICAL, 0.97),
        ("Twilio API Key", r"SK[0-9a-fA-F]{32}", Severity.HIGH, 0.95),
        ("SendGrid API Key", r"SG\.[0-9a-zA-Z]{22}\.[0-9a-zA-Z\-_]{43,}", Severity.HIGH, 0.95),
        ("Twilio Account SID", r"AC[0-9a-fA-F]{32}", Severity.HIGH, 0.9),
        ("Mailgun API Key", r"key-[0-9a-zA-Z]{32}", Severity.HIGH, 0.9),
        ("Mailchimp API Key", r"[0-9a-fA-F]{32}-us[0-9]{1,2}", Severity.HIGH, 0.85),
        ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}", Severity.HIGH, 0.9),
        ("Google Cloud API Key", r"AIza[0-9A-Za-z\-_]{35}", Severity.HIGH, 0.9),
        (
            "Azure Subscription Key",
            r"[0-9a-fA-F]{32}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            Severity.HIGH,
            0.85,
        ),
        (
            "Heroku API Key",
            r"(?i)heroku[_-]?api[_-]?key[\"'\s:=]+[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            Severity.HIGH,
            0.9,
        ),
        (
            "Private Key",
            r"-----BEGIN " + r"[A-Z ]+PRIVATE KEY-----",
            Severity.CRITICAL,
            0.99,
        ),
        (
            "PGP Private Key",
            r"-----BEGIN " + r"PGP PRIVATE KEY BLOCK-----",
            Severity.CRITICAL,
            0.99,
        ),
        (
            "SSH Private Key",
            r"-----BEGIN " + r"(OPENSSH |)PRIVATE KEY-----",
            Severity.CRITICAL,
            0.99,
        ),
        (
            "Docker Hub / Registry Password",
            r"(?i)(docker|registry)[_-]?(password|passwd|token)[\"'\s:=]+\S{8,}",
            Severity.HIGH,
            0.8,
        ),
        (
            "Database Connection String with Credentials",
            r"(?i)(postgres|postgresql|mongodb|mysql|redis|mssql)://[^:\s]+:[^:\s]+@",
            Severity.HIGH,
            0.85,
        ),
        # --- Medium confidence: generic key/value assignments ---------------
        (
            "Generic API Key",
            r"(?i)(api[_-]?key|apikey)[\"'\s:=]+[0-9a-zA-Z\-_]{20,}",
            Severity.HIGH,
            0.6,
        ),
        (
            "Generic Secret",
            r"(?i)(secret|passwd|password)[\"'\s:=]+[0-9a-zA-Z\-_]{20,}",
            Severity.HIGH,
            0.55,
        ),
        # Note: "token" alone is intentionally excluded from the generic secret
        # pattern because ``projectId``/``apiKey`` Firebase config values are
        # public and generate many false positives.
    ]

    # Remediation guidance keyed by secret type.
    REMEDIATION: dict[str, dict[str, str]] = {
        "AWS Access Key ID": {
            "explanation": "An AWS access key ID was hardcoded in the source.",
            "why_it_matters": "Anyone with repository access can use this key to "
            "make AWS API calls on the account's behalf.",
            "recommended_fix": "Remove the key and configure AWS credentials via "
            "environment variables (``AWS_ACCESS_KEY_ID``/``AWS_SECRET_ACCESS_KEY``) "
            "or IAM roles.",
            "example_fix": "export AWS_ACCESS_KEY_ID=...  # set in CI, not in code",
        },
        "AWS Secret Access Key": {
            "explanation": "An AWS secret access key was hardcoded in the source.",
            "why_it_matters": "This is a long-lived AWS credential that grants "
            "programmatic access; exposure can lead to account compromise.",
            "recommended_fix": "Remove the secret and use AWS IAM roles or "
            "environment variables. Rotate the exposed key immediately.",
            "example_fix": "aws configure  # or set AWS_SECRET_ACCESS_KEY in CI",
        },
        "GitHub Personal Access Token": {
            "explanation": "A GitHub personal access token was hardcoded.",
            "why_it_matters": "A PAT can read/write repositories and organizations "
            "the token owner has access to.",
            "recommended_fix": "Remove the token and store it in a secrets manager "
            "or GitHub Actions secrets. Rotate the exposed token.",
            "example_fix": "secrets: GITHUB_TOKEN ${{ secrets.GITHUB_TOKEN }}",
        },
        "Private Key": {
            "explanation": "A private key block was found in the repository.",
            "why_it_matters": "A private key allows impersonation and decryption "
            "of data protected by the corresponding public key.",
            "recommended_fix": "Remove the key from the repository, store it in "
            "a secrets manager or HSM, and rotate the key pair.",
            "example_fix": "# Move to ~/.ssh/id_rsa with chmod 600, not in repo",
        },
    }

    # File extensions never scanned for secrets (binaries, lockfiles, etc.).
    SKIP_EXTENSIONS: frozenset[str] = frozenset(
        {
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".bmp",
            ".ico",
            ".svg",
            ".webp",
            ".pdf",
            ".zip",
            ".tar",
            ".gz",
            ".bz2",
            ".xz",
            ".7z",
            ".rar",
            ".whl",
            ".gem",
            ".nupkg",
            ".jar",
            ".class",
            ".o",
            ".so",
            ".dll",
            ".exe",
            ".bin",
            ".pyc",
            ".pyo",
            ".pyd",
            ".lock",
            ".md",
            ".rst",
            ".txt",
            ".csv",
            ".tsv",
            ".json",
            ".yaml",
            ".yml",
            ".toml",
            ".ini",
            ".cfg",
            ".conf",
        }
    )

    # Maximum file size scanned for secrets (bytes).
    MAX_FILE_SIZE = 2_000_000  # 2 MB

    def _scan(self, root: Path) -> RuleResult:  # noqa: ARG002
        result = RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            enabled=True,
            passed=True,
        )

        compiled = [
            (name, re.compile(pattern), severity, confidence)
            for name, pattern, severity, confidence in self.SECRET_PATTERNS
        ]

        for file_path in iter_files_secure(
            root,
            ignore_dirs=self.config.exclude_dirs,
            ignore_files=self.config.exclude_files,
            max_file_size=self.MAX_FILE_SIZE,
        ):
            # Skip binary/lockfile extensions outright.
            if file_path.suffix.lower() in self.SKIP_EXTENSIONS:
                continue

            content = _read_file_safely(file_path)
            if content is None:
                continue

            for line_number, line in enumerate(content.splitlines(), start=1):
                for name, regex, severity, confidence in compiled:
                    if not regex.search(line):
                        continue

                    # Never store the raw line or any part of it.
                    remediation = self.REMEDIATION.get(name, {})
                    finding = self._finding(
                        title=f"Possible exposed {name}",
                        description=(
                            f"A potential {name} was detected on line "
                            f"{line_number} of {file_path.name}. The secret "
                            "value has been redacted and is not stored in "
                            "this report."
                        ),
                        severity=severity,
                        file_path=file_path,
                        line_number=line_number,
                        suggestion=remediation.get(
                            "recommended_fix",
                            "Remove the secret from the file and store it in "
                            "an environment variable or a secrets manager. "
                            "Rotate any exposed credentials immediately.",
                        ),
                        explanation=remediation.get("explanation"),
                        why_it_matters=remediation.get("why_it_matters"),
                        example_fix=remediation.get("example_fix"),
                        metadata={
                            "secret_type": name,
                            "redacted": True,
                            "confidence": confidence,
                        },
                        confidence=confidence,
                        redacted=True,
                    )
                    result.findings.append(finding)

        # De-duplicate findings on the same file/line/secret type.
        result.findings = _dedupe_findings(result.findings)
        result.passed = len(result.findings) == 0
        return result


def _read_file_safely(path: Path) -> str | None:
    """Read a file as text, returning ``None`` on any error.

    Delegates to :func:`repodoctor.utils.read_file_safely` but is kept here so
    the scanner remains self-contained and testable.
    """
    from repodoctor.utils import read_file_safely

    return read_file_safely(path)


def _dedupe_findings(findings: list) -> list:
    """Remove duplicate findings for the same file, line, and secret type."""
    seen: set[tuple[str, int | None, str]] = set()
    unique: list = []
    for f in findings:
        key = (
            str(f.file_path) if f.file_path else "",
            f.line_number,
            f.metadata.get("secret_type", "") if f.metadata else "",
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    return unique
