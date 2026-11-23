"""Tests for secret redaction and secret detection security properties."""

from __future__ import annotations

from pathlib import Path

from repodoctor.config import RepodoctorConfig
from repodoctor.redaction import REDACTED, redact, sanitize_line, scrub_metadata
from repodoctor.reporters.json import JSONReporter
from repodoctor.reporters.sarif import SARIFReporter
from repodoctor.reporters.text import TextReporter
from repodoctor.rules import Finding, ScanReport, Severity
from repodoctor.scanners.secrets import SecretsScanner

AWS_TEST_ACCESS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
STRIPE_TEST_SECRET = "sk_" + "live_" + "1234567890abcdef1234567890"


def test_redact_never_returns_actual_value():
    """redact() must never return the secret it is given."""
    assert redact("sk_live_abcdef1234567890") == REDACTED
    assert redact(None) == REDACTED
    assert redact("") == REDACTED
    assert REDACTED != "sk_live_abcdef1234567890"


def test_sanitize_line_does_not_reproduce_line():
    """sanitize_line() must not include any of the original line content."""
    line = f'API_KEY = "{STRIPE_TEST_SECRET}"'
    sanitized = sanitize_line(line)
    assert "sk_live_" not in sanitized
    assert "API_KEY" not in sanitized
    assert STRIPE_TEST_SECRET[-24:] not in sanitized
    assert sanitized == REDACTED


def test_scrub_metadata_removes_secret_values():
    """scrub_metadata() must replace secret-like strings with [REDACTED]."""
    metadata = {
        "secret_type": "AWS Access Key ID",
        "line": AWS_TEST_ACCESS_KEY,
        "token": "ghp_1234567890abcdef1234567890",
        "count": 3,
        "safe": "hello",
    }
    scrubbed = scrub_metadata(metadata)
    assert scrubbed["secret_type"] == "AWS Access Key ID"  # noqa: S105
    assert scrubbed["line"] == REDACTED
    assert scrubbed["token"] == REDACTED
    assert scrubbed["count"] == 3
    assert scrubbed["safe"] == "hello"


def test_finding_to_dict_scrubs_secrets():
    """Finding.to_dict() must not emit raw secret values in metadata."""
    finding = Finding(
        rule_id="secrets",
        title="Possible exposed AWS Key",
        description="A potential key was detected.",
        severity=Severity.CRITICAL,
        file_path=Path("config.py"),
        line_number=7,
        metadata={"secret_type": "AWS Access Key ID", "line": AWS_TEST_ACCESS_KEY},
        redacted=True,
    )
    data = finding.to_dict()
    assert AWS_TEST_ACCESS_KEY not in str(data)
    assert data["metadata"]["line"] == REDACTED
    assert data["redacted"] is True


def test_reporter_output_redacts_secrets(tmp_path):
    """Reporters must not leak secret values even if metadata contains them."""
    report = ScanReport(target=tmp_path)
    report.all_findings.append(
        Finding(
            rule_id="secrets",
            title="Possible exposed API Key",
            description="A potential api key was detected.",
            severity=Severity.CRITICAL,
            file_path=tmp_path / "config.py",
            line_number=42,
            metadata={
                "line": STRIPE_TEST_SECRET,
                "secret_type": "Stripe API Key",
            },
            redacted=True,
        )
    )

    for reporter in (
        TextReporter(),
        JSONReporter(),
        SARIFReporter(),
    ):
        output = reporter.format(report)
        assert STRIPE_TEST_SECRET not in output, reporter.format_name


def test_secrets_scanner_no_raw_line_in_metadata(tmp_path):
    """SecretsScanner must never store the raw source line in metadata."""
    (tmp_path / "secret.py").write_text(f'API_KEY = "{STRIPE_TEST_SECRET}"\n')
    scanner = SecretsScanner(RepodoctorConfig())
    result = scanner.scan(tmp_path)
    for finding in result.findings:
        metadata_str = str(finding.metadata or {})
        assert "sk_live_" not in metadata_str
        assert "API_KEY" not in metadata_str
        assert finding.metadata.get("redacted") is True


def test_secrets_scanner_false_positives_reduced(tmp_path):
    """Public Firebase-style config keys should not be flagged as secrets."""
    (tmp_path / "firebase.js").write_text(
        'const config = { apiKey: "AIzaSyFake", projectId: "my-project", '
        'databaseURL: "https://my-project.firebaseio.com" };\n'
    )
    scanner = SecretsScanner(RepodoctorConfig())
    result = scanner.scan(tmp_path)
    # apiKey/projectId/databaseURL with short public values should not match
    # the generic secret pattern (which requires 20+ char values).
    titles = [f.title for f in result.findings]
    assert not any("projectId" in t for t in titles)
    assert not any("databaseURL" in t for t in titles)


def test_generic_pattern_requires_sufficient_length(tmp_path):
    """Short values assigned to 'secret' should not be flagged."""
    (tmp_path / "config.py").write_text('SECRET = "abc"\n')
    scanner = SecretsScanner(RepodoctorConfig())
    result = scanner.scan(tmp_path)
    assert result.passed
    assert len(result.findings) == 0


def test_secrets_detects_real_stripe_key(tmp_path):
    """A real Stripe key is detected as critical."""
    stripe_secret = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"
    (tmp_path / "payments.py").write_text(f'STRIPE_KEY = "{stripe_secret}"\n')
    scanner = SecretsScanner(RepodoctorConfig())
    result = scanner.scan(tmp_path)
    assert not result.passed
    critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical) > 0
    assert any("Stripe" in f.title for f in critical)
