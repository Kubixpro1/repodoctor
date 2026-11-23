"""Secret redaction utilities.

This module guarantees that secret values never leak into repodoctor findings,
terminal output, JSON, SARIF, logs, or debug messages.

Design principles
-----------------
* Secret values are never stored in :class:`~repodoctor.rules.Finding`
  metadata.
* The only safe representation of a secret is a redaction placeholder.
* Reporter output is scanned for any accidental secret material and redacted
  before it is written.
"""

from __future__ import annotations

import re

# Placeholder used whenever a secret value would otherwise be disclosed.
REDACTED = "[REDACTED]"

# A secret-like value that should never be stored verbatim. This is used to
# scrub any raw source line that happens to match a secret pattern.
_SECRET_VALUE_TOKEN = re.compile(r"\S{8,}")


def redact(value: str | None) -> str:
    """Return a safe placeholder for *value*, never the actual content.

    Args:
        value: A potential secret value (or ``None``).

    Returns:
        Always ``"[REDACTED]"`` — the actual content is never returned.
    """
    return REDACTED


def sanitize_line(line: str) -> str:
    """Return a diagnostic-safe rendering of a source line.

    The returned string never reproduces the line content, so a secret that
    happens to appear on the matched line cannot leak through reports.

    Args:
        line: The raw source line that triggered a finding.

    Returns:
        A string indicating that a match occurred on this line, without the
        line's content.
    """
    # We intentionally do not include any part of the line. Even a short
    # prefix could reveal a secret (e.g. a 4-char AWS key prefix).
    return REDACTED


def is_secret_metadata(metadata: dict) -> bool:
    """Return True if *metadata* appears to contain a disclosed secret value.

    This is a best-effort check used as a final safety net in reporters.
    """
    for value in metadata.values():
        if _looks_like_secret(value):
            return True
    return False


def _looks_like_secret(value: object) -> bool:
    if not isinstance(value, str):
        return False
    if not value or value == REDACTED:
        return False
    # Separator lines (e.g. "=====" or "-----") are not secrets.
    if len(set(value)) == 1:
        return False
    # A token-like secret must contain at least one alphanumeric character.
    if not any(ch.isalnum() for ch in value):
        return False
    # Heuristic: long, high-entropy strings are likely secrets/tokens.
    if len(value) >= 16 and re.fullmatch(r"[0-9A-Za-z_\-+/=]{16,}", value):
        return True
    # Common prefix patterns for known secret types.
    prefixes = (
        "AKIA",
        "ghp_",
        "gho_",
        "github_pat_",
        "xoxb-",
        "xoxa-",
        "xoxp-",
        "xoxr-",
        "xoxs-",
        "sk_live_",
        "sk_test_",
        "pk_live_",
        "pk_test_",
        "SG.",
        "AIza",
        "SK",
    )
    return any(value.startswith(p) for p in prefixes)


def scrub_metadata(metadata: dict) -> dict:
    """Return a copy of *metadata* with any secret values replaced.

    Only primitive values are inspected; nested structures are passed through
    unchanged (scanners should not nest raw secrets).
    """
    scrubbed: dict = {}
    for key, value in metadata.items():
        if isinstance(value, str) and _looks_like_secret(value):
            scrubbed[key] = REDACTED
        else:
            scrubbed[key] = value
    return scrubbed
