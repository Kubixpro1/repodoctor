# Output Formats

repodoctor supports four output formats.

## Text (`--format text`)

Human-readable terminal output with emoji severity indicators and
color-coded sections. This is the default format.

```
============================================================
repodoctor — Repository Health Report
============================================================

Target:      /path/to/repo
Health Score: 85/100
Rules:       9/10 passed
Findings:    3 total
...
```

## JSON (`--format json`)

Machine-readable JSON with a stable schema. Suitable for CI pipelines and
custom tooling.

```json
{
  "target": "/path/to/repo",
  "health_score": 85,
  "total_rules": 10,
  "passed_rules": 9,
  "failed_rules": 1,
  "total_findings": 3,
  "findings_by_severity": {
    "critical": 0,
    "high": 1,
    "medium": 1,
    "low": 1,
    "info": 0
  },
  "rules": [...]
}
```

## SARIF (`--format sarif`)

SARIF 2.1.0 format compatible with GitHub Code Scanning and other static
analysis platforms.

```json
{
  "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/...",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "repodoctor",
        "version": "1.0.0",
        "rules": [...]
      }
    },
    "results": [...]
  }]
}
```

## Markdown (`--format markdown`)

Markdown-formatted report suitable for documentation, issue comments, or
README badges.

```markdown
# repodoctor — Repository Health Report

**Target:** `/path/to/repo`
**Health Score:** 85/100
...
```
