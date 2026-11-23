# Usage

## Basic Commands

```bash
# Scan the current directory
repodoctor scan .

# Scan a specific path
repodoctor scan /path/to/repo

# Use a specific output format
repodoctor scan . --format json
repodoctor scan . --format sarif
repodoctor scan . --format markdown

# Write output to a file
repodoctor scan . --format json --output report.json

# Fail if findings at or above a severity exist
repodoctor scan . --fail-on high

# List all available rules
repodoctor --list-rules

# Show version
repodoctor version

# Initialize a configuration file
repodoctor init
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed, no findings above `--fail-on` threshold |
| 1 | Findings exist at or above `--fail-on` threshold |
| 2 | Error (e.g., path is not a directory) |

## Examples

### CI Pipeline (GitHub Actions)

```yaml
- run: repodoctor scan . --fail-on high
```

### Generate SARIF for Code Scanning

```bash
repodoctor scan . --format sarif > repodoctor.sarif
```

### JSON for Custom Tooling

```bash
repodoctor scan . --format json --output health.json
```
