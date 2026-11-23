# CI/CD Integration

## GitHub Actions

Add a workflow file at `.github/workflows/health.yml`:

```yaml
name: Repository Health
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  repodoctor:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.x"
      - run: pip install repodoctor
      - run: repodoctor scan . --fail-on high
```

## GitHub Code Scanning (SARIF)

Upload SARIF results to GitHub Code Scanning:

```yaml
- run: repodoctor scan . --format sarif > repodoctor.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: repodoctor.sarif
```

## GitLab CI

```yaml
repodoctor:
  image: python:3.11
  script:
    - pip install repodoctor
    - repodoctor scan . --fail-on high
```

## Exit Codes in CI

Use `--fail-on` to control when the scan fails the CI pipeline:

| Flag | Behavior |
|------|----------|
| `--fail-on info` | Fail on any finding (strictest) |
| `--fail-on low` | Fail on low and above |
| `--fail-on medium` | Fail on medium and above |
| `--fail-on high` | Fail on high and above |
| `--fail-on critical` | Fail only on critical findings |

## Pre-commit Hook

Add to `.pre-commit-config.yaml`:

```yaml
- repo: https://github.com/repodoctor/repodoctor
  rev: v1.0.0
  hooks:
    - id: repodoctor
      args: [scan, ., --fail-on, medium]
```
