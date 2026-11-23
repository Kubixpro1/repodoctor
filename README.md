# repodoctor

Repository health diagnostic CLI for open-source maintainers.

`repodoctor` scans your repository for missing governance files, exposed
secrets, dependency issues, CI/CD security gaps, and other common problems,
producing actionable reports in text, JSON, SARIF 2.1.0, and Markdown formats.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/Kubixpro1/repodoctor/actions/workflows/ci.yml/badge.svg)](https://github.com/Kubixpro1/repodoctor/actions/workflows/ci.yml)

## Problem

Open-source maintainers juggle many responsibilities: reviewing pull requests,
managing dependencies, responding to security reports, and keeping documentation
up to date. It's easy for small but critical issues to slip through the cracks
— a missing LICENSE file, a hardcoded API key, an outdated dependency with a
known vulnerability, or a CI pipeline that doesn't run tests.

`repodoctor` gives you a single command to check your repository's health and
get a prioritized list of things to fix.

## Features

- **Governance file checks** — LICENSE, README.md, CONTRIBUTING.md,
  CODE_OF_CONDUCT.md, SECURITY.md, CHANGELOG.md, .gitignore
- **Extended governance** — CODEOWNERS, issue templates, pull request
  templates, maintainer documentation, versioning policy
- **README quality** — verifies essential sections (installation, usage, license)
- **Secret detection** — Finds hardcoded API keys, tokens, private keys, and
  credentials across 20+ secret types (AWS, GitHub, Stripe, Slack, Twilio,
  Azure, Heroku, Mailgun, etc.). Secret values are **never** stored in findings
  or emitted in any report format — they are redacted to `[REDACTED]`.
- **Dependency intelligence** — Parses requirements.txt, pyproject.toml,
  Pipfile, poetry.lock, package.json, package-lock.json, yarn.lock,
  pnpm-lock.yaml, Cargo.toml, Cargo.lock, go.mod, go.sum, .csproj,
  packages.lock.json and Directory.Packages.props. Detects outdated
  dependencies, missing lockfiles, version conflicts, and unidentified
  licenses, plus a full dependency inventory with transitive analysis.
- **Known vulnerability detection** — Runs `pip-audit`, `safety`,
  `npm audit` and `cargo audit` when available (opt-in, skipped in offline
  mode). No repository contents or secrets are transmitted.
- **CI/CD validation** — Checks for CI configuration and test steps
- **License validation** — Verifies LICENSE uses an OSI-approved identifier
- **Test presence** — Detects missing test suites
- **Git hygiene** — Checks for commits, remotes, and release tags
- **Large files & build artifacts** — Flags files >50MB and committed binaries
- **Build system detection** — Python, Node.js, Rust, Go, .NET
- **GitHub security analysis** — Workflow permissions, unpinned actions,
  `pull_request_target`, Dependabot, security policy, branch protection
  (reported as unknown when not locally verifiable)
- **Multiple output formats** — Text, JSON, SARIF 2.1.0, Markdown
- **Historical health tracking** — Store and compare scan summaries, detect
  new/resolved problems, track dependency changes
- **Smart remediation** — Every finding includes an explanation, why it
  matters, a recommended fix, and an example where appropriate
- **Plugin architecture** — Custom scanners via entry points or a
  `repodoctor_plugins/` directory without modifying core
- **Configurable** — `repodoctor.json` for excluding directories/files and
  disabling rules
- **CI-friendly** — `--fail-on` flag for non-zero exit on findings above a
  severity threshold; `--offline` to skip network checks

## Installation

```bash
python -m pip install "repodoctor @ git+https://github.com/Kubixpro1/repodoctor.git"
```

For development from source:

```bash
git clone https://github.com/Kubixpro1/repodoctor.git
cd repodoctor
python -m pip install -e ".[dev]"
```

## Usage

```bash
# Scan the current repository
repodoctor scan .

# Scan a specific directory
repodoctor scan /path/to/repo

# JSON output for CI pipelines
repodoctor scan . --format json

# SARIF output for GitHub Code Scanning
repodoctor scan . --format sarif > results.sarif

# Fail CI if critical or high findings exist
repodoctor scan . --fail-on high

# Skip network-based dependency checks
repodoctor scan . --offline

# Exclude directories from scanning
repodoctor scan . --exclude tests/ --exclude docs/

# Quiet / verbose mode
repodoctor scan . --quiet
repodoctor scan . --verbose

# Initialize a repodoctor.json config file
repodoctor init

# Show version
repodoctor version
```

## Try the Demo

Clone the repository and run the end-to-end demonstration:

```bash
python examples/demo.py
```

It creates an intentionally unhealthy repository in a temporary directory,
detects governance, dependency, and credential issues, then removes the sample
directory. The demo never scans or modifies your own project.

## Configuration

Create a `repodoctor.json` in your repository root to customize behavior.
Run `repodoctor init` to generate a default configuration.

```json
{
  "severity_threshold": "info",
  "output_format": "text",
  "exclude_dirs": [".git", "node_modules", "dist"],
  "exclude_files": ["*.lock", "*.pyc"],
  "exclude": ["tests/"],
  "offline": false,
  "max_file_size": 2000000,
  "rules": {
    "governance_files": true,
    "extended_governance": true,
    "readme_quality": true,
    "secrets": true,
    "dependencies": true,
    "ci_cd": true,
    "github_security": true,
    "license": true,
    "tests": true,
    "git_hygiene": true,
    "large_files": true,
    "build_artifacts": true
  },
  "rule_overrides": {},
  "dependency_checks": {
    "outdated": true,
    "vulnerabilities": true,
    "licenses": true,
    "conflicts": true,
    "missing_lockfile": true
  },
  "github_security": {
    "check_workflow_permissions": true,
    "check_unpinned_actions": true,
    "check_pull_request_target": true,
    "check_dependabot": true,
    "check_branch_protection": true
  }
}
```

## Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| Text | `--format text` (default) | Human-readable terminal output |
| JSON | `--format json` | Machine-readable, CI pipelines |
| SARIF | `--format sarif` | GitHub Code Scanning integration |
| Markdown | `--format markdown` | Documentation, issue comments |

## Severity Levels

| Level | Description | Example |
|-------|-------------|---------|
| Critical | Immediate security risk | Exposed private key, AWS secret key |
| High | Serious issue | Missing LICENSE, hardcoded API key |
| Medium | Important gap | No CI/CD, missing security policy |
| Low | Minor improvement | Missing changelog, large file |
| Info | Informational | No dependency manifest found |

## Safety

`repodoctor` is **read-only**. It never modifies your repository, never uploads
source code or secrets, and never sends data to any external service unless you
explicitly opt in to network-based dependency checks (and even then, only
package metadata is sent to the relevant audit tool — never secrets).

Detected secret values are never printed in output — only the file, line
number, and secret type are reported. Secret values are redacted to
`[REDACTED]` in all findings.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed, no findings above `--fail-on` threshold |
| 1 | Findings exist at or above `--fail-on` threshold |
| 2 | Error (e.g., path is not a directory) |

## CI/CD Integration

### GitHub Actions

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

### GitHub Code Scanning (SARIF)

```yaml
- run: repodoctor scan . --format sarif > repodoctor.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: repodoctor.sarif
```

## Plugin Architecture

External developers can create custom scanners without modifying RepoDoctor
core. See [docs/plugins.md](docs/plugins.md) for the plugin interface, scanner
lifecycle, finding schema, and an example plugin.

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for details on
setting up a development environment, coding standards, and the pull request
process.

## Security

Please see [SECURITY.md](SECURITY.md) for information on reporting
vulnerabilities.

## License

This project is licensed under the [MIT License](LICENSE).

## Code of Conduct

Please see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for our community
expectations.

## Roadmap

See [ROADMAP.md](ROADMAP.md) for planned features and releases.
