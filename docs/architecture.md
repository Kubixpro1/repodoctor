# Architecture

## Overview

repodoctor follows a modular, plugin-like architecture with clear separation
between scanning, reporting, and CLI concerns.

## Core Components

### Configuration (`repodoctor/config.py`)

Loads and manages configuration from `repodoctor.json`. Provides defaults for
all settings and supports merging user-provided configuration with defaults.

### Rules (`repodoctor/rules.py`)

Defines data models for findings, rule results, and scan reports:

- `Finding` — A single issue with severity, description, and suggestion
- `RuleResult` — Result of running one scanner rule
- `ScanReport` — Complete scan report with health score computation

The health score starts at 100 and is reduced by weighted findings:

| Severity | Weight |
|----------|--------|
| Critical | 25 |
| High | 15 |
| Medium | 7 |
| Low | 3 |
| Info | 1 |

### Scanners (`repodoctor/scanners/`)

Each scanner is a subclass of `ScannerBase` and implements `_scan()` to
produce a `RuleResult`. Scanners are registered in `cli.py` and run
sequentially.

Available scanners:

| Scanner | Rule ID | Checks |
|---------|---------|--------|
| GovernanceFilesScanner | `governance_files` | LICENSE, README, CONTRIBUTING, etc. |
| ReadmeQualityScanner | `readme_quality` | README section completeness |
| SecretsScanner | `secrets` | Hardcoded API keys and tokens |
| DependenciesScanner | `dependencies` | Dependency manifests and vulnerabilities |
| CIScanner | `ci_cd` | CI/CD configuration |
| LicenseScanner | `license` | License validity |
| TestsScanner | `tests` | Test presence |
| GitHygieneScanner | `git_hygiene` | Git repository health |
| LargeFilesScanner | `large_files` | Large files and build artifacts |
| BuildArtifactsScanner | `build_artifacts` | Build system detection |

### Reporters (`repodoctor/reporters/`)

Each reporter formats a `ScanReport` into a specific output format:

| Reporter | Format | Use Case |
|----------|--------|----------|
| TextReporter | text | Human-readable terminal output |
| JSONReporter | json | Machine-readable CI integration |
| SARIFReporter | sarif | GitHub Code Scanning |
| MarkdownReporter | markdown | Documentation and issue comments |

### CLI (`repodoctor/cli.py`)

Argument parsing using `argparse`. Subcommands: `scan`, `init`, `version`.

## Design Principles

- **Read-only**: Scanners never modify the target repository.
- **Fail-safe**: Scanner errors are caught and reported, not fatal.
- **Extensible**: New scanners and reporters can be added without modifying
  existing code.
- **Configurable**: All behavior can be customized via `repodoctor.json`.
- **Type-safe**: Full type hints with mypy validation.

## Data Flow

```
CLI → Config → Scanners → ScanReport → Reporter → Output
                      ↳ Findings → Health Score
```
