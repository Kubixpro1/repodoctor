# Changelog

All notable changes to repodoctor will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Added a development dependency group, automated dependency updates, explicit
  CI permissions, code ownership, and maintainer documentation.
- Corrected installation instructions to use the GitHub repository until a
  PyPI release is published.
- Replaced committed secret-shaped test fixtures with runtime-generated values.

## [2.0.0] - 2026-11-23

### Major

- **Secret detection hardened**: secret values are never stored in finding
  metadata or emitted in any report format; raw source lines are redacted.
- **Filesystem security**: symlinks that escape the scan root are never
  followed; directory traversal is prevented; unreadable files are handled
  gracefully.
- **Network safety**: network-based dependency checks are opt-in and skipped
  in `--offline` mode; no repository contents or secrets are transmitted.
- **CLI**: added `--offline`, `--exclude`, `--quiet`, `--verbose`, and
  `--history`/`--no-history` flags.
- **SARIF 2.1.0**: repository-relative artifact paths, stable rule
  identifiers, severity-mapped `security-severity`, GitHub Code Scanning
  compatibility.
- **Plugin architecture**: custom scanners via entry points or a
  `repodoctor_plugins/` directory.

### Added

- Dependency intelligence: inventory, outdated detection, missing lockfile,
  version conflict, and license identification for Python, Node.js, Rust, Go
  and .NET manifests/lockfiles.
- GitHub security analysis: workflow permissions, unpinned actions,
  `pull_request_target`, Dependabot, security policy, branch protection.
- Extended governance: CODEOWNERS, issue/PR templates, maintainer docs,
  versioning policy.
- Historical health tracking: compare scores, detect new/resolved findings,
  track dependency changes.
- Smart remediation: explanation, why it matters, recommended fix, example.
- `--list-rules` now includes plugin scanners.

### Changed

- Bumped version to 2.0.0.
- Finding model gains `explanation`, `why_it_matters`, `recommended_fix`,
  `example_fix`, `confidence`, `redacted` fields.

### Security

- Secrets scanner: reduced false positives, added 20+ secret types, redacted
  secret values in all output formats.
- No raw source lines stored in finding metadata.

## [1.0.0] - 2026-11-23

### Added

- Initial release of repodoctor
- 10 scanner rules:
  - governance_files — checks for LICENSE, README.md, CONTRIBUTING.md,
    CODE_OF_CONDUCT.md, SECURITY.md, CHANGELOG.md, .gitignore
  - readme_quality — checks README.md for Installation, Usage, License sections
  - secrets — detects 15+ secret types (AWS, GitHub, Stripe, Slack, etc.)
  - dependencies — checks for dependency manifests and runs audit tools
  - ci_cd — checks for CI/CD configuration and test steps
  - license — validates LICENSE uses an OSI-approved identifier
  - tests — detects presence of test files and directories
  - git_hygiene — checks for commits, remotes, and release tags
  - large_files — flags files >50MB and committed build artifacts
  - build_artifacts — detects build system configuration
- 4 output formats: text, JSON, SARIF 2.1.0, Markdown
- Configuration file support (`repodoctor.json`)
- `--fail-on` flag for CI/CD integration
- `repodoctor init` command to generate default config
- `repodoctor --list-rules` to list available rules
- `repodoctor version` command
- Comprehensive test suite (48 tests)
- GitHub Actions CI workflow
- MIT License, CONTRIBUTING, CODE_OF_CONDUCT, SECURITY documentation

### Security

- Secrets scanner detects hardcoded API keys, tokens, and private keys
- Secret values are never printed in output
- Read-only scanning — never modifies the target repository
