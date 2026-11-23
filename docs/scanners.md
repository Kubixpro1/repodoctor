# Scanner Rules

repodoctor includes 10 built-in scanner rules. Each rule checks for a specific
category of repository health issues.

## Governance Files (`governance_files`)

Checks for the presence of essential repository governance files:

- **LICENSE** (High) — Required for legal clarity on reuse
- **README.md** (High) — Primary entry point for users and contributors
- **CONTRIBUTING.md** (Medium) — Contribution guidelines for external contributors
- **CODE_OF_CONDUCT.md** (Medium) — Community behavior expectations
- **SECURITY.md** (Medium) — Vulnerability reporting instructions
- **CHANGELOG.md** (Low) — Track changes between releases
- **.gitignore** (Low) — Prevent accidental commits of build artifacts

## README Quality (`readme_quality`)

Checks README.md for essential sections:

- **Installation** (Low) — How to install the project
- **Usage** (Low) — How to use the project
- **License** (Low) — License information

## Secrets Detection (`secrets`)

Scans files for hardcoded secrets and credentials. Detects 15+ secret types:

- AWS Access Key ID / Secret Access Key (Critical)
- GitHub Personal Access Tokens (Critical)
- Private keys and PGP blocks (Critical)
- Stripe API keys (Critical)
- Slack tokens (Critical)
- SendGrid API keys (High)
- Twilio API keys (High)
- Generic API keys and secrets (High)
- Database connection strings with credentials (High)
- Docker registry credentials (High)
- Google API keys (High)
- Firebase config (Medium)

Secret values are never printed in output.

## Dependencies (`dependencies`)

Checks for dependency manifest files and runs vulnerability audit tools when
available:

- Python: `pip-audit`, `safety`
- Node.js: `npm audit`
- Rust: `cargo audit`

If no dependency manifest is found, an informational finding is reported.

## CI/CD (`ci_cd`)

Checks for CI/CD configuration files:

- GitHub Actions (`.github/workflows/*.yml`)
- GitLab CI (`.gitlab-ci.yml`)
- CircleCI (`.circleci/config.yml`)
- Jenkins (`Jenkinsfile`)
- Travis CI (`.travis.yml`)
- Azure Pipelines (`azure-pipelines.yml`)
- Buildkite (`buildkite.yml`)

Also checks that CI configurations include test steps.

## License (`license`)

Validates that the LICENSE file contains a recognized OSI-approved license
identifier (MIT, Apache-2.0, BSD variants, GPL variants, LGPL, AGPL, ISC,
MPL-2.0, Unlicense, 0BSD).

## Tests (`tests`)

Checks for the presence of test files and directories:

- Test directories: `tests/`, `test/`, `testing/`, `__tests__/`
- Test file patterns: `test_*.py`, `*_test.py`, `*_test.go`, `*_test.js`,
  `*_test.ts`, `*.test.js`, `*.test.ts`

## Git Hygiene (`git_hygiene`)

Checks Git repository health:

- Is a Git repository (High)
- Has commits (High)
- Has remote configured (Medium)
- Has release tags (Low)

## Large Files & Artifacts (`large_files`)

Flags:

- Files larger than 50 MB (Medium)
- Committed build artifacts in directories like `node_modules/`, `dist/`,
  `build/`, `target/` (Low)
- Committed binary files with extensions like `.o`, `.so`, `.dll`, `.exe`,
  `.pyc`, `.class`, `.jar` (Low)

## Build System (`build_artifacts`)

Detects build system configuration files:

- Python: `pyproject.toml`, `setup.py`, `setup.cfg`
- Node.js: `package.json`
- Rust: `Cargo.toml`
- Go: `go.mod`
- .NET: `*.csproj`, `*.sln`
