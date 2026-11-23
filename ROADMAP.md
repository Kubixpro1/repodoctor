# Roadmap

## 2.1.0 (Near Term)

- [ ] Add `.repodoctorignore` file support for excluding files/directories
- [ ] Add `--include` CLI flags for ad-hoc inclusions
- [ ] Add more secret types (GCP and additional SaaS providers)
- [ ] Add Python package age check (detect unmaintained dependencies)
- [ ] Add GitHub-specific checks (branch protection, dependabot, etc.)
- [ ] Add HTML report format
- [ ] Add `--watch` mode for continuous monitoring

## 2.2.0 (Medium Term)

- [ ] Add Go, Rust, Node.js, .NET specific vulnerability database checks
- [ ] Add license compatibility checking (detect GPL in MIT-licensed projects)
- [ ] Add dependency freshness scoring (how recently were deps updated?)
- [ ] Add pre-commit hook integration
- [ ] Add GitHub Action that posts review comments on PRs
- [ ] Add benchmarking for scan performance on large repos

## Future Releases

- [ ] Web dashboard for viewing scan history
- [ ] Multi-repository scanning (scan an organization's repos)
- [ ] Integration with external vulnerability databases (OSV, GitHub Advisories)
- [ ] Remote scanning mode (scan via SSH or Git protocol)
- [ ] Language server protocol (LSP) support for IDE integration

## Release Process

1. Update `CHANGELOG.md` with changes since last release.
2. Bump version in `repodoctor/__init__.py` and `pyproject.toml`.
3. Create a Git tag (e.g. `v1.1.0`).
4. Publish to PyPI.
5. Create a GitHub release with release notes.
