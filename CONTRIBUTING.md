# Contributing to repodoctor

Thank you for considering a contribution to repodoctor! We welcome bug reports,
feature suggestions, documentation improvements, and code contributions.

## Getting Started

1. Fork the repository on GitHub.
2. Clone your fork: `git clone https://github.com/your-username/repodoctor.git`
3. Create a virtual environment: `python -m venv .venv && source .venv/bin/activate`
4. Install development dependencies: `pip install -e ".[dev]"`
5. Install pre-commit hooks: `pre-commit install`

## Development Workflow

1. Create a feature branch: `git checkout -b feature/your-feature-name`
2. Make your changes.
3. Add or update tests for your changes.
4. Run the test suite: `pytest`
5. Run linting: `ruff check repodoctor/ tests/`
6. Run formatting: `ruff format repodoctor/ tests/`
7. Run type checking: `mypy repodoctor/`
8. Commit your changes: `git commit -m "feat: describe your change"`
9. Push to your fork: `git push origin feature/your-feature-name`
10. Open a pull request against the `main` branch.

## Coding Standards

- Follow PEP 8 style guidelines.
- Use type hints for all function signatures.
- Write docstrings for all public classes and methods.
- Keep functions small and focused on a single responsibility.
- Add tests for all new scanner rules and reporters.
- Use `ruff` for linting and formatting (configured in `pyproject.toml`).

## Scanner Rules

To add a new scanner rule:

1. Create a new file in `repodoctor/scanners/` (e.g. `my_rule.py`).
2. Subclass `ScannerBase` and implement `_scan()`.
3. Set `rule_id` and `rule_name` class attributes.
4. Import and register the scanner in `repodoctor/cli.py` (add to `SCANNERS` list).
5. Add tests in `tests/test_scanners.py`.
6. Document the rule in `README.md`.

## Reporters

To add a new output format:

1. Create a new file in `repodoctor/reporters/` (e.g. `html.py`).
2. Subclass `ReporterBase` and implement `format()`.
3. Set `format_name` class attribute.
4. Register the reporter in `repodoctor/cli.py` (add to `REPORTERS` dict).
5. Add tests in `tests/test_reporters.py`.

## Pull Request Process

1. Ensure all tests pass: `pytest`
2. Ensure linting passes: `ruff check repodoctor/ tests/`
3. Ensure formatting is correct: `ruff format --check repodoctor/ tests/`
4. Ensure type checking passes: `mypy repodoctor/`
5. Update documentation if needed.
6. Link to any related issues in your pull request description.
7. A maintainer will review your pull request and may request changes.

## Code Review

All pull requests are reviewed by at least one maintainer. We look for:

- Correctness and completeness of the implementation.
- Test coverage for new code.
- Clear, well-documented code.
- No intentional or accidental metric manipulation.

## Community

- Follow the [Code of Conduct](CODE_OF_CONDUCT.md).
- Ask questions by opening an issue with the "question" label.
- Report bugs by opening an issue with the "bug" label.
- Suggest features by opening an issue with the "enhancement" label.
