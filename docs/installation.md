# Installation

## From PyPI

```bash
pip install repodoctor
```

## From Source

```bash
git clone https://github.com/repodoctor/repodoctor.git
cd repodoctor
pip install -e .
```

## Development Installation

For contributing to repodoctor itself:

```bash
git clone https://github.com/repodoctor/repodoctor.git
cd repodoctor
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pre-commit install
```

## Requirements

- Python 3.9 or higher
- pip or another Python package manager

## Optional Dependencies

`repodoctor` can optionally invoke external audit tools if they are installed:

| Tool | Purpose | Install |
|------|---------|---------|
| `pip-audit` | Python dependency vulnerabilities | `pip install pip-audit` |
| `safety` | Python dependency vulnerabilities | `pip install safety` |
| `npm` | Node.js dependency audit | [Node.js](https://nodejs.org/) |
| `cargo` | Rust dependency audit | [Rust](https://rustup.rs/) |
