# Configuration

Create a `repodoctor.json` file in your repository root to customize behavior.
Run `repodoctor init` to generate a default configuration.

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `severity_threshold` | string | `"info"` | Minimum severity for findings |
| `output_format` | string | `"text"` | Default output format |
| `exclude_dirs` | array | `[".git", ...]` | Directory names to skip |
| `exclude_files` | array | `[".DS_Store", ...]` | File name patterns to skip |
| `rules` | object | all `true` | Enable/disable specific rules |
| `rule_overrides` | object | `{}` | Per-rule configuration overrides |

## Example Configuration

```json
{
  "severity_threshold": "medium",
  "output_format": "text",
  "exclude_dirs": [
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build"
  ],
  "exclude_files": [
    ".DS_Store",
    "Thumbs.db",
    "*.lock",
    "*.pyc",
    "*.pyo"
  ],
  "rules": {
    "governance_files": true,
    "readme_quality": true,
    "secrets": true,
    "dependencies": true,
    "ci_cd": true,
    "license": true,
    "tests": true,
    "git_hygiene": true,
    "large_files": true,
    "build_artifacts": true
  },
  "rule_overrides": {}
}
```

## Disabling Rules

To disable a specific rule, set it to `false` in the `rules` object:

```json
{
  "rules": {
    "large_files": false
  }
}
```

## Rule Overrides

Per-rule configuration can be specified in `rule_overrides`. The exact
overrides available depend on the rule.
