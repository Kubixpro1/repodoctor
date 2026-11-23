# Plugin Architecture

Repodoctor is designed to be extensible. External developers can create custom
scanners **without modifying RepoDoctor core**.

## How plugins are discovered

Plugins are loaded from three sources, in order:

1. **Installed entry points** — any package that registers a factory under the
   `repodoctor.plugins` entry point group.
2. **`repodoctor_plugins/` directory** — a directory next to the current
   working directory (or passed via configuration) scanned for `.py` modules.
3. **`--plugin MODULE` CLI flag** — a Python module name or `.py` file path,
   repeatable.

Each plugin module must expose either:

* a `create_plugin(config)` factory function returning a `ScannerPlugin`, or
* a module-level `PLUGIN` instance of `ScannerPlugin`.

## Scanner interface

Subclass `repodoctor.plugins.ScannerPlugin` and implement `_scan(root)`.

```python
from pathlib import Path

from repodoctor.config import RepodoctorConfig
from repodoctor.plugins import ScannerPlugin
from repodoctor.rules import RuleResult, Severity


class MyRule(ScannerPlugin):
    rule_id = "my_rule"
    rule_name = "My Custom Rule"

    def _scan(self, root: Path) -> RuleResult:
        result = RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            enabled=True,
            passed=True,
        )

        marker = root / "REQUIRED_FILE.txt"
        if not marker.is_file():
            result.findings.append(
                self._finding(
                    title="Missing REQUIRED_FILE.txt",
                    description=(
                        "The repository is missing REQUIRED_FILE.txt, which "
                        "my custom rule requires."
                    ),
                    severity=Severity.MEDIUM,
                    file_path=marker,
                    suggestion="Create REQUIRED_FILE.txt in the repository root.",
                    explanation="REQUIRED_FILE.txt documents project setup.",
                    why_it_matters=(
                        "Without it, new contributors cannot determine how to "
                        "bootstrap the project."
                    ),
                    recommended_fix="Add REQUIRED_FILE.txt with setup steps.",
                    example_fix="# REQUIRED_FILE.txt\npip install -r requirements.txt\n",
                )
            )

        result.passed = len(result.findings) == 0
        return result
```

## Registering via entry points

In your plugin's `pyproject.toml`:

```toml
[project.entry-points."repodoctor.plugins"]
my_rule = "my_plugin_module:MyRule"
```

`MyRule` must be a class (instantiated with `config`) or a factory return
value.

## Registering via a directory

Drop a `my_plugin.py` into a `repodoctor_plugins/` directory:

```
myrepo/
  repodoctor.json
  repodoctor_plugins/
    my_plugin.py
```

## Finding schema

Each finding produced by a scanner (built-in or plugin) is a
`repodoctor.rules.Finding` with these fields:

| Field | Type | Description |
|-------|------|-------------|
| `rule_id` | str | Stable rule identifier |
| `title` | str | Short finding title |
| `description` | str | Human-readable description |
| `severity` | Severity | info / low / medium / high / critical |
| `file_path` | str \| None | Repository-relative file path |
| `line_number` | int \| None | Line where the issue was found |
| `suggestion` | str \| None | Suggested fix |
| `recommended_fix` | str \| None | Concrete recommended fix |
| `explanation` | str \| None | Plain-language explanation |
| `why_it_matters` | str \| None | Why the issue matters |
| `example_fix` | str \| None | Example remediation |
| `confidence` | float | Scanner confidence (0.0-1.0) |
| `redacted` | bool | True if secret material was redacted |
| `metadata` | dict | Extra data (no secret values) |

**Important**: plugins must never store raw secret values in `metadata` or any
string field. Use `repodoctor.redaction.redact()` and
`repodoctor.redaction.sanitize_line()` when referencing lines that may contain
secrets.

## Lifecycle

1. `ScannerPlugin.__init__(config)` — store the configuration.
2. `is_enabled()` — consults `config.is_rule_enabled(rule_id)`.
3. `scan(root)` — handles enabled/disabled and error handling, then calls
   `_scan(root)`.
4. `_scan(root)` — your scanning logic; returns a `RuleResult`.

Scanner errors are caught and reported as `RuleResult.error`; they never crash
the scan.

## Example plugin

Repodoctor ships with an example plugin,
`repodoctor.plugins.ExamplePlugin` (rule_id `example_plugin`), which checks
for a `REQUIRED_FILE.txt`. It is registered as a built-in demonstration and is
not enabled by default.

## Keeping core small

Repodoctor's core has no required third-party dependencies beyond the Python
standard library. Plugins may bring their own dependencies, which are the
plugin author's responsibility to document.
