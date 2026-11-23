# API Reference

## repodoctor.cli

```python
from repodoctor.cli import main

exit_code = main(["scan", ".", "--format", "json"])
```

### `main(argv=None) -> int`

CLI entry point. Parses arguments and dispatches to the appropriate command
handler. Returns a process exit code.

**Commands:**

- `scan [path] [--format FORMAT] [--output PATH] [--config PATH] [--fail-on SEVERITY]`
- `init [--path PATH]`
- `version`

**Options:**

- `--list-rules` — List all available scanner rules
- `--version` — Show version information

## repodoctor.config

### `RepodoctorConfig`

Configuration dataclass for repodoctor runs.

```python
from repodoctor.config import RepodoctorConfig

config = RepodoctorConfig.load(Path("repodoctor.json"))
config = RepodoctorConfig.from_dict({"rules": {"secrets": False}})
config.is_rule_enabled("governance_files")  # True/False
```

**Attributes:**

| Attribute | Type | Default |
|-----------|------|---------|
| `severity_threshold` | str | `"info"` |
| `output_format` | str | `"text"` |
| `exclude_dirs` | list[str] | Common VCS/build directories |
| `exclude_files` | list[str] | Common OS/backup files |
| `rules` | dict[str, bool] | All rules enabled |
| `rule_overrides` | dict[str, dict] | Empty |

## repodoctor.rules

### `Severity`

Enum of severity levels: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.

### `Finding`

A single finding produced by a scanner.

```python
from repodoctor.rules import Finding, Severity
from pathlib import Path

finding = Finding(
    rule_id="secrets",
    title="Possible exposed API Key",
    description="A potential api key was detected.",
    severity=Severity.HIGH,
    file_path=Path("config.py"),
    line_number=42,
    suggestion="Move to environment variable.",
)
```

### `RuleResult`

Result of running one scanner rule.

### `ScanReport`

Complete scan report. Computes health score and aggregates findings.

```python
report = ScanReport(target=Path("/path/to/repo"))
score = report.health_score()  # 0-100
data = report.to_dict()  # JSON-serializable dict
```

## repodoctor.scanners.base

### `ScannerBase`

Base class for all scanners. Subclasses must implement `_scan()` and set
`rule_id` and `rule_name` class attributes.

```python
from repodoctor.scanners.base import ScannerBase
from repodoctor.config import RepodoctorConfig
from repodoctor.rules import Severity

class MyScanner(ScannerBase):
    rule_id = "my_rule"
    rule_name = "My Rule"

    def _scan(self, root):
        result = RuleResult(...)
        finding = self._finding(
            title="Issue found",
            description="Description",
            severity=Severity.MEDIUM,
            suggestion="Fix it",
        )
        result.findings.append(finding)
        return result
```

## repodoctor.reporters.base

### `ReporterBase`

Base class for all reporters. Subclasses must implement `format()` and set
`format_name` class attribute.

```python
from repodoctor.reporters.base import ReporterBase
from repodoctor.rules import ScanReport

class MyReporter(ReporterBase):
    format_name = "myformat"

    def format(self, report: ScanReport) -> str:
        return "report content"
```

## repodoctor.utils

Utility functions for file iteration and safe reading.

```python
from repodoctor.utils import iter_files, read_file_safely

for path in iter_files(root, patterns=["*.py"]):
    content = read_file_safely(path)
```
