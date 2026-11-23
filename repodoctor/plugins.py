"""Plugin architecture for repodoctor.

External developers can create custom scanners without modifying RepoDoctor
core. Plugins are discovered through:

1. ``repodoctor.plugins`` entry points (installed packages).
2. A ``repodoctor_plugins/`` directory next to the config or cwd.
3. The ``--plugin`` CLI flag (a Python module path or file path).

See ``docs/plugins.md`` for the full plugin developer guide.
"""

from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path
from typing import Any, cast

from repodoctor.config import RepodoctorConfig
from repodoctor.rules import Finding, RuleResult, Severity

ENTRY_POINT_GROUP = "repodoctor.plugins"
PLUGIN_DIR_NAME = "repodoctor_plugins"


class ScannerPlugin:
    """Interface for custom scanner plugins.

    Subclass this and register via an entry point or drop a module into a
    ``repodoctor_plugins/`` directory.
    """

    rule_id: str = ""
    rule_name: str = ""

    def __init__(self, config: RepodoctorConfig) -> None:
        self.config = config

    def is_enabled(self) -> bool:
        return self.config.is_rule_enabled(self.rule_id)

    def scan(self, root: Path) -> RuleResult:
        """Scan *root* and return a :class:`RuleResult`.

        The base implementation handles enabled/disabled and error handling;
        subclasses implement ``_scan``.
        """
        result = RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            enabled=self.is_enabled(),
            passed=False,
        )
        if not self.is_enabled():
            result.passed = True
            return result
        try:
            result = self._scan(root)
        except Exception as exc:  # pragma: no cover - defensive
            result.error = f"Plugin scanner error: {exc!s}"
            result.passed = False
        return result

    def _scan(self, root: Path) -> RuleResult:  # noqa: ARG002
        raise NotImplementedError

    def _finding(
        self,
        title: str,
        description: str,
        severity: Severity = Severity.INFO,
        file_path: Path | None = None,
        line_number: int | None = None,
        suggestion: str | None = None,
        explanation: str | None = None,
        why_it_matters: str | None = None,
        recommended_fix: str | None = None,
        example_fix: str | None = None,
        confidence: float = 1.0,
        metadata: dict[str, Any] | None = None,
    ) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            title=title,
            description=description,
            severity=severity,
            file_path=file_path,
            line_number=line_number,
            suggestion=suggestion,
            explanation=explanation,
            why_it_matters=why_it_matters,
            recommended_fix=recommended_fix or suggestion,
            example_fix=example_fix,
            confidence=confidence,
            metadata=metadata or {},
        )


def load_entry_point_plugins(config: RepodoctorConfig) -> list[ScannerPlugin]:
    """Load scanner plugins registered under the ``repodoctor.plugins`` entry point group."""
    plugins: list[ScannerPlugin] = []
    try:
        from importlib.metadata import entry_points  # Python 3.10+

        eps = entry_points()
        # importlib.metadata.entry_points().select() is 3.10+; handle both.
        group_eps: list = []
        if hasattr(eps, "select"):
            group_eps = list(eps.select(group=ENTRY_POINT_GROUP))
        else:
            group_eps = [ep for ep in eps if getattr(ep, "group", None) == ENTRY_POINT_GROUP]
        for ep in group_eps:
            try:
                factory = ep.load()
                plugin = factory(config)
                plugins.append(cast(ScannerPlugin, plugin))
            except Exception:  # pragma: no cover - defensive, bad plugin  # noqa: S110
                pass
    except Exception:  # pragma: no cover - metadata unavailable  # noqa: S110
        pass
    return plugins


def load_directory_plugins(
    config: RepodoctorConfig, search_dirs: list[Path]
) -> list[ScannerPlugin]:
    """Load scanner plugin modules from a list of directories.

    Each directory is scanned for ``*.py`` modules (excluding ``__init__.py``)
    that define a ``create_plugin(config)`` factory returning a
    :class:`ScannerPlugin`, or a module-level ``PLUGIN`` instance.
    """
    plugins: list[ScannerPlugin] = []
    for directory in search_dirs:
        if not directory.is_dir():
            continue
        try:
            entries = sorted(p for p in directory.iterdir() if p.is_file() and p.suffix == ".py")
        except OSError:
            continue
        for entry in entries:
            if entry.name == "__init__.py":
                continue
            plugin = _load_plugin_module(entry, config)
            if plugin is not None:
                plugins.append(plugin)
    return plugins


def _load_plugin_module(path: Path, config: RepodoctorConfig) -> ScannerPlugin | None:
    """Load a single plugin module from a file path."""
    module_name = f"repodoctor_plugin_{path.stem}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    try:
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
    except Exception:  # pragma: no cover - defensive, bad plugin
        sys.modules.pop(module_name, None)
        return None

    factory = getattr(module, "create_plugin", None)
    if factory is not None:
        try:
            return cast(ScannerPlugin, factory(config))
        except Exception:  # pragma: no cover - defensive
            return None
    plugin_instance = getattr(module, "PLUGIN", None)
    if plugin_instance is not None:
        return cast(ScannerPlugin, plugin_instance)
    return None


def discover_plugins(
    config: RepodoctorConfig, extra_dirs: list[Path] | None = None
) -> list[ScannerPlugin]:
    """Discover all available scanner plugins."""
    plugins: list[ScannerPlugin] = []
    plugins.extend(load_entry_point_plugins(config))

    search_dirs: list[Path] = []
    cwd = Path.cwd()
    search_dirs.append(cwd / PLUGIN_DIR_NAME)
    if extra_dirs:
        search_dirs.extend(extra_dirs)
    plugins.extend(load_directory_plugins(config, search_dirs))
    return plugins


# Example plugin (included for documentation and testing).
class ExamplePlugin(ScannerPlugin):
    """Example plugin demonstrating the scanner interface."""

    rule_id = "example_plugin"
    rule_name = "Example Plugin"

    def _scan(self, root: Path) -> RuleResult:  # noqa: ARG002
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
                        "The example plugin requires a REQUIRED_FILE.txt in the repository root."
                    ),
                    severity=Severity.INFO,
                    file_path=marker,
                    suggestion="Create REQUIRED_FILE.txt in the repository root.",
                )
            )
        result.passed = len(result.findings) == 0
        return result
