"""Command-line interface for repodoctor.

Supports:

    repodoctor scan .
    repodoctor scan . --format json
    repodoctor scan . --format sarif
    repodoctor scan . --fail-on high
    repodoctor scan . --offline
    repodoctor scan . --exclude tests/
    repodoctor init
    repodoctor version

argparse is preserved as the argument-parsing library.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Any, cast

from repodoctor import __version__
from repodoctor.config import RepodoctorConfig
from repodoctor.history import HistoryStore, build_summary, compare
from repodoctor.plugins import discover_plugins
from repodoctor.reporters.json import JSONReporter
from repodoctor.reporters.markdown import MarkdownReporter
from repodoctor.reporters.sarif import SARIFReporter
from repodoctor.reporters.text import TextReporter
from repodoctor.rules import ScanReport
from repodoctor.scanners.base import ScannerBase
from repodoctor.scanners.build_artifacts import BuildArtifactsScanner
from repodoctor.scanners.ci import CIScanner
from repodoctor.scanners.deps import DependenciesScanner
from repodoctor.scanners.files import GovernanceFilesScanner, ReadmeQualityScanner
from repodoctor.scanners.gh_security import GitHubSecurityScanner
from repodoctor.scanners.git_hygiene import GitHygieneScanner
from repodoctor.scanners.governance_extended import ExtendedGovernanceScanner
from repodoctor.scanners.large_files import LargeFilesScanner
from repodoctor.scanners.license import LicenseScanner
from repodoctor.scanners.secrets import SecretsScanner
from repodoctor.scanners.tests import TestsScanner
from repodoctor.utils import resolve_root

REPORTERS: dict[str, type] = {
    "text": TextReporter,
    "json": JSONReporter,
    "sarif": SARIFReporter,
    "markdown": MarkdownReporter,
}

# Core scanners registered by default. Plugin scanners are appended at runtime.
SCANNERS: list[type[ScannerBase]] = [
    GovernanceFilesScanner,
    ExtendedGovernanceScanner,
    ReadmeQualityScanner,
    SecretsScanner,
    DependenciesScanner,
    CIScanner,
    GitHubSecurityScanner,
    LicenseScanner,
    TestsScanner,
    GitHygieneScanner,
    LargeFilesScanner,
    BuildArtifactsScanner,
]

SEVERITY_ORDER: list[str] = ["info", "low", "medium", "high", "critical"]


class ProgressReporter:
    """Minimal progress indicator written to stderr.

    Silent unless ``verbose`` is True, keeping machine-readable output (JSON,
    SARIF) on stdout clean.
    """

    def __init__(self, verbose: bool = False, quiet: bool = False) -> None:
        self.verbose = verbose and not quiet
        self.quiet = quiet
        self._start = time.monotonic()

    def scanner_started(self, name: str, index: int, total: int) -> None:
        if self.verbose:
            elapsed = time.monotonic() - self._start
            print(
                f"[{index}/{total}] {elapsed:5.2f}s  scanning {name}...",
                file=sys.stderr,
            )

    def finished(self, total_findings: int, health_score: int) -> None:
        if self.verbose:
            elapsed = time.monotonic() - self._start
            print(
                f"scan complete in {elapsed:.2f}s: {total_findings} findings, "
                f"health score {health_score}/100",
                file=sys.stderr,
            )


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with subcommands."""
    parser = argparse.ArgumentParser(
        prog="repodoctor",
        description=(
            "Repository health diagnostic CLI for open-source maintainers. "
            "Scans repositories for governance gaps, exposed secrets, "
            "dependency issues, and CI/CD security problems."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"repodoctor {__version__}",
    )
    parser.add_argument(
        "--list-rules",
        action="store_true",
        help="List all available scanner rules and exit.",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress progress and informational messages.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show progress indicators and detailed diagnostics.",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # scan subcommand
    scan_parser = subparsers.add_parser("scan", help="Scan a repository for health issues")
    scan_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Repository directory to scan (default: current directory).",
    )
    scan_parser.add_argument(
        "--format",
        "-f",
        choices=sorted(REPORTERS.keys()),
        default="text",
        help="Output format (default: text).",
    )
    scan_parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=None,
        help="Write report to a file instead of stdout.",
    )
    scan_parser.add_argument(
        "--config",
        "-c",
        type=Path,
        default=None,
        help="Path to repodoctor.json configuration file.",
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=SEVERITY_ORDER,
        default="critical",
        help=("Exit non-zero if findings at or above this severity exist (default: critical)."),
    )
    scan_parser.add_argument(
        "--offline",
        action="store_true",
        help="Skip network-based dependency vulnerability checks.",
    )
    scan_parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="PATTERN",
        help="Exclude files/directories matching this glob pattern (repeatable).",
    )
    scan_parser.add_argument(
        "--history",
        action="store_true",
        default=None,
        help="Enable historical health tracking and comparison (default: on).",
    )
    scan_parser.add_argument(
        "--no-history",
        action="store_true",
        help="Disable historical health tracking.",
    )
    scan_parser.add_argument(
        "--plugin",
        action="append",
        default=[],
        metavar="MODULE",
        help="Load an additional plugin module or file (repeatable).",
    )

    # init subcommand
    init_parser = subparsers.add_parser("init", help="Initialize a repodoctor.json config file")
    init_parser.add_argument(
        "--path",
        type=Path,
        default=Path("repodoctor.json"),
        help="Path to write the config file (default: repodoctor.json).",
    )

    # version subcommand
    subparsers.add_parser("version", help="Show version information")

    return parser


def run_scanners(
    config: RepodoctorConfig,
    root: Path,
    progress: ProgressReporter,
    extra_plugins: list[ScannerBase] | None = None,
) -> ScanReport:
    """Run all enabled scanners and return a combined report."""
    report = ScanReport(target=root)

    scanner_classes: list[type[ScannerBase]] = list(SCANNERS)
    scanner_instances: list[ScannerBase] = [cls(config) for cls in scanner_classes]

    # Discover and attach external plugins.
    if extra_plugins:
        for plugin in extra_plugins:
            scanner_instances.append(plugin)

    for index, scanner in enumerate(scanner_instances, start=1):
        if not scanner.is_enabled():
            continue
        progress.scanner_started(scanner.rule_name, index, len(scanner_instances))
        result = scanner.scan(root)
        report.rules.append(result)
        report.all_findings.extend(result.findings)

    progress.finished(report.total_findings, report.health_score())
    return report


def compute_exit_code(report: ScanReport, fail_on: str) -> int:
    """Determine the process exit code based on findings and threshold."""
    try:
        threshold_index = SEVERITY_ORDER.index(fail_on.lower())
    except ValueError:
        threshold_index = 0

    severity_counts = {
        "critical": report.critical_count,
        "high": report.high_count,
        "medium": report.medium_count,
        "low": report.low_count,
        "info": report.info_count,
    }

    for sev in SEVERITY_ORDER[threshold_index:]:
        if severity_counts.get(sev, 0) > 0:
            return 1

    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    """Execute the scan command."""
    root = resolve_root(Path(args.path))
    if not root.is_dir():
        print(f"Error: '{root}' is not a directory.", file=sys.stderr)
        return 2

    config = RepodoctorConfig.load(args.config)

    # Apply CLI overrides.
    if args.offline:
        config.offline = True
    if args.exclude:
        config.exclude.extend(args.exclude)
        for pattern in args.exclude:
            name = pattern.strip("/").replace("\\", "/").split("/")[-1]
            if name and name not in config.exclude_dirs:
                config.exclude_dirs.append(name)
            config.exclude_files.append(pattern)

    progress = ProgressReporter(verbose=args.verbose, quiet=args.quiet)

    # Load plugins.
    extra_plugins: list[ScannerBase] = []
    if args.plugin:
        for plugin_spec in args.plugin:
            plugin = _load_plugin(plugin_spec, config)
            if plugin is not None:
                extra_plugins.append(plugin)

    # Auto-discover installed/directory plugins.
    discovered: list = discover_plugins(config)
    for plugin in discovered:
        # Avoid duplicates by rule_id.
        if not any(p.rule_id == plugin.rule_id for p in extra_plugins):
            extra_plugins.append(cast(ScannerBase, plugin))

    report = run_scanners(config, root, progress, extra_plugins=extra_plugins)

    # --- Historical tracking -------------------------------------------
    use_history = True
    if args.no_history:
        use_history = False
    elif args.history is not None:
        use_history = args.history

    history_comparison: dict[str, Any] | None = None
    if use_history:
        store = HistoryStore(root)
        summary = build_summary(report)
        previous = store.load_previous()
        if previous is not None:
            history_comparison = compare(previous, summary)
        store.save(summary)

    reporter_cls = REPORTERS[args.format]
    reporter = reporter_cls()
    reporter.write(report, args.output, history_comparison=history_comparison)

    if not args.quiet and args.format == "text" and args.output is None:
        _print_history_summary(history_comparison)

    return compute_exit_code(report, args.fail_on)


def _load_plugin(spec: str, config: RepodoctorConfig) -> ScannerBase | None:
    """Load a plugin from a module name or file path."""
    path = Path(spec)
    if path.exists() and path.is_file() and path.suffix == ".py":
        from repodoctor.plugins import _load_plugin_module

        return cast(ScannerBase, _load_plugin_module(path, config))
    try:
        module = __import__(spec, fromlist=["create_plugin", "PLUGIN"])
    except ImportError:
        return None
    factory = getattr(module, "create_plugin", None)
    if factory is not None:
        try:
            return cast(ScannerBase, factory(config))
        except Exception:
            return None
    instance = getattr(module, "PLUGIN", None)
    return cast(ScannerBase, instance) if instance is not None else None


def _print_history_summary(comparison: dict[str, Any] | None) -> None:
    """Print a short history comparison to stdout after a text report."""
    if not comparison:
        return
    print("")
    print("--- Historical Health Tracking ---")
    print(f"Previous score: {comparison['previous_score']}/100")
    print(f"Current score:  {comparison['current_score']}/100")
    print(f"Trend: {comparison['trend']} (delta {comparison['score_delta']:+d})")
    if comparison["new_count"]:
        print(f"New findings: {comparison['new_count']}")
    if comparison["resolved_count"]:
        print(f"Resolved findings: {comparison['resolved_count']}")
    print("")


def cmd_init(args: argparse.Namespace) -> int:
    """Execute the init command."""
    import json

    config_path: Path = args.path
    if config_path.exists():
        print(f"Error: '{config_path}' already exists.", file=sys.stderr)
        return 1

    config = RepodoctorConfig()

    config_dict = {
        "severity_threshold": config.severity_threshold,
        "output_format": config.output_format,
        "exclude_dirs": config.exclude_dirs,
        "exclude_files": config.exclude_files,
        "exclude": config.exclude,
        "offline": config.offline,
        "max_file_size": config.max_file_size,
        "rules": config.rules,
        "rule_overrides": config.rule_overrides,
        "dependency_checks": config.dependency_checks,
        "github_security": config.github_security,
    }

    try:
        config_path.write_text(
            json.dumps(config_dict, indent=2) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        print(f"Error writing config: {exc}", file=sys.stderr)
        return 1

    print(f"Configuration written to {config_path}")
    return 0


def cmd_version() -> int:
    """Execute the version command."""
    print(f"repodoctor {__version__}")
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    if hasattr(sys.stdout, "reconfigure"):
        cast(Any, sys.stdout).reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        cast(Any, sys.stderr).reconfigure(encoding="utf-8", errors="replace")

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_rules:
        # Discover plugins for a complete listing.
        config = RepodoctorConfig()
        plugins = discover_plugins(config)
        print("Available rules:")
        for scanner_cls in SCANNERS:
            scanner = scanner_cls.__new__(scanner_cls)
            print(f"  {scanner.rule_id:30s} — {scanner.rule_name}")
        for plugin in plugins:
            print(f"  {plugin.rule_id:30s} — {plugin.rule_name} (plugin)")
        return 0

    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "init":
        return cmd_init(args)
    if args.command == "version":
        return cmd_version()

    # No subcommand given; show help and exit
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
