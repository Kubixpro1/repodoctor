"""Dependency manifest and lockfile parsers.

Parses dependency files for Python, Node.js, Rust, Go, and .NET to build a
dependency inventory. All parsers are best-effort: malformed manifests are
skipped gracefully and never crash a scan.

No network access is performed here. Version comparison (outdated detection)
and vulnerability lookup live in :mod:`repodoctor.scanners.deps`.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

try:  # Python 3.11+
    import tomllib as _TOMLLIB  # type: ignore[import-not-found]  # noqa: N812
except ModuleNotFoundError:  # pragma: no cover - older Python
    _TOMLLIB = None

try:
    import tomli as _TOMLI  # type: ignore[import-not-found]  # noqa: N812
except ModuleNotFoundError:  # pragma: no cover - tomli not installed
    _TOMLI = None


@dataclass
class Dependency:
    """A single dependency entry."""

    name: str
    version: str | None = None
    source_file: Path | None = None
    declared: bool = True
    """True if declared in a manifest; False if resolved from a lockfile."""
    transitive: bool = False
    """True if the dependency is transitive (only present in a lockfile)."""
    dev: bool = False
    """True if it is a development-only dependency."""
    license: str | None = None
    """SPDX license identifier, if known."""
    dependency_type: str = "runtime"


@dataclass
class DependencyInventory:
    """The full set of dependencies discovered in a repository."""

    dependencies: list[Dependency] = field(default_factory=list)
    manifest_files: list[Path] = field(default_factory=list)
    lock_files: list[Path] = field(default_factory=list)
    missing_lockfiles: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def by_name(self) -> dict[str, list[Dependency]]:
        """Group dependencies by normalized name."""
        grouped: dict[str, list[Dependency]] = {}
        for dep in self.dependencies:
            grouped.setdefault(dep.name.lower(), []).append(dep)
        return grouped

    def declared_only(self) -> list[Dependency]:
        return [d for d in self.dependencies if d.declared and not d.transitive]

    def resolved_only(self) -> list[Dependency]:
        return [d for d in self.dependencies if not d.declared]


# ---------------------------------------------------------------------------
# TOML parsing (stdlib tomllib on 3.11+, with fallbacks)
# ---------------------------------------------------------------------------


def _parse_toml(text: str) -> dict[str, Any]:
    """Parse TOML text, with fallbacks for older Python versions."""
    if _TOMLLIB is not None:
        return _TOMLLIB.loads(text)  # type: ignore[no-any-return]
    if _TOMLI is not None:
        return _TOMLI.loads(text)  # type: ignore[no-any-return]
    return _simple_toml_parse(text)
    return _simple_toml_parse(text)


def _simple_toml_parse(text: str) -> dict[str, Any]:
    """Very small TOML subset parser used as a last resort.

    Handles ``[table]`` headers, ``[[array_of_tables]]`` headers, and
    ``key = "value"`` / ``key = value`` lines. Enough to extract dependency
    declarations from pyproject.toml, Pipfile and Cargo.lock.
    """
    root: dict[str, Any] = {}
    table: list[str] = []
    array_table: list[str] | None = None

    def _ensure_table(parts: list[str]) -> dict[str, Any]:
        cur: dict[str, Any] = root
        for part in parts:
            cur = cur.setdefault(part, {})
            if not isinstance(cur, dict):
                cur = {}
        return cur

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[["):
            name = line[2:-2].strip()
            parts = name.split(".")
            array_table = parts
            arr = _ensure_table(parts[:-1]).setdefault(parts[-1], [])
            if not isinstance(arr, list):
                arr = []
            arr.append({})
            _ensure_table(parts)  # ensure the key exists as a list
            table = parts
        elif line.startswith("["):
            name = line[1:-1].strip()
            table = name.split(".")
            array_table = None
            _ensure_table(table)
        elif "=" in line and array_table is not None:
            key, _, value = line.partition("=")
            key = key.strip()
            value = _coerce(value.strip())
            # Append to the last array-of-tables entry.
            cur = _ensure_table(array_table)
            last = cur[array_table[-1]] if array_table[-1] in cur else {}
            if isinstance(cur.get(array_table[-1]), list):
                cur[array_table[-1]][-1][key] = value
            else:
                cur[array_table[-1]] = (
                    [last]
                    if not isinstance(cur.get(array_table[-1]), list)
                    else cur[array_table[-1]]
                )
                cur[array_table[-1]][-1][key] = value
        elif "=" in line:
            key, _, value = line.partition("=")
            key = key.strip()
            value = _coerce(value.strip())
            cur = _ensure_table(table)
            cur[key] = value
    return root


def _coerce(value: str) -> Any:
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]
    if value == "true":
        return True
    if value == "false":
        return False
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return value


# ---------------------------------------------------------------------------
# Python parsers
# ---------------------------------------------------------------------------


def parse_requirements_txt(path: Path) -> list[Dependency]:
    """Parse a ``requirements.txt`` (or ``requirements.in``) file."""
    deps: list[Dependency] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return deps

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # Strip inline comments and environment markers.
        line = re.split(r"\s+#", line, maxsplit=1)[0].strip()
        line = re.split(r";\s*", line, maxsplit=1)[0].strip()
        # Skip options like -r, -e, --index-url.
        if line.startswith("-") or line.startswith("http://") or line.startswith("https://"):
            continue
        # Normalize name and version.
        match = re.match(r"^([A-Za-z0-9_.\-]+)\s*(==|>=|<=|>|<|~=|!=)?\s*([^\s,]+)?", line)
        if not match:
            continue
        name = match.group(1)
        op = match.group(2) or ""
        version = match.group(3)
        if version and op:
            version = f"{op}{version}" if op else version
        elif version:
            version = version
        else:
            version = None
        # Strip extras like package[extra]==1.0
        name = re.sub(r"\[.*\]$", "", name)
        deps.append(
            Dependency(
                name=name,
                version=version,
                source_file=path,
                declared=True,
                license=None,
            )
        )
    return deps


def parse_pyproject_toml(path: Path) -> list[Dependency]:
    """Parse dependencies declared in ``pyproject.toml``."""
    deps: list[Dependency] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        data = _parse_toml(text)
    except OSError:
        return deps
    except Exception:
        return deps

    # [project] dependencies (PEP 621).
    project = data.get("project", {}) if isinstance(data, dict) else {}
    for entry in project.get("dependencies", []) or []:
        if isinstance(entry, str):
            deps.append(_parse_pep508_requirement(entry, path))

    # [tool.poetry.dependencies] / [tool.poetry.group.*.dependencies].
    tool = data.get("tool", {}) if isinstance(data, dict) else {}
    poetry = tool.get("poetry", {}) if isinstance(tool, dict) else {}
    for name, spec in (poetry.get("dependencies", {}) or {}).items():
        if name == "python":
            continue
        deps.append(_poetry_spec_to_dependency(name, spec, path, declared=True))

    groups = poetry.get("group", {}) if isinstance(poetry, dict) else {}
    for group in groups.values() if isinstance(groups, dict) else []:
        if not isinstance(group, dict):
            continue
        for name, spec in (group.get("dependencies", {}) or {}).items():
            deps.append(_poetry_spec_to_dependency(name, spec, path, declared=True))

    # [project.optional-dependencies].
    for extra, entries in (project.get("optional-dependencies", {}) or {}).items():
        for entry in entries or []:
            if isinstance(entry, str):
                dep = _parse_pep508_requirement(entry, path)
                dep.dev = True
                deps.append(dep)

    return deps


def _parse_pep508_requirement(entry: str, path: Path) -> Dependency:
    """Parse a PEP 508 requirement string like ``requests==2.28.1``."""
    entry = entry.strip()
    match = re.match(
        r"^([A-Za-z0-9_.\-]+)(?:\[.*?\])?\s*(==|>=|<=|>|<|~=|!=)?\s*([^\s,;]+)?",
        entry,
    )
    if match:
        name = match.group(1)
        version = match.group(3)
        if match.group(2) and version:
            version = f"{match.group(2)}{version}"
    else:
        name = entry
        version = None
    return Dependency(name=name, version=version, source_file=path, declared=True)


def _poetry_spec_to_dependency(name: str, spec: Any, path: Path, *, declared: bool) -> Dependency:
    """Convert a Poetry dependency specification to a Dependency."""
    version: str | None = None
    dev = False
    if isinstance(spec, str):
        version = spec if spec != "*" else None
    elif isinstance(spec, dict):
        version = spec.get("version")
        if version == "*":
            version = None
        dev = bool(spec.get("dev"))
    return Dependency(
        name=name,
        version=version,
        source_file=path,
        declared=declared,
        dev=dev,
    )


def parse_pipfile(path: Path) -> list[Dependency]:
    """Parse a Pipfile's ``[packages]`` and ``[dev-packages]``."""
    deps: list[Dependency] = []
    try:
        data = _parse_toml(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return deps
    except Exception:
        return deps

    for section, dev in (("packages", False), ("dev-packages", True)):
        for name, spec in (data.get(section, {}) or {}).items():
            version: str | None = None
            if isinstance(spec, str):
                version = spec if spec != "*" else None
            elif isinstance(spec, dict):
                version = spec.get("version")
                if version == "*":
                    version = None
            deps.append(
                Dependency(name=name, version=version, source_file=path, declared=True, dev=dev)
            )
    return deps


def parse_poetry_lock(path: Path) -> list[Dependency]:
    """Parse resolved package versions from ``poetry.lock``."""
    deps: list[Dependency] = []
    try:
        data = _parse_toml(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return deps
    except Exception:
        return deps

    packages = data.get("package", []) if isinstance(data, dict) else []
    for entry in packages or []:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        version = entry.get("version")
        if name:
            deps.append(
                Dependency(
                    name=name,
                    version=version,
                    source_file=path,
                    declared=False,
                    transitive=True,
                )
            )
    return deps


# ---------------------------------------------------------------------------
# Node.js parsers
# ---------------------------------------------------------------------------


def parse_package_json(path: Path) -> list[Dependency]:
    """Parse ``dependencies``/``devDependencies`` from ``package.json``."""
    deps: list[Dependency] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return deps
    if not isinstance(data, dict):
        return deps

    for section, dev in (
        ("dependencies", False),
        ("devDependencies", True),
        ("peerDependencies", False),
        ("optionalDependencies", False),
    ):
        for name, version in (data.get(section, {}) or {}).items():
            deps.append(
                Dependency(
                    name=name,
                    version=str(version),
                    source_file=path,
                    declared=True,
                    dev=dev,
                )
            )
    return deps


def parse_package_lock_json(path: Path) -> list[Dependency]:
    """Parse resolved versions from ``package-lock.json`` (npm v2/v3/v7+)."""
    deps: list[Dependency] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return deps
    if not isinstance(data, dict):
        return deps

    # npm v2/v3: top-level "dependencies" map.
    dependencies = data.get("dependencies", {}) or {}
    if isinstance(dependencies, dict):
        for name, info in dependencies.items():
            version = _extract_npm_version(info)
            deps.append(
                Dependency(
                    name=name, version=version, source_file=path, declared=False, transitive=True
                )
            )

    # npm v7+: "packages" map with "node_modules/<name>" keys.
    packages = data.get("packages", {}) or {}
    if isinstance(packages, dict):
        for key, info in packages.items():
            if key == "":
                continue
            name = key.rsplit("/", 1)[-1]
            version = _extract_npm_version(info)
            deps.append(
                Dependency(
                    name=name, version=version, source_file=path, declared=False, transitive=True
                )
            )
    return deps


def _extract_npm_version(info: Any) -> str | None:
    if isinstance(info, dict):
        return info.get("version")
    if isinstance(info, str):
        return info
    return None


def parse_yarn_lock(path: Path) -> list[Dependency]:
    """Parse resolved versions from ``yarn.lock`` (v1 format)."""
    deps: list[Dependency] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return deps

    # Pattern:
    #   "pkg@1.2.3":
    #     version "1.2.3"
    current: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Header line: <name>@<version>: or "<name>@<version>":
        m = re.match(r'^"?([A-Za-z0-9@_.\-/]+)@([^":\s]+)"?\s*:', stripped)
        if m:
            current = m.group(1)
            version = m.group(2)
            deps.append(
                Dependency(
                    name=current,
                    version=version,
                    source_file=path,
                    declared=False,
                    transitive=True,
                )
            )
            continue
        version_m = re.match(r'^version\s+"([^"]+)"', stripped)
        if version_m and current is not None:
            # Update the last entry's version if more precise.
            if deps and deps[-1].name == current:
                deps[-1].version = version_m.group(1)
            current = None
    return deps


def parse_pnpm_lock_yaml(path: Path) -> list[Dependency]:
    """Parse resolved versions from ``pnpm-lock.yaml`` (best-effort)."""
    deps: list[Dependency] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return deps

    try:
        import yaml  # type: ignore

        data = yaml.safe_load(text) or {}
    except ModuleNotFoundError:
        data = _simple_yaml_parse(text)

    if not isinstance(data, dict):
        return deps

    packages = data.get("packages", {}) or {}
    if isinstance(packages, dict):
        for key, info in packages.items():
            if not key.startswith("/"):
                continue
            name = key.rsplit("/", 1)[-1]
            version: str | None = None
            if isinstance(info, dict):
                resolution = info.get("resolution", {}) or {}
                version = resolution.get("version")
                if version is None:
                    version = info.get("version")
            elif isinstance(info, str):
                version = info
            deps.append(
                Dependency(
                    name=name, version=version, source_file=path, declared=False, transitive=True
                )
            )
    return deps


def _simple_yaml_parse(text: str) -> dict[str, Any]:
    """Tiny YAML subset parser for pnpm-lock.yaml fallback."""
    result: dict[str, Any] = {}
    return result  # pnpm-lock without PyYAML yields no resolved deps


# ---------------------------------------------------------------------------
# Rust parsers
# ---------------------------------------------------------------------------


def parse_cargo_toml(path: Path) -> list[Dependency]:
    """Parse ``[dependencies]`` from ``Cargo.toml``."""
    deps: list[Dependency] = []
    try:
        data = _parse_toml(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return deps
    except Exception:
        return deps

    for section, dev in (
        ("dependencies", False),
        ("dev-dependencies", True),
        ("build-dependencies", False),
    ):
        for name, spec in (data.get(section, {}) or {}).items():
            version: str | None = None
            if isinstance(spec, str):
                version = spec if spec != "*" else None
            elif isinstance(spec, dict):
                version = spec.get("version")
                if version == "*":
                    version = None
            deps.append(
                Dependency(name=name, version=version, source_file=path, declared=True, dev=dev)
            )
    return deps


def parse_cargo_lock(path: Path) -> list[Dependency]:
    """Parse resolved versions from ``Cargo.lock``."""
    deps: list[Dependency] = []
    try:
        data = _parse_toml(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return deps
    except Exception:
        return deps

    packages = data.get("package", []) if isinstance(data, dict) else []
    for entry in packages or []:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        version = entry.get("version")
        if name:
            deps.append(
                Dependency(
                    name=name,
                    version=version,
                    source_file=path,
                    declared=False,
                    transitive=True,
                )
            )
    return deps


# ---------------------------------------------------------------------------
# Go parsers
# ---------------------------------------------------------------------------


def parse_go_mod(path: Path) -> list[Dependency]:
    """Parse ``require`` directives from ``go.mod``."""
    deps: list[Dependency] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return deps

    # Single-line: require github.com/foo/bar v1.2.3
    for match in re.finditer(
        r"^\s*require\s+([A-Za-z0-9_.\-/]+)\s+(v?\d[\S]*)\s*$", text, re.MULTILINE
    ):
        deps.append(
            Dependency(
                name=match.group(1),
                version=match.group(2),
                source_file=path,
                declared=True,
            )
        )

    # Block form:
    # require (
    #   github.com/foo/bar v1.2.3
    # )
    in_block = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if in_block:
            m = re.match(r"^([A-Za-z0-9_.\-/]+)\s+(v?\d[\S]*)", line)
            if m:
                deps.append(
                    Dependency(
                        name=m.group(1),
                        version=m.group(2),
                        source_file=path,
                        declared=True,
                    )
                )
    return deps


def parse_go_sum(path: Path) -> list[Dependency]:
    """Parse resolved module versions from ``go.sum``."""
    deps: list[Dependency] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return deps

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        m = re.match(r"^([A-Za-z0-9_.\-/]+)\s+(v?\d[\S]*)\s", line)
        if m:
            deps.append(
                Dependency(
                    name=m.group(1),
                    version=m.group(2),
                    source_file=path,
                    declared=False,
                    transitive=True,
                )
            )
    return deps


# ---------------------------------------------------------------------------
# .NET parsers
# ---------------------------------------------------------------------------


def parse_csproj(path: Path) -> list[Dependency]:
    """Parse ``<PackageReference>`` entries from a ``.csproj`` file."""
    deps: list[Dependency] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return deps

    for m in re.finditer(r'<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"', text):
        deps.append(
            Dependency(
                name=m.group(1),
                version=m.group(2),
                source_file=path,
                declared=True,
            )
        )
    # Also handle Version attribute before Include.
    for m in re.finditer(r'<PackageReference\s+Version="([^"]+)"\s+Include="([^"]+)"', text):
        # Avoid duplicates if both patterns match (they won't, but be safe).
        name = m.group(2)
        version = m.group(1)
        if not any(d.name == name for d in deps):
            deps.append(Dependency(name=name, version=version, source_file=path, declared=True))
    return deps


def parse_packages_lock_json(path: Path) -> list[Dependency]:
    """Parse resolved versions from NuGet ``packages.lock.json``."""
    deps: list[Dependency] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return deps
    if not isinstance(data, dict):
        return deps

    dependencies = data.get("dependencies", {}) or {}
    if isinstance(dependencies, dict):
        for name, info in dependencies.items():
            version: str | None = None
            if isinstance(info, dict):
                version = info.get("resolved")
            elif isinstance(info, str):
                version = info
            deps.append(
                Dependency(
                    name=name, version=version, source_file=path, declared=False, transitive=True
                )
            )
    return deps


def parse_directory_packages_props(path: Path) -> list[Dependency]:
    """Parse central package versions from ``Directory.Packages.props``."""
    deps: list[Dependency] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return deps

    for m in re.finditer(r'<PackageVersion\s+Include="([^"]+)"\s+Version="([^"]+)"', text):
        deps.append(
            Dependency(
                name=m.group(1),
                version=m.group(2),
                source_file=path,
                declared=True,
            )
        )
    return deps


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

MANIFEST_PARSERS: dict[str, Callable] = {
    "requirements.txt": parse_requirements_txt,
    "requirements.in": parse_requirements_txt,
    "pyproject.toml": parse_pyproject_toml,
    "Pipfile": parse_pipfile,
    "poetry.lock": parse_poetry_lock,
    "package.json": parse_package_json,
    "package-lock.json": parse_package_lock_json,
    "yarn.lock": parse_yarn_lock,
    "pnpm-lock.yaml": parse_pnpm_lock_yaml,
    "Cargo.toml": parse_cargo_toml,
    "Cargo.lock": parse_cargo_lock,
    "go.mod": parse_go_mod,
    "go.sum": parse_go_sum,
    "packages.lock.json": parse_packages_lock_json,
    "Directory.Packages.props": parse_directory_packages_props,
}

LOCKFILES: frozenset[str] = frozenset(
    {
        "poetry.lock",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "Cargo.lock",
        "go.sum",
        "packages.lock.json",
    }
)

# Map manifest -> expected lockfile.
MANIFEST_TO_LOCKFILE: dict[str, str | None] = {
    "requirements.txt": None,  # no standard lockfile (pip doesn't create one)
    "requirements.in": None,
    "pyproject.toml": "poetry.lock",
    "Pipfile": "Pipfile.lock",
    "package.json": "package-lock.json",
    "Cargo.toml": "Cargo.lock",
    "go.mod": "go.sum",
    # .csproj: packages.lock.json is optional
}


def discover_manifest_files(root: Path) -> tuple[list[Path], list[Path]]:
    """Return (manifest_files, lock_files) present under *root*."""
    manifest_files: list[Path] = []
    lock_files: list[Path] = []
    for filename in sorted(MANIFEST_PARSERS):
        path = root / filename
        if path.is_file():
            if filename in LOCKFILES:
                lock_files.append(path)
            else:
                manifest_files.append(path)
    return manifest_files, lock_files


def parse_all_manifests(root: Path) -> DependencyInventory:
    """Parse every manifest/lockfile under *root* into an inventory."""
    inventory = DependencyInventory()
    manifest_files, lock_files = discover_manifest_files(root)
    inventory.manifest_files = manifest_files
    inventory.lock_files = lock_files

    for path in manifest_files:
        parser = MANIFEST_PARSERS[path.name]
        try:
            inventory.dependencies.extend(parser(path))
        except Exception as exc:  # pragma: no cover - defensive
            inventory.errors.append(f"{path}: {exc}")

    for path in lock_files:
        parser = MANIFEST_PARSERS[path.name]
        try:
            lock_deps = parser(path)
            # Mark lockfile-only deps as transitive/resolved.
            for dep in lock_deps:
                dep.declared = False
                dep.transitive = True
            inventory.dependencies.extend(lock_deps)
        except Exception as exc:  # pragma: no cover - defensive
            inventory.errors.append(f"{path}: {exc}")

    # Detect missing lockfiles.
    for manifest in manifest_files:
        expected = MANIFEST_TO_LOCKFILE.get(manifest.name)
        if expected and not (manifest.parent / expected).is_file():
            inventory.missing_lockfiles.append(str(manifest))

    # Deduplicate exact duplicates (name + version + source).
    seen: set[tuple[str, str | None, str]] = set()
    unique: list[Dependency] = []
    for dep in inventory.dependencies:
        key = (dep.name.lower(), dep.version, str(dep.source_file or ""))
        if key in seen:
            continue
        seen.add(key)
        unique.append(dep)
    inventory.dependencies = unique
    return inventory


def find_version_conflicts(inventory: DependencyInventory) -> list[dict[str, Any]]:
    """Find packages declared with multiple different versions.

    Returns a list of conflict descriptions, one per package name.
    """
    conflicts: list[dict[str, Any]] = []
    by_name: dict[str, list[Dependency]] = {}
    for dep in inventory.dependencies:
        by_name.setdefault(dep.name.lower(), []).append(dep)

    for name, deps in by_name.items():
        versions = {d.version for d in deps if d.version}
        if len(versions) > 1:
            conflicts.append(
                {
                    "package": name,
                    "versions": sorted(versions),
                    "sources": [
                        {
                            "file": str(d.source_file) if d.source_file else "",
                            "version": d.version,
                            "declared": d.declared,
                        }
                        for d in deps
                        if d.version
                    ],
                }
            )
    return conflicts
