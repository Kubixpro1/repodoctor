"""Tests for the dependency parser."""

from __future__ import annotations

from pathlib import Path

from repodoctor.dependency_parser import (
    DependencyInventory,
    find_version_conflicts,
    parse_all_manifests,
    parse_cargo_lock,
    parse_cargo_toml,
    parse_go_mod,
    parse_go_sum,
    parse_package_json,
    parse_package_lock_json,
    parse_pipfile,
    parse_pyproject_toml,
    parse_requirements_txt,
    parse_yarn_lock,
)


def test_parse_requirements_txt():
    import tempfile

    d = Path(tempfile.mkdtemp())
    p = d / "requirements.txt"
    p.write_text("requests==2.28.1\nflask>=2.0\n# comment\n-r other.txt\npackage[extra]==1.0\n")
    deps = parse_requirements_txt(p)
    names = {dep.name for dep in deps}
    assert "requests" in names
    assert "flask" in names
    assert "package" in names
    req = next(x for x in deps if x.name == "requests")
    assert req.version == "==2.28.1"


def test_parse_pyproject_toml():
    import tempfile

    d = Path(tempfile.mkdtemp())
    p = d / "pyproject.toml"
    p.write_text(
        '[project]\nname = "x"\ndependencies = ["requests==2.28.1", "flask"]\n'
        '[tool.poetry.dependencies]\npython = "^3.9"\npoetry-core = "1.0"\n'
    )
    deps = parse_pyproject_toml(p)
    names = {dep.name for dep in deps}
    assert "requests" in names
    assert "flask" in names
    assert "poetry-core" in names
    assert "python" not in names


def test_parse_pipfile():
    import tempfile

    d = Path(tempfile.mkdtemp())
    p = d / "Pipfile"
    p.write_text('[packages]\nrequests = "==2.28.1"\n[dev-packages]\npytest = "*"\n')
    deps = parse_pipfile(p)
    names = {dep.name for dep in deps}
    assert "requests" in names
    assert "pytest" in names


def test_parse_package_json():
    import json
    import tempfile

    d = Path(tempfile.mkdtemp())
    p = d / "package.json"
    p.write_text(
        json.dumps(
            {
                "dependencies": {"lodash": "^4.17.21"},
                "devDependencies": {"jest": "^29.0.0"},
            }
        )
    )
    deps = parse_package_json(p)
    names = {dep.name for dep in deps}
    assert "lodash" in names
    assert "jest" in names


def test_parse_package_lock_json():
    import json
    import tempfile

    d = Path(tempfile.mkdtemp())
    p = d / "package-lock.json"
    p.write_text(
        json.dumps(
            {
                "dependencies": {"lodash": {"version": "4.17.21"}},
                "packages": {
                    "node_modules/querystring": {"version": "0.2.0"},
                },
            }
        )
    )
    deps = parse_package_lock_json(p)
    names = {dep.name for dep in deps}
    assert "lodash" in names
    assert "querystring" in names


def test_parse_yarn_lock():
    import tempfile

    d = Path(tempfile.mkdtemp())
    p = d / "yarn.lock"
    p.write_text('"lodash@4.17.21":\n  version "4.17.21"\n  resolved "https://..."\n')
    deps = parse_yarn_lock(p)
    names = {dep.name for dep in deps}
    assert "lodash" in names


def test_parse_cargo_toml_and_lock():
    import tempfile

    d = Path(tempfile.mkdtemp())
    p = d / "Cargo.toml"
    p.write_text('[dependencies]\nserde = "1.0"\n[dev-dependencies]\ncriterion = "0.3"\n')
    deps = parse_cargo_toml(p)
    names = {dep.name for dep in deps}
    assert "serde" in names
    assert "criterion" in names

    lock_file = d / "Cargo.lock"
    lock_file.write_text(
        '[[package]]\nname = "serde"\nversion = "1.0.193"\n'
        '[[package]]\nname = "criterion"\nversion = "0.3.5"\n'
    )
    lock_deps = parse_cargo_lock(lock_file)
    lock_names = {dep.name for dep in lock_deps}
    assert "serde" in lock_names
    assert "criterion" in lock_names


def test_parse_go_mod_and_sum():
    import tempfile

    d = Path(tempfile.mkdtemp())
    p = d / "go.mod"
    p.write_text("module example.com/m\nrequire github.com/foo/bar v1.2.3\n")
    deps = parse_go_mod(p)
    assert any(dep.name == "github.com/foo/bar" for dep in deps)

    s = d / "go.sum"
    s.write_text("github.com/foo/bar v1.2.3 h1:abc\n")
    sum_deps = parse_go_sum(s)
    assert any(dep.name == "github.com/foo/bar" for dep in sum_deps)


def test_parse_all_manifests_missing_lockfile():
    import tempfile

    d = Path(tempfile.mkdtemp())
    (d / "package.json").write_text('{"dependencies": {}}\n')
    inventory = parse_all_manifests(d)
    assert any("package.json" in m for m in inventory.missing_lockfiles)
    assert len(inventory.dependencies) >= 0


def test_find_version_conflicts():
    inventory = DependencyInventory()
    inventory.dependencies = [
        Dependency("pkg", "1.0", Path("a.txt"), declared=True),
        Dependency("pkg", "2.0", Path("b.txt"), declared=True),
        Dependency("other", "1.0", Path("c.txt"), declared=True),
    ]
    conflicts = find_version_conflicts(inventory)
    assert len(conflicts) == 1
    assert conflicts[0]["package"] == "pkg"
    assert "1.0" in conflicts[0]["versions"]
    assert "2.0" in conflicts[0]["versions"]


# Small local helper to avoid top-level import cost in tests.
from repodoctor.dependency_parser import Dependency  # noqa: E402
