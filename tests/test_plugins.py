"""Tests for the plugin architecture."""

from __future__ import annotations

import tempfile
from pathlib import Path

from repodoctor.config import RepodoctorConfig
from repodoctor.plugins import (
    ScannerPlugin,
    discover_plugins,
    load_directory_plugins,
)


class MyPlugin(ScannerPlugin):
    rule_id = "my_plugin"
    rule_name = "My Plugin"

    def _scan(self, root: Path):  # noqa: ARG002
        from repodoctor.rules import RuleResult

        result = RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            enabled=True,
            passed=True,
        )
        return result


def test_plugin_interface_instantiation():
    plugin = MyPlugin(RepodoctorConfig())
    assert plugin.rule_id == "my_plugin"
    assert plugin.rule_name == "My Plugin"
    assert plugin.is_enabled() is True


def test_load_directory_plugins_picks_up_create_plugin_factory():
    with tempfile.TemporaryDirectory() as d:
        plugin_dir = Path(d)
        module = plugin_dir / "my_plugin_mod.py"
        module.write_text(
            "from repodoctor.plugins import ScannerPlugin\n"
            "from repodoctor.config import RepodoctorConfig\n"
            "\n"
            "class P(ScannerPlugin):\n"
            "    rule_id = 'factory_plugin'\n"
            "    rule_name = 'Factory Plugin'\n"
            "    def _scan(self, root):\n"
            "        from repodoctor.rules import RuleResult\n"
            "        return RuleResult(rule_id=self.rule_id, rule_name=self.rule_name, enabled=True, passed=True)\n"
            "\n"
            "def create_plugin(config):\n"
            "    return P(config)\n"
        )
        plugins = load_directory_plugins(RepodoctorConfig(), [plugin_dir])
        ids = {p.rule_id for p in plugins}
        assert "factory_plugin" in ids


def test_discover_plugins_returns_list():
    plugins = discover_plugins(RepodoctorConfig())
    assert isinstance(plugins, list)
