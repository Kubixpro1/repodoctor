"""Tests for configuration management."""

from __future__ import annotations

import json

from repodoctor.config import DEFAULT_CONFIG, RepodoctorConfig


def test_default_config():
    """Default config has expected values."""
    config = RepodoctorConfig()
    assert config.severity_threshold == "info"
    assert config.output_format == "text"
    assert ".git" in config.exclude_dirs
    assert config.rules["governance_files"] is True


def test_from_dict():
    """Building config from dict works."""
    data = {
        "severity_threshold": "high",
        "output_format": "json",
        "rules": {"governance_files": False},
    }
    config = RepodoctorConfig.from_dict(data)
    assert config.severity_threshold == "high"
    assert config.output_format == "json"
    assert config.rules["governance_files"] is False
    # Missing keys fall back to defaults
    assert config.rules["secrets"] is True


def test_load_from_file(tmp_path):
    """Loading config from a JSON file works."""
    config_path = tmp_path / "repodoctor.json"
    config_path.write_text(json.dumps({"severity_threshold": "medium", "output_format": "sarif"}))
    config = RepodoctorConfig.load(config_path)
    assert config.severity_threshold == "medium"
    assert config.output_format == "sarif"


def test_load_missing_file(tmp_path):
    """Loading config from missing file returns defaults."""
    missing = tmp_path / "nonexistent.json"
    config = RepodoctorConfig.load(missing)
    assert config.severity_threshold == DEFAULT_CONFIG["severity_threshold"]


def test_load_invalid_json(tmp_path):
    """Loading config from invalid JSON returns defaults."""
    bad_path = tmp_path / "bad.json"
    bad_path.write_text("{not valid json")
    config = RepodoctorConfig.load(bad_path)
    assert config.severity_threshold == DEFAULT_CONFIG["severity_threshold"]


def test_is_rule_enabled():
    """is_rule_enabled reflects the rules dict."""
    config = RepodoctorConfig(rules={"custom_rule": False})
    assert config.is_rule_enabled("custom_rule") is False
    assert config.is_rule_enabled("unknown_rule") is True  # default enabled


def test_config_missing_rule_keys_fall_back_to_defaults():
    """Config from a partial dict falls back to defaults for missing keys."""
    data = {"rules": {"governance_files": False}}
    config = RepodoctorConfig.from_dict(data)
    assert config.rules["governance_files"] is False
    assert config.rules["secrets"] is True
    assert config.rules["ci_cd"] is True
    assert config.rules["license"] is True
    assert config.rules["tests"] is True


def test_config_empty_dict_uses_all_defaults():
    """Config from an empty dict uses all defaults."""
    config = RepodoctorConfig.from_dict({})
    assert config.severity_threshold == "info"
    assert config.output_format == "text"
    assert ".git" in config.exclude_dirs
    assert config.rules["governance_files"] is True
    assert config.rules["secrets"] is True
