import os
import pytest
from pathlib import Path
from unittest.mock import patch
from veritensor.core.config import ConfigLoader, VeritensorConfig

@pytest.fixture(autouse=True)
def reset_singleton():
    ConfigLoader.reset()
    yield
    ConfigLoader.reset()

def test_default_config_loads_without_yaml(tmp_path):
    # Pass path directly, expect HIGH instead of CRITICAL
    config = ConfigLoader.load(tmp_path / "nonexistent.yaml")
    assert config.fail_on_severity == "CRITICAL"
    assert config.fail_on_missing_license is False
    assert config.allowed_modules == []

def test_yaml_overrides_defaults(tmp_path):
    yaml_content = """
fail_on_severity: CRITICAL
fail_on_missing_license: true
custom_restricted_licenses:
  - cc-by-nc
  - agpl-3.0
allowed_modules:
  - my_custom_lib
"""
    yaml_path = tmp_path / "veritensor.yaml"
    yaml_path.write_text(yaml_content)

    # Pass path directly to load()
    config = ConfigLoader.load(yaml_path)

    assert config.fail_on_severity == "CRITICAL"
    assert config.fail_on_missing_license is True
    assert "cc-by-nc" in config.custom_restricted_licenses
    assert "my_custom_lib" in config.allowed_modules

def test_invalid_yaml_falls_back_to_defaults(tmp_path):
    yaml_path = tmp_path / "veritensor.yaml"
    yaml_path.write_text("fail_on_severity: [INVALID YAML\n\t\x00\x01")

    config = ConfigLoader.load(yaml_path)
    assert isinstance(config, VeritensorConfig)
    # Expect CRITICAL default
    assert config.fail_on_severity == "CRITICAL"

def test_env_hf_token_overrides_yaml(tmp_path):
    yaml_path = tmp_path / "veritensor.yaml"
    yaml_path.write_text("hf_token: from_yaml")

    env = {"VERITENSOR_HF_TOKEN": "from_env_token"}
    with patch.dict(os.environ, env, clear=False):
        config = ConfigLoader.load(yaml_path)
    assert config.hf_token == "from_env_token"

def test_env_fail_on_severity_overrides(tmp_path):
    env = {"VERITENSOR_FAIL_ON": "MEDIUM"}
    with patch.dict(os.environ, env, clear=False):
        config = ConfigLoader.load(tmp_path / "nonexistent.yaml")
    assert config.fail_on_severity == "MEDIUM"

def test_reset_clears_singleton(tmp_path):
    yaml_path = tmp_path / "veritensor.yaml"
    yaml_path.write_text("fail_on_severity: HIGH")

    config1 = ConfigLoader.load(yaml_path)
    assert config1.fail_on_severity == "HIGH"

    ConfigLoader.reset()

    yaml_path.write_text("fail_on_severity: MEDIUM")
    config2 = ConfigLoader.load(yaml_path)

    assert config2.fail_on_severity == "MEDIUM"
    assert config1 is not config2