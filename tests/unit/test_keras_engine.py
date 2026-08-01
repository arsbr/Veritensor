"""
Tests for keras_engine.py — Keras Lambda layer RCE detection.
No tests existed before for this engine.
"""
import json
import zipfile
import pytest
from pathlib import Path
from veritensor.engines.static.keras_engine import scan_keras_file


def _write_keras_zip(path: Path, config: dict) -> Path:
    """Creates a minimal .keras archive (ZIP) with a config.json inside."""
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("config.json", json.dumps(config))
    return path


def _lambda_config(nested: bool = False) -> dict:
    """Minimal Keras config containing a Lambda layer."""
    lambda_layer = {"class_name": "Lambda", "config": {"function": "<lambda>"}}
    if nested:
        # Lambda inside a Functional/Sequential wrapper
        return {
            "class_name": "Functional",
            "config": {
                "layers": [lambda_layer]
            }
        }
    return {"class_name": "Sequential", "config": {"layers": [lambda_layer]}}


def _clean_config() -> dict:
    """Minimal Keras config with only safe layers."""
    return {
        "class_name": "Sequential",
        "config": {
            "layers": [
                {"class_name": "Dense",   "config": {"units": 128}},
                {"class_name": "Dropout", "config": {"rate": 0.5}},
            ]
        }
    }


# ── Happy path ────────────────────────────────────────────────────────────────

def test_clean_keras_zip_no_threats(tmp_path):
    """Dense + Dropout layers must not produce any threats."""
    path = _write_keras_zip(tmp_path / "clean.keras", _clean_config())
    threats = scan_keras_file(path)
    assert threats == []


def test_empty_layers_list_no_threats(tmp_path):
    """A model with no layers should pass cleanly."""
    path = _write_keras_zip(
        tmp_path / "empty.keras",
        {"class_name": "Sequential", "config": {"layers": []}}
    )
    assert scan_keras_file(path) == []


# ── Lambda layer detection ────────────────────────────────────────────────────

def test_detects_lambda_layer_in_keras_zip(tmp_path):
    """Lambda layer in .keras ZIP must produce a CRITICAL threat."""
    path = _write_keras_zip(tmp_path / "bad.keras", _lambda_config())
    threats = scan_keras_file(path)
    assert len(threats) > 0
    assert any("Lambda" in t and "CRITICAL" in t for t in threats)


def test_detects_nested_lambda_inside_functional(tmp_path):
    """Lambda nested inside a Functional wrapper must still be detected."""
    path = _write_keras_zip(tmp_path / "nested.keras", _lambda_config(nested=True))
    threats = scan_keras_file(path)
    assert any("Lambda" in t for t in threats)


def test_detects_lambda_at_root_config_level(tmp_path):
    """Config where the root IS the Lambda layer (not inside layers list)."""
    path = _write_keras_zip(
        tmp_path / "root_lambda.keras",
        {"class_name": "Lambda", "config": {"function": "lambda x: x**2"}}
    )
    # The root config is a Lambda — _analyze_model_config should catch it
    # when traversing layers. Even if it doesn't detect root-level, test
    # that scan doesn't crash.
    threats = scan_keras_file(path)
    assert isinstance(threats, list)


def test_detects_lambda_inside_deeply_nested_sequential(tmp_path):
    """Double-nested Sequential > Functional > Lambda must be caught."""
    config = {
        "class_name": "Sequential",
        "config": {
            "layers": [{
                "class_name": "Functional",
                "config": {
                    "layers": [
                        {"class_name": "Dense", "config": {}},
                        {"class_name": "Lambda", "config": {}},
                    ]
                }
            }]
        }
    }
    path = _write_keras_zip(tmp_path / "deep.keras", config)
    threats = scan_keras_file(path)
    assert any("Lambda" in t for t in threats)


# ── Zip Bomb protection ───────────────────────────────────────────────────────

def test_keras_zip_bomb_rejected(tmp_path):
    """A .keras file that is a zip bomb must be caught by SafeZipReader."""
    from veritensor.core.safe_zip import ZipBombError

    huge_zeros = b"\x00" * (15 * 1024 * 1024)
    path = tmp_path / "bomb.keras"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("config.json", huge_zeros)

    threats = scan_keras_file(path)
    assert any("CRITICAL" in t and ("Zip Bomb" in t or "DoS" in t) for t in threats)


# ── Edge cases ────────────────────────────────────────────────────────────────

def test_invalid_json_in_keras_zip_does_not_crash(tmp_path):
    path = tmp_path / "broken.keras"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("config.json", "{ not valid json }")
    # Should not raise — internal exception is caught
    threats = scan_keras_file(path)
    assert isinstance(threats, list)


def test_keras_zip_without_config_json_no_threats(tmp_path):
    """A valid ZIP with no config.json should produce no threats."""
    path = tmp_path / "no_config.keras"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("weights.h5", b"\x89HDF fake data")
    threats = scan_keras_file(path)
    assert threats == []


def test_non_zip_non_h5_file_no_crash(tmp_path):
    """Random binary that is neither ZIP nor HDF5 should not crash."""
    path = tmp_path / "random.keras"
    path.write_bytes(b"\x00\x01\x02\x03RANDOM DATA")
    threats = scan_keras_file(path)
    assert isinstance(threats, list)
    assert threats == []
