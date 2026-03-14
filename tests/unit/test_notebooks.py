import pytest
import json
from unittest.mock import patch
from veritensor.engines.static.notebook_engine import scan_notebook

MOCKED_SUSPICIOUS = ["AWS_ACCESS_KEY_ID"]
MOCKED_INJECTIONS = ["Ignore previous instructions"]

@pytest.fixture(autouse=True)
def mock_signatures():
    with patch("veritensor.engines.static.rules.SignatureLoader.get_suspicious_strings", return_value=MOCKED_SUSPICIOUS), \
         patch("veritensor.engines.static.rules.SignatureLoader.get_prompt_injections", return_value=MOCKED_INJECTIONS):
        yield

def create_dummy_notebook(path, cells):
    """Helper to create a .ipynb file for testing."""
    content = {
        "cells": cells,
        "metadata": {},
        "nbformat": 4,
        "nbformat_minor": 5
    }
    with open(path, "w") as f:
        json.dump(content, f)

def test_notebook_clean(tmp_path):
    """Test a safe notebook."""
    f = tmp_path / "clean.ipynb"
    cells = [
        {
            "cell_type": "code",
            "source": ["print('Hello World')"],
            "outputs": []
        }
    ]
    create_dummy_notebook(f, cells)
    
    threats = scan_notebook(f)
    assert len(threats) == 0

def test_notebook_magic_injection(tmp_path):
    """Test detection of shell injection via magic commands."""
    f = tmp_path / "magic.ipynb"
    cells = [
        {
            "cell_type": "code",
            "source": ["!rm -rf / # Evil command"],
            "outputs": []
        }
    ]
    create_dummy_notebook(f, cells)
    
    threats = scan_notebook(f)
    assert len(threats) > 0
    # Ищем угрозу в списке
    assert any("Jupyter Magic" in t for t in threats)

def test_notebook_secret_in_output(tmp_path):
    """Test detection of leaked secrets in cell outputs."""
    f = tmp_path / "leaked_key.ipynb"
    cells = [
        {
            "cell_type": "code",
            "source": ["print('oops')"],
            "outputs": [
                {
                    "name": "stdout",
                    "output_type": "stream",
                    "text": ["AWS_ACCESS_KEY_ID=AKIA1234567890"]
                }
            ]
        }
    ]
    create_dummy_notebook(f, cells)
    
    threats = scan_notebook(f)
    # With the mock above, it will pass.
    assert len(threats) > 0
    assert any("Leaked secret" in t for t in threats)

def test_notebook_malicious_import(tmp_path):
    """Test detection of malicious imports via AST."""
    f = tmp_path / "malware.ipynb"
    cells = [
        {
            "cell_type": "code",
            "source": ["import os\n", "os.system('hack')"],
            "outputs": []
        }
    ]
    create_dummy_notebook(f, cells)
    
    threats = scan_notebook(f)
    assert len(threats) > 0
    
    found_import = any("Unsafe import" in t and "'os'" in t for t in threats)
    found_call = any("os.system" in t for t in threats)
    
    assert found_import or found_call, f"Threats found: {threats}"
