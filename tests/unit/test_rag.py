import pytest
from veritensor.engines.content.injection import scan_text_file

def test_rag_injection_detection(infected_text_path):
    """
    Checks that the scanner finds a prompt injection in a text file.
    The fixture infected_text_path is taken from conftest.py
    """
    threats = scan_text_file(infected_text_path)
    
    assert len(threats) > 0
    # We check that the signature has been triggered
    assert any("Ignore previous instructions" in t for t in threats)
    assert any("HIGH" in t for t in threats)

def test_rag_clean_file(tmp_path):
    """Checks that plain text does not cause false positives.."""
    clean_file = tmp_path / "safe.txt"
    clean_file.write_text("Hello world, this is a safe document.")
    
    threats = scan_text_file(clean_file)
    assert len(threats) == 0
