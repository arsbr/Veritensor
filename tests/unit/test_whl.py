import pytest
import io
import zipfile
from veritensor.engines.static.pickle_engine import scan_pickle_stream

def test_scan_wheel_with_secrets():
    """
    Checks that the engine can scan a .whl (zip) file and find suspicious strings in setup.py.
    """
    # Create a fake setup.py with a secret
    setup_content = """
    import os
    # This is a bad idea
    AWS_SECRET_ACCESS_KEY = "AKIA..."
    """
    
    # Pack into Zip (Wheel)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as z:
        z.writestr("setup.py", setup_content)
        z.writestr("veritensor/__init__.py", "print('hello')")
    
    zip_bytes = buffer.getvalue()

    # Scan
    threats = scan_pickle_stream(zip_bytes)
    
    # Verify detection
    assert len(threats) > 0
    assert any("AWS_SECRET_ACCESS_KEY" in t for t in threats)
