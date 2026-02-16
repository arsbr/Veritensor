import pytest
import zipfile
from veritensor.engines.container.archive_engine import scan_archive

def test_zip_with_malware(tmp_path):
    f = tmp_path / "malware.zip"
    with zipfile.ZipFile(f, 'w') as z:
        z.writestr("payload.exe", "MZ...")
        z.writestr("readme.txt", "hello")
        
    threats = scan_archive(f)
    assert any("Executable found" in t and "payload.exe" in t for t in threats)
