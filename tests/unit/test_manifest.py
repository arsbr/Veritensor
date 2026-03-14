import pytest
import json
import os
from veritensor.core.types import ScanResult
from veritensor.reporting.manifest import generate_manifest

def test_manifest_generation(tmp_path):
    # 1. Prepare dummy results
    r1 = ScanResult("model.pkl", status="FAIL", file_hash="sha256:123")
    r1.add_threat("CRITICAL: Malware")
    
    r2 = ScanResult("data.csv", status="PASS", file_hash="sha256:456")
    
    # 2. Generate
    output_file = tmp_path / "manifest.json"
    generate_manifest([r1, r2], str(output_file))
    
    # 3. Verify
    assert output_file.exists()
    
    with open(output_file) as f:
        data = json.load(f)
        
    assert data["summary"]["total_files"] == 2
    assert data["summary"]["failed"] == 1
    assert data["artifacts"][0]["path"] == "model.pkl"
    assert data["artifacts"][0]["threats"][0] == "CRITICAL: Malware"
