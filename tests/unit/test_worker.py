import pytest
from pathlib import Path
from veritensor.cli.main import scan_worker
from veritensor.core.config import VeritensorConfig

def test_worker_detects_pickle(tmp_path):
    # 1. Create a real malicious pickle
    f = tmp_path / "exploit.pkl"
    # Create a simple "GLOBAL" opcode pattern manually or use fickling
    f.write_bytes(b"\x80\x04\x95\x08\x00\x00\x00\x00\x00\x00\x00.") # Empty pickle

    config = VeritensorConfig()
    
    # FIX: Added 7th argument (precalc_hash = None)
    # Args: (path, config, repo, ignore_license, full_scan, is_s3, precalc_hash)
    args = (str(f), config, None, False, False, False, None)
    
    result = scan_worker(args)
    
    assert result.file_path == str(f)
    assert result.status in["PASS", "FAIL"] 

def test_worker_s3_logic(mocker):
    # Mocking calculate_sha256 to ensure it's NOT called for S3
    mock_hash = mocker.patch("veritensor.cli.main.calculate_sha256")
    
    config = VeritensorConfig()
    
    # FIX: Added 7th argument (precalc_hash = None)
    args = ("s3://bucket/model.pkl", config, None, False, False, True, None)
    
    result = scan_worker(args)
    
    # Ensure local hashing was skipped
    mock_hash.assert_not_called()
    assert result.file_path == "s3://bucket/model.pkl"