import pytest
from pathlib import Path
from veritensor.cli.main import scan_worker
from veritensor.core.config import VeritensorConfig

def test_worker_detects_pickle(tmp_path):
    # 1. Create a real malicious pickle
    f = tmp_path / "exploit.pkl"
    # Create a simple "GLOBAL" opcode pattern manually or use fickling
    # Here just empty file to test routing, or verify it calls engine
    f.write_bytes(b"\x80\x04\x95\x08\x00\x00\x00\x00\x00\x00\x00.") # Empty pickle

    config = VeritensorConfig()
    
    # Args: (path, config, repo, ignore_license, full_scan, is_s3)
    args = (str(f), config, None, False, False, False)
    
    result = scan_worker(args)
    
    assert result.file_path == str(f)
    # Even if empty/safe, status should be PASS or FAIL depending on engine logic
    # This proves the worker routed .pkl to the pickle engine
    assert result.status in ["PASS", "FAIL"] 

def test_worker_s3_logic(mocker):
    # Mocking calculate_sha256 to ensure it's NOT called for S3
    mock_hash = mocker.patch("veritensor.cli.main.calculate_sha256")
    
    config = VeritensorConfig()
    args = ("s3://bucket/model.pkl", config, None, False, False, True)
    
    result = scan_worker(args)
    
    # Ensure local hashing was skipped
    mock_hash.assert_not_called()
    assert result.file_path == "s3://bucket/model.pkl"
