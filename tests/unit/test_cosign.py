import pytest
from unittest.mock import patch, MagicMock
from veritensor.integrations.cosign import sign_container

@patch("veritensor.integrations.cosign.subprocess.run")
@patch("veritensor.integrations.cosign.is_cosign_available", return_value=True)
@patch("pathlib.Path.exists", return_value=True)
def test_sign_container_success(mock_exists, mock_avail, mock_run):
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = "Signed successfully"
    mock_run.return_value = mock_proc

    # Test with annotations
    annotations = {
        "scanned_by": "veritensor",
        "status": "clean",
        "scan_date": "2025-01-01T12:00:00Z"
    }

    result = sign_container("my-image:v1", "key.pem", annotations=annotations)
    
    assert result is True
    
    # Check arguments
    args = mock_run.call_args[0][0]
    assert "cosign" in args
    assert "sign" in args
    # Verify annotations are passed correctly
    assert "-a" in args
    assert "scanned_by=veritensor" in args
    assert "status=clean" in args
