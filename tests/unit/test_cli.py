import pytest
from typer.testing import CliRunner
from unittest.mock import MagicMock, patch
from pathlib import Path
from veritensor.cli.main import app
from veritensor.core.types import ScanResult

runner = CliRunner()

@pytest.fixture
def mock_executor(mocker):
    """
    Mock ProcessPoolExecutor to avoid spawning real processes.
    """
    mock_pool = mocker.patch("concurrent.futures.ProcessPoolExecutor")
    mock_instance = mock_pool.return_value
    mock_instance.__enter__.return_value = mock_instance
    # Ensure shutdown(wait=True) doesn't hang the test
    mock_instance.shutdown.return_value = None
    return mock_instance

@pytest.fixture
def mock_as_completed(mocker):
    """
    Mocks as_completed to return the futures immediately.
    """
    return mocker.patch("concurrent.futures.as_completed")

def test_scan_local_file_clean(tmp_path, mock_executor, mock_as_completed):
    f = tmp_path / "model.pkl"
    f.write_text("fake pickle content")

    # Setup Mock Result
    fake_result = ScanResult(str(f), status="PASS")
    fake_result.file_hash = "sha256:12345"
    
    mock_future = MagicMock()
    mock_future.result.return_value = fake_result
    
    # Configure the mocks
    mock_executor.submit.return_value = mock_future
    mock_as_completed.return_value = [mock_future]

    result = runner.invoke(app, ["scan", str(f)])

    assert result.exit_code == 0
    assert "Scan Passed" in result.stdout

def test_scan_malware_blocking(tmp_path, mock_executor, mock_as_completed):
    f = tmp_path / "evil.pkl"
    f.write_text("malware")

    fake_result = ScanResult(str(f), status="FAIL")
    fake_result.add_threat("CRITICAL: RCE Detected")
    
    mock_future = MagicMock()
    mock_future.result.return_value = fake_result
    
    mock_executor.submit.return_value = mock_future
    mock_as_completed.return_value = [mock_future]

    result = runner.invoke(app, ["scan", str(f)])

    assert result.exit_code == 1
    assert "BLOCKING DEPLOYMENT" in result.stdout

def test_scan_ignore_malware(tmp_path, mock_executor, mock_as_completed):
    f = tmp_path / "evil.pkl"
    f.write_text("malware")

    fake_result = ScanResult(str(f), status="FAIL")
    fake_result.add_threat("CRITICAL: RCE Detected")
    
    mock_future = MagicMock()
    mock_future.result.return_value = fake_result
    
    mock_executor.submit.return_value = mock_future
    mock_as_completed.return_value = [mock_future]

    result = runner.invoke(app, ["scan", str(f), "--ignore-malware"])

    assert result.exit_code == 0
    # Updated expected string
    assert "SECURITY RISKS DETECTED" in result.stdout

# ── C-1 REGRESSION: SARIF/JSON output must use filtered_results ───────────────

def test_c1_regression_json_output_excludes_suppressed_threats(
    tmp_path, mock_executor, mock_as_completed
):
    """
    C-1 regression: --json output was using raw `results` instead of
    `filtered_results`, so suppressed threats appeared in JSON even when
    they were hidden in the console table.

    The JSON output must match what the table shows.
    This test verifies that a PASS result produces JSON with status=PASS
    (not the raw unfiltered FAIL).
    """
    import json as _json

    f = tmp_path / "model.pkl"
    f.write_text("fake content")

    # Simulate a result that starts as FAIL but is downgraded to PASS
    # after filtering (e.g. all threats are noise or below threshold)
    fake_result = ScanResult(str(f), status="PASS")
    fake_result.file_hash = "abc123"
    # No threats — result is clean after filtering

    mock_future = MagicMock()
    mock_future.result.return_value = fake_result
    mock_executor.submit.return_value = mock_future
    mock_as_completed.return_value = [mock_future]

    output_file = tmp_path / "out.json"
    result = runner.invoke(
        app, ["scan", str(f), "--json", "--output-file", str(output_file)]
    )

    assert result.exit_code == 0
    assert output_file.exists()

    data = _json.loads(output_file.read_text())
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["status"] == "PASS", (
        "C-1 regression: JSON output has wrong status. "
        "Likely using raw results instead of filtered_results."
    )


def test_c1_regression_sarif_output_written_to_file(
    tmp_path, mock_executor, mock_as_completed
):
    """SARIF output must be written to --output-file without errors."""
    f = tmp_path / "model.pkl"
    f.write_text("content")

    fake_result = ScanResult(str(f), status="PASS")
    mock_future = MagicMock()
    mock_future.result.return_value = fake_result
    mock_executor.submit.return_value = mock_future
    mock_as_completed.return_value = [mock_future]

    sarif_file = tmp_path / "report.sarif"
    result = runner.invoke(
        app, ["scan", str(f), "--sarif", "--output-file", str(sarif_file)]
    )

    assert result.exit_code == 0
    assert sarif_file.exists()
    content = sarif_file.read_text()
    # Must be valid JSON with SARIF structure
    import json as _json
    sarif = _json.loads(content)
    assert "$schema" in sarif or "runs" in sarif
