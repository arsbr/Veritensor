from typer.testing import CliRunner
from veritensor.cli.main import app

runner = CliRunner()

def test_cli_scan_clean(clean_model_path):
    result = runner.invoke(app, ["scan", str(clean_model_path)])
    assert result.exit_code == 0
    assert "Scan Passed" in result.stdout

def test_cli_scan_infected(infected_pickle_path):
    result = runner.invoke(app, ["scan", str(infected_pickle_path)])
    assert result.exit_code == 1
    assert "BLOCKING DEPLOYMENT" in result.stdout

def test_cli_ignore_malware(infected_pickle_path):
    # Test new flag
    result = runner.invoke(app, ["scan", str(infected_pickle_path), "--ignore-malware"])
    assert result.exit_code == 0
    assert "MALWARE/INTEGRITY RISKS DETECTED (Ignored by user)" in result.stdout
