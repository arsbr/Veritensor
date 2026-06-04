import pytest
import json
from unittest.mock import patch
from pathlib import Path
from veritensor.engines.data.dataset_engine import scan_dataset

# Optional dependencies check
pd = pytest.importorskip("pandas") 
pa = pytest.importorskip("pyarrow")
pq = pytest.importorskip("pyarrow.parquet")

# --- CONSTANTS FOR TESTING ---
# Valid length AWS Key (AKIA + 16 chars = 20 chars total)
FAKE_AWS_KEY = "AKIA0000000000000000" 

# Mocked signatures to ensure tests pass regardless of external yaml files
MOCKED_SUSPICIOUS = [
    "regex:AKIA[0-9A-Z]{16}", 
    "regex:https?://\\S+\\.exe"
]
MOCKED_INJECTIONS = [
    "Ignore previous instructions"
]

@pytest.fixture
def temp_data_dir(tmp_path):
    d = tmp_path / "data"
    d.mkdir()
    return d

# --- MOCKING SIGNATURES FOR ALL TESTS ---
@pytest.fixture(autouse=True)
def mock_signatures():
    with patch("veritensor.engines.static.rules.SignatureLoader.get_suspicious_strings", return_value=MOCKED_SUSPICIOUS), \
         patch("veritensor.engines.static.rules.SignatureLoader.get_prompt_injections", return_value=MOCKED_INJECTIONS):
        yield

def test_scan_csv_with_threats(temp_data_dir):
    # Test: Finding the secret in CSV
    csv_file = temp_data_dir / "test.csv"
    csv_file.write_text(f"id,text\n1,SAFE\n2,https://evil.exe\n3,{FAKE_AWS_KEY}")
    
    # CRITICAL FIX: Unpack the tuple (threats, bias_data)
    threats, _ = scan_dataset(csv_file)
    assert any("Malicious URL" in t for t in threats)
    assert any("Secret/PII" in t for t in threats)

def test_scan_jsonl_deep_nesting(temp_data_dir):
    """Test: Recursion protection (deep JSON) without hitting json.dumps limits."""
    jsonl_file = temp_data_dir / "deep.jsonl"
    
    # CRITICAL FIX: Generate deep JSON string manually to bypass json.dumps recursion limit
    depth = 1000
    deep_json_str = '{"data": ' + ('[' * depth) + '"SAFE"' + (']' * depth) + '}'
    
    with open(jsonl_file, "w", encoding="utf-8") as f:
        f.write(deep_json_str + "\n")
        
    # Run the scanner
    from veritensor.engines.data.dataset_engine import scan_dataset
    threats, bias_data = scan_dataset(jsonl_file)
    
    # The scanner should gracefully handle or skip it without crashing
    assert isinstance(threats, list)

def test_scan_jsonl_oversized_line(temp_data_dir):
    # Test: OOM protection (too long line)
    jsonl_file = temp_data_dir / "huge.jsonl"
    with open(jsonl_file, "w") as f:
        # The row is larger than 10MB (our MAX_JSON_LINE_SIZE limit)
        f.write("A" * (11 * 1024 * 1024) + "\n")
        # Use valid length key
        f.write(json.dumps({"text": FAKE_AWS_KEY}) + "\n")

    # CRITICAL FIX: Unpack the tuple
    threats, _ = scan_dataset(jsonl_file)
    # The first line should be skipped, the second one should be caught.
    assert any("Secret/PII" in t for t in threats)

def test_scan_parquet_column_pruning(temp_data_dir):
    # Test: Checking that Parquet scans only row columns
    pq_file = temp_data_dir / "test.parquet"
    df = pd.DataFrame({
        "numbers": [1, 2, 3],
        "safe_text": ["hello", "world", "fine"],
        "danger_text": ["https://evil.exe", "safe", "safe"]
    })
    df.to_parquet(pq_file)

    # CRITICAL FIX: Unpack the tuple
    threats, _ = scan_dataset(pq_file)
    assert any("Malicious URL" in t for t in threats)

def test_sampling_logic(temp_data_dir):
    # Test: Checking string constraints (Sampling)
    csv_file = temp_data_dir / "large.csv"
    with open(csv_file, "w") as f:
        f.write("text\n")
        for i in range(15000):
            # The secret is at the very end (line 14000)
            val = FAKE_AWS_KEY if i == 14000 else "safe"
            f.write(f"{val}\n")

    # With a normal scan (10k limit), the threat should NOT be found.
    # CRITICAL FIX: Unpack the tuple
    threats_quick, _ = scan_dataset(csv_file, full_scan=False)
    assert len(threats_quick) == 0

    # If full_scan=True, the threat MUST be found.
    # CRITICAL FIX: Unpack the tuple
    threats_full, _ = scan_dataset(csv_file, full_scan=True)
    assert len(threats_full) > 0
