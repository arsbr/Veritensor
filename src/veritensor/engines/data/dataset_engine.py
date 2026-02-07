# Copyright 2026 Veritensor Security Apache 2.0
# Dataset Scanner (Parquet, CSV, JSONL) for Data Poisoning & Malicious URLs

import logging
import json
import csv
import sys
from pathlib import Path
from typing import List, Generator, Optional, Any

from veritensor.engines.static.rules import SignatureLoader, is_match
from veritensor.engines.content.pii import PIIScanner

logger = logging.getLogger(__name__)

# Optional Imports (Lazy Loading)
try:
    import pyarrow.parquet as pq
    import pyarrow as pa
    PYARROW_AVAILABLE = True
except ImportError:
    PYARROW_AVAILABLE = False

# Config
MAX_ROWS_DEFAULT = 10_000  # Quick scan limit (Sampling)
CHUNK_SIZE = 1000          # Rows per batch
MAX_JSON_LINE_SIZE = 10 * 1024 * 1024 # 10MB limit for JSONL lines (DoS protection)

# FALLBACK PATTERNS 
FALLBACK_SUSPICIOUS = [
    "regex:https?://[\\w\\.-]+", # Basic URL
    "regex:(?i)malicious",
    "regex:(?i)eval\\(", 
    "regex:AKIA[0-9A-Z]{16}",     # AWS Key
    "regex:(?i)password",
    "regex:(?i)secret"
]

def scan_dataset(file_path: Path, full_scan: bool = False) -> List[str]:
    """
    Scans datasets for Malicious URLs, Prompt Injections, and Secrets.
    Supports: .parquet, .csv, .jsonl
    """
    ext = file_path.suffix.lower()
    threats = []
    
    # 1. Load Signatures
    injections = SignatureLoader.get_prompt_injections()
    
    try:
        suspicious = SignatureLoader.get_suspicious_strings()
    except AttributeError:
        suspicious = []
    
    if not suspicious: 
        suspicious = FALLBACK_SUSPICIOUS

    # 2. Setup Limit
    row_limit = None if full_scan else MAX_ROWS_DEFAULT
    
    try:
        # 3. Get Stream
        text_stream = None
        
        if ext == ".parquet":
            if not PYARROW_AVAILABLE:
                return ["WARNING: pyarrow not installed. Run 'pip install veritensor[data]'"]
            text_stream = _stream_parquet(file_path)
            
        elif ext in {".csv", ".tsv"}:
            text_stream = _stream_csv(file_path)
            
        elif ext in {".jsonl", ".ndjson", ".ldjson"}:
            text_stream = _stream_jsonl(file_path)
            
        else:
            return [] # Not a dataset

        # 4. Scan Loop
        row_count = 0
        pii_buffer = [] 
        
        for text_chunk in text_stream:
            if not text_chunk: continue
            
            # ReDoS protection
            scan_text = text_chunk if len(text_chunk) <= 4096 else text_chunk[:4096]

            # A. Prompt Injection (Fail Fast)
            for pat in injections:
                if is_match(scan_text, [pat]):
                    threats.append(f"HIGH: Data Poisoning (Injection) detected in {file_path.name}: '{pat}'")
                    return threats 

            # B. Malicious URLs / Secrets (Regex)
            for pat in suspicious:
                if is_match(scan_text, [pat]):
                    label = "Malicious URL" if "http" in pat or "://" in pat else "Secret/PII"
                    threats.append(f"MEDIUM: {label} detected in dataset {file_path.name}: '{pat}'")
            
            # C. Collect PII Sample 
            if len(pii_buffer) < 50:
                pii_buffer.append(scan_text)

            row_count += 1
            # Check limit here (Centralized control)
            if row_limit and row_count >= row_limit:
                break
        
        # 5. Run PII Scan on Sample
        if pii_buffer:
            combined_sample = "\n".join(pii_buffer)
            pii_threats = PIIScanner.scan(combined_sample)
            threats.extend(pii_threats)
                
    except Exception as e:
        logger.warning(f"Failed to scan dataset {file_path}: {e}")
        threats.append(f"WARNING: Dataset Scan Error: {str(e)}")

    return threats

# --- GENERATORS (Infinite streams, limit handled by caller) ---

def _stream_parquet(path: Path) -> Generator[str, None, None]:
    try:
        parquet_file = pq.ParquetFile(path)
    except Exception:
        return 

    str_columns = []
    for field in parquet_file.schema_arrow:
        if pa.types.is_string(field.type) or pa.types.is_large_string(field.type):
            str_columns.append(field.name)
            
    if not str_columns:
        return

    for batch in parquet_file.iter_batches(batch_size=CHUNK_SIZE, columns=str_columns):
        df = batch.to_pandas()
        for _, row in df.iterrows():
            # Convert row to single string
            text_values = " ".join(row.dropna().astype(str).tolist())
            yield text_values

def _stream_csv(path: Path) -> Generator[str, None, None]:
    ext = path.suffix.lower()
    sep = "\t" if ext == ".tsv" else ","
    
    try:
        import pandas as pd
        # Read in chunks without limit (limit handled by caller)
        chunks = pd.read_csv(
            path, sep=sep, chunksize=CHUNK_SIZE, 
            encoding="utf-8", on_bad_lines="skip", low_memory=True
        )
        
        for chunk in chunks:
            # Select object (string) columns only
            text_df = chunk.select_dtypes(include=['object'])
            for _, row in text_df.iterrows():
                text_val = " ".join(row.dropna().astype(str).tolist())
                yield text_val

    except ImportError:
        # Fallback to stdlib
        csv.field_size_limit(min(sys.maxsize, 2147483647))
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f, delimiter=sep)
            for row in reader:
                yield " ".join(row)
                
def _stream_jsonl(path: Path) -> Generator[str, None, None]:
    """Reads JSONL safely."""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        while True:
            line = f.readline()
            if not line:
                break
                
            # OOM Protection: Skip huge lines, do NOT yield, do NOT increment caller's count
            if len(line) > MAX_JSON_LINE_SIZE:
                continue

            try:
                data = json.loads(line)
                strings = list(_extract_strings_from_json(data))
                if strings:
                    yield " ".join(strings)
            except json.JSONDecodeError:
                pass 

def _extract_strings_from_json(data: Any) -> Generator[str, None, None]:
    stack = [data]
    while stack:
        current = stack.pop()
        if isinstance(current, str):
            yield current
        elif isinstance(current, dict):
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)
