# Copyright 2026 Veritensor Security Apache 2.0
# Dataset Scanner (Parquet, CSV, JSONL) for Data Poisoning, Malicious URLs, and Toxic Columns

import logging
import json
from pathlib import Path
from typing import List, Generator, Any, Tuple, Optional
import pandas as pd
from veritensor.engines.static.rules import SignatureLoader, is_match
from veritensor.engines.content.pii import PIIScanner
from collections import defaultdict
logger = logging.getLogger(__name__)

try:
    import pyarrow.parquet as pq
    import pyarrow as pa
    PYARROW_AVAILABLE = True
except ImportError:
    PYARROW_AVAILABLE = False

MAX_ROWS_DEFAULT = 10_000
CHUNK_SIZE = 1000
MAX_JSON_LINE_SIZE = 10 * 1024 * 1024

FALLBACK_SUSPICIOUS = [
    "regex:https?://[\\w\\.-]+",
    "regex:(?i)malicious",
    "regex:(?i)eval\\(", 
    "regex:AKIA[0-9A-Z]{16}",
    "regex:(?i)password",
    "regex:(?i)secret"
]

# --- CRITICAL FIX: Robust Singleton for GLiNER ---
_GLINER_UNAVAILABLE = object()
_gliner_model = None

def _get_gliner_model():
    """Lazy loads GLiNER to avoid 30-90s delay on every function call."""
    global _gliner_model
    if _gliner_model is None:
        try:
            from gliner import GLiNER
            logger.info("Loading GLiNER model for column analysis...")
            _gliner_model = GLiNER.from_pretrained("urchade/gliner_multi-v2.1")
        except ImportError:
            _gliner_model = _GLINER_UNAVAILABLE
        except Exception as e:
            logger.warning(f"GLiNER failed to load: {e}. Falling back to regex.")
            _gliner_model = _GLINER_UNAVAILABLE
    return _gliner_model

def _check_toxic_columns(columns: List[str]) -> List[str]:
    """
    Article 5 (Prohibited AI): Detects toxic columns.
    """
    threats = []
    if not columns:
        return threats
        
    toxic_keywords = [
        "social_credit", "political_affiliation", "sexual_orientation", 
        "race", "religion", "trade_union", "biometric_categorization", "criminal_prediction"
    ]
    
    model = _get_gliner_model()
    
    # Use identity operator (is not) with the object sentinel
    if model is not _GLINER_UNAVAILABLE:
        text = " ".join(columns).replace("_", " ")
        preds = model.predict_entities(text, ["prohibited AI attribute", "sensitive personal data"], threshold=0.6)
        for p in preds:
            threats.append(f"CRITICAL: Article 5 Violation Risk (Prohibited AI). Toxic column detected: '{p['text']}'")
    else:
        # Fallback to Regex if GLiNER is unavailable
        for col in columns:
            if any(k in col.lower() for k in toxic_keywords):
                threats.append(f"CRITICAL: Article 5 Violation Risk (Prohibited AI). Toxic column detected: '{col}'")
                
    return threats

def scan_dataset(file_path: Path, full_scan: bool = False, bias_profile: Optional[dict] = None) -> Tuple[List[str], Optional[dict]]:
    ext = file_path.suffix.lower()
    threats = []
    bias_data = None
    injections = SignatureLoader.get_prompt_injections()
    
    try:
        suspicious = SignatureLoader.get_suspicious_strings()
    except AttributeError:
        suspicious = []
    
    if not suspicious: 
        suspicious = FALLBACK_SUSPICIOUS

    row_limit = None if full_scan else MAX_ROWS_DEFAULT
    
    # Initialize Bias Aggregator if profile is provided
    aggregator = BiasAggregator(bias_profile) if bias_profile else None
    
    try:
        text_stream = None
        
        if ext == ".parquet":
            if not PYARROW_AVAILABLE:
                return ["WARNING: pyarrow not installed. Run 'pip install veritensor[data]'"], None
            
            try:
                parquet_file = pq.ParquetFile(file_path)
                columns = parquet_file.schema_arrow.names
                threats.extend(_check_toxic_columns(columns))
            except Exception:
                pass
                
            # Pass dataframe chunks to aggregator
            if aggregator:
                try:
                    for batch in pq.ParquetFile(file_path).iter_batches(batch_size=CHUNK_SIZE):
                        aggregator.update(batch.to_pandas())
                except Exception as e:
                    logger.debug(f"Bias aggregation failed for parquet: {e}")
                
            text_stream = _stream_parquet(file_path)
            
        elif ext in {".csv", ".tsv"}:
       
            sep = "\t" if ext == ".tsv" else ","
            try:
                df_preview = pd.read_csv(file_path, sep=sep, nrows=0)
                threats.extend(_check_toxic_columns(df_preview.columns.tolist()))
            except Exception:
                pass
                
            #  Pass dataframe chunks to aggregator
            if aggregator:
                try:
                    for chunk in pd.read_csv(file_path, sep=sep, chunksize=CHUNK_SIZE, on_bad_lines="skip", low_memory=True):
                        aggregator.update(chunk)
                except Exception as e:
                    logger.debug(f"Bias aggregation failed for csv: {e}")
                
            text_stream = _stream_csv(file_path)
            
        elif ext in {".jsonl", ".ndjson", ".ldjson"}:
            # JSONL logic remains the same (we don't do bias math on JSONL for now)
            def _single_pass_jsonl(filepath):
                json_keys = set()
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    for i, line in enumerate(f):
                        if not line: break
                        if len(line) > MAX_JSON_LINE_SIZE: continue
                        try:
                            data = json.loads(line)
                            if i < 10 and isinstance(data, dict):
                                json_keys.update(data.keys())
                            strings = list(_extract_strings_from_json(data))
                            if strings: yield " ".join(strings)
                        except json.JSONDecodeError: pass
                if json_keys:
                    threats.extend(_check_toxic_columns(list(json_keys)))

            text_stream = _single_pass_jsonl(file_path)
        else:
            return [], None

        row_count = 0
        pii_buffer = [] 
        unique_data_threats = set()

        for text_chunk in text_stream:
            row_count += 1
            if row_limit and row_count >= row_limit: break
            if not text_chunk or len(text_chunk) < 5: continue
            if len(text_chunk) > 4096: text_chunk = text_chunk[:4096]

            for pat in injections:
                if is_match(text_chunk, [pat]):
                    unique_data_threats.add(f"HIGH: Data Poisoning (Injection) detected in {file_path.name}: '{pat}'")

            for pat in suspicious:
                if is_match(text_chunk, [pat]):
                    label = "Malicious URL" if "http" in pat else "Secret/PII Pattern"
                    unique_data_threats.add(f"MEDIUM: {label} detected in dataset {file_path.name}: '{pat}'")
            
            if len(pii_buffer) < 50:
                pii_buffer.append(text_chunk)

        data_threats = sorted(list(unique_data_threats))
        pii_threats = []
        if pii_buffer:
            combined_sample = "\n".join(pii_buffer)
            pii_threats = PIIScanner.scan(combined_sample)

        threats.extend(data_threats)
        threats.extend(pii_threats)
        
        # Get final bias data
        if aggregator:
            bias_data = aggregator.get_results()
                
    except Exception as e:
        logger.warning(f"Failed to scan dataset {file_path}: {e}")
        threats.append(f"WARNING: Dataset Scan Error: {str(e)}")

    return threats, bias_data


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
            yield " ".join(row.dropna().astype(str).tolist())

def _stream_csv(path: Path) -> Generator[str, None, None]:
    ext = path.suffix.lower()
    sep = "\t" if ext == ".tsv" else ","
    try:
   
        chunks = pd.read_csv(path, sep=sep, chunksize=CHUNK_SIZE, encoding="utf-8", on_bad_lines="skip", low_memory=True)
        for chunk in chunks:
            text_df = chunk.select_dtypes(include=['object'])
            for _, row in text_df.iterrows():
                yield " ".join(row.dropna().astype(str).tolist())
        return
    except Exception:
        import csv, sys
        csv.field_size_limit(min(sys.maxsize, 2147483647))
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f, delimiter=sep)
            for row in reader:
                yield " ".join(row)

def _stream_jsonl(path: Path) -> Generator[str, None, None]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        while True:
            line = f.readline()
            if not line: break
            if len(line) > MAX_JSON_LINE_SIZE: continue
            try:
                data = json.loads(line)
                strings = list(_extract_strings_from_json(data))
                if strings: yield " ".join(strings)
            except json.JSONDecodeError: pass 

def _extract_strings_from_json(data: Any) -> Generator[str, None, None]:
    stack = [data]
    while stack:
        current = stack.pop()
        if isinstance(current, str): yield current
        elif isinstance(current, dict): stack.extend(current.values())
        elif isinstance(current, list): stack.extend(current)

class BiasAggregator:
    """Aggregates counts for fairness metrics using O(1) memory. Safe for multiprocessing (no lambdas)."""
    def __init__(self, profile: dict):
        self.protected_attrs = profile.get("protected_attributes", [])
        self.target_var = profile.get("target_variable")
        self.favorable_label = str(profile.get("favorable_label"))
        
        self.group_target_counts = {}
        self.proxy_counts = {}
        self.candidate_cols = None

    def update(self, df):
        
        df.columns = df.columns.str.strip().str.lower()
        
        target_var_lower = self.target_var.lower()
        protected_attrs_lower = [attr.lower() for attr in self.protected_attrs]

        if target_var_lower not in df.columns:
            return
            
        missing_attrs = [attr for attr in protected_attrs_lower if attr not in df.columns]
        if missing_attrs:
            return

        # Update Group-Target Counts
        eval_df = df.dropna(subset=protected_attrs_lower + [target_var_lower]).copy()
        # Strip whitespaces to ensure " 1" matches "1"
        eval_df[target_var_lower] = eval_df[target_var_lower].astype(str).str.strip()
        
        if len(protected_attrs_lower) > 1:
            eval_df['intersectional_group'] = eval_df[protected_attrs_lower].astype(str).apply(lambda x: '_'.join(x.str.strip()), axis=1)
            group_col = 'intersectional_group'
        else:
            group_col = protected_attrs_lower[0]
            eval_df[group_col] = eval_df[group_col].astype(str).str.strip()

        # 1. Update Group-Target Counts
        counts = eval_df.groupby([group_col, target_var_lower]).size().to_dict()
        for (group_val, target_val), count in counts.items():
            g_val_str = str(group_val)
            t_val_str = str(target_val)
            
            if g_val_str not in self.group_target_counts:
                self.group_target_counts[g_val_str] = {}
            self.group_target_counts[g_val_str][t_val_str] = self.group_target_counts[g_val_str].get(t_val_str, 0) + count

        # 2. Update Proxy Counts
        if self.candidate_cols is None:
            cat_cols = df.select_dtypes(include=['object', 'category', 'bool']).columns.tolist()
            self.candidate_cols = [c for c in cat_cols if c not in protected_attrs_lower and df[c].nunique() < 100]

        for p_attr in protected_attrs_lower:
            if p_attr not in self.proxy_counts:
                self.proxy_counts[p_attr] = {}
                
            for c_col in self.candidate_cols:
                if c_col in eval_df.columns:
                    if c_col not in self.proxy_counts[p_attr]:
                        self.proxy_counts[p_attr][c_col] = {}
                        
                    co_counts = eval_df.groupby([p_attr, c_col]).size().to_dict()
                    for (p_val, c_val), count in co_counts.items():
                        p_val_str = str(p_val)
                        c_val_str = str(c_val)
                        
                        if p_val_str not in self.proxy_counts[p_attr][c_col]:
                            self.proxy_counts[p_attr][c_col][p_val_str] = {}
                            
                        self.proxy_counts[p_attr][c_col][p_val_str][c_val_str] = self.proxy_counts[p_attr][c_col][p_val_str].get(c_val_str, 0) + count

    def get_results(self) -> dict:
        return {
            "group_target_counts": self.group_target_counts,
            "proxy_counts": self.proxy_counts,
            "favorable_label": self.favorable_label
        }

