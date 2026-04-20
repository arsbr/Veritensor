# Copyright 2026 Veritensor Security
# Enterprise Scanner Integration: Offloads heavy files to the Veritensor Control Plane.
import sys
import requests
import time
import logging
import os
import tempfile
from pathlib import Path
from typing import List, Generator
from veritensor.engines.data.dataset_engine import _stream_parquet, _stream_csv, _stream_jsonl

logger = logging.getLogger(__name__)

class EnterpriseScanner:
    def __init__(self, base_url: str, api_key: str):
        # Убираем /telemetry из URL, если юзер передал его
        self.base_url = base_url.replace("/telemetry", "")
        self.headers = {"X-API-Key": api_key}

    def _yield_dataset_chunks(self, file_path: Path, chunk_size: int = 10000, full_scan: bool = False) -> Generator[str, None, None]:
        ext = file_path.suffix.lower()
        sep = "\t" if ext == ".tsv" else ","

        if ext == ".parquet":
            stream = _stream_parquet(file_path)
        elif ext in {".csv", ".tsv"}:
            stream = _stream_csv(file_path)
        elif ext in {".jsonl", ".ndjson", ".ldjson"}:
            stream = _stream_jsonl(file_path)
        else:
            yield str(file_path)
            return

        if not stream:
            yield str(file_path)
            return

        chunk_count = 0
        current_lines = 0
        fd, temp_path = tempfile.mkstemp(suffix=".txt", prefix=f"chunk_{chunk_count}_{file_path.name}_")
        f = os.fdopen(fd, 'w', encoding='utf-8', errors='ignore')

        for line in stream:
            if line:
                f.write(line + "\n")
                current_lines += 1

            if current_lines >= chunk_size:
                f.close()
                yield temp_path

                if not full_scan:
                    return

                chunk_count += 1
                current_lines = 0
                fd, temp_path = tempfile.mkstemp(suffix=".txt", prefix=f"chunk_{chunk_count}_{file_path.name}_")
                f = os.fdopen(fd, 'w', encoding='utf-8', errors='ignore')

        f.close()
        if current_lines > 0:
            yield temp_path
        else:
            os.remove(temp_path)


    def _scan_single_file(self, file_to_upload: str, original_name: str) -> List[str]:
        # Sends one physical file to the server and waits for the result
        try:
            # Getting the file size
            file_size = os.path.getsize(file_to_upload)
            # Requesting a link
            req_url = f"{self.base_url}/upload/request"
            payload = {
                "filename": original_name,
                "file_size_bytes": file_size # Passing the size
            }
            res = requests.post(req_url, headers=self.headers, json=payload, timeout=5)
            res.raise_for_status()
            data = res.json()
            
            # Load
            with open(file_to_upload, "rb") as f:
                requests.put(data["upload_url"], data=f).raise_for_status()

            # Start Celery
            scan_req = requests.post(f"{self.base_url}/scan/async", headers=self.headers, json={"file_id": data["file_id"]}, timeout=5)
            scan_req.raise_for_status()
            task_id = scan_req.json()["task_id"]

            POLL_INTERVAL_SECONDS = 6
            MAX_WAIT_SECONDS = int(os.getenv("VERITENSOR_SCAN_TIMEOUT", "600"))  # 10 min default, configurable

            elapsed = 0

            while True:
                status_res = requests.get(f"{self.base_url}/scan/result/{task_id}", headers=self.headers, timeout=5)
                status_data = status_res.json()
                
                if status_data["status"] == "completed":
                    return status_data.get("result", {}).get("threats", [])
                elif status_data["status"] == "failed":
                    return [f"WARNING: Enterprise Worker failed: {status_data.get('error')}"]
                
                
                if elapsed >= MAX_WAIT_SECONDS:
                    # Non-interactive: never call input() in a scanner
                    partial = status_data.get("result", {}).get("threats", [])
                    logger.warning(f"Enterprise scan timeout after {elapsed}s.")
                    return (["WARNING: Enterprise scan timed out."] + partial) if partial else \
                           ["WARNING: Enterprise scan timed out. No partial results."]
                
                time.sleep(POLL_INTERVAL_SECONDS)
                elapsed += POLL_INTERVAL_SECONDS
        
        except Exception as e:
            return[f"WARNING: Failed to reach Enterprise Scanner: {e}"]

    def scan_file_remotely(self, file_path: Path, full_scan: bool = False) -> List[str]:
        # The main method. Orchestrates the sending of chunks
        all_threats = []

        # If it's a dataset, we slice it. If it's a regular file (PDF/PNG), it will be given in its entirety
        is_dataset = file_path.suffix.lower() in {".parquet", ".csv", ".tsv", ".jsonl", ".ndjson"}

        if is_dataset:
            logger.info(f"Preparing dataset {file_path.name} (Full Scan: {full_scan})...")
            chunk_generator = self._yield_dataset_chunks(file_path, chunk_size=10000, full_scan=full_scan)

            for chunk_path in chunk_generator:
                try:
                    logger.info(f"Uploading chunk to Enterprise Server...")
                    threats = self._scan_single_file(chunk_path, original_name=file_path.name)
                    all_threats.extend(threats)
                finally:        
                # Deleting a temporary chunk from the user's disk
                    if os.path.exists(chunk_path):
                        try:
                            os.remove(chunk_path)
                        except OSError:
                            pass
                            
        else:
            # We send the usual files (PDF, images, archives) in their entirety.
            threats = self._scan_single_file(str(file_path), original_name=file_path.name)
            all_threats.extend(threats)

        # Sort LINE X results by line number, non-LINE threats go first
        def sort_key(t):
            if t.startswith("LINE "):
                try:
                    return (1, int(t.split(":")[0].replace("LINE ", "").strip()))
                except ValueError:
                    return (1, 9999)
            return (0, 0)

        all_threats.sort(key=sort_key)
        return all_threats
