# Copyright 2026 Veritensor Security
# Enterprise Scanner Integration: Offloads heavy files to the Veritensor Control Plane.

import requests
import time
import logging
from pathlib import Path
from typing import List
from veritensor.core.networking import validate_url_safety

logger = logging.getLogger(__name__)

class EnterpriseScanner:
    def __init__(self, base_url: str, api_key: str):
        # Убираем /telemetry из URL, если юзер передал его
        self.base_url = base_url.replace("/telemetry", "")
        self.headers = {"X-API-Key": api_key}

    def scan_file_remotely(self, file_path: Path) -> List[str]:
        """
        Sends a heavy file to the server for OCR, YARA, and Semantic Analysis.
        Retrieves the list of threats found.
        """
        try:
            # 1. Requesting a download link
            req_url = f"{self.base_url}/upload/request"
            res = requests.post(req_url, headers=self.headers, json={"filename": file_path.name}, timeout=5)
            res.raise_for_status()
            data = res.json()
            upload_url = validate_url_safety(data["upload_url"])
            file_id = data["file_id"]

            # 2. Upload the file directly to S3 (MinIO)
            with open(file_path, "rb") as f:
                upload_res = requests.put(upload_url, data=f, allow_redirects=False)
                upload_res.raise_for_status()

            # 3. Launching an asynchronous task in Celery
            scan_req = requests.post(f"{self.base_url}/scan/async", headers=self.headers, json={"file_id": file_id}, timeout=5)
            scan_req.raise_for_status()
            task_id = scan_req.json()["task_id"]

            # 4. Waiting for the result (Polling)
            max_retries = 10 # 
            for i in range(max_retries):
                status_res = requests.get(f"{self.base_url}/scan/result/{task_id}", headers=self.headers, timeout=5)
                status_data = status_res.json()
                
                if status_data["status"] == "completed":
                    return status_data.get("result", {}).get("threats", [])
                elif status_data["status"] == "failed":
                    return [f"WARNING: Enterprise Worker failed: {status_data.get('error')}"]
                
                # Waiting for: 1s, 2s, 4s, 8s, 15s (maximum 15)
                sleep_time = min(2 ** i, 15)
                time.sleep(sleep_time)
                
            return["WARNING: Enterprise scan timed out."]

        except Exception as e:
            logger.debug(f"Enterprise remote scan failed for {file_path.name}: {e}")
            return [f"WARNING: Failed to reach Enterprise Scanner: {e}"]