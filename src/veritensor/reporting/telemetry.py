# Copyright 2025 Veritensor Security Apache 2.0
# Telemetry Client for Enterprise Reporting

import requests
import logging
import json
import datetime
import platform
from pathlib import Path
from typing import List, Optional
from veritensor.core.types import ScanResult
from veritensor.core.config import VeritensorConfig
from veritensor import __version__

logger = logging.getLogger(__name__)

def send_report(
    results: List[ScanResult], 
    config: VeritensorConfig, 
    override_url: Optional[str] = None,
    override_key: Optional[str] = None
):
    """
    Sends scan metadata to the centralized Veritensor Dashboard.
    Does NOT send file content.
    """
    target_url = override_url or config.report_url
    api_key = override_key or config.api_key

    if not target_url:
        return # Telemetry disabled

    # 1. Prepare Payload (Strict Schema)
    payload = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "tool": "veritensor-cli",
        "version": __version__,
        "system": {
            "os": platform.system(),
            "python": platform.python_version()
        },
        "scan_summary": {
            "total_files": len(results),
            "failed_files": len([r for r in results if r.status == "FAIL"]),
        },
        "results": []
    }

    # 2. Sanitize Results (Privacy Filter)
    for res in results:
        payload["results"].append({
            "file_name": Path(res.file_path).name,
            "file_hash": res.file_hash,
            "status": res.status,
            "threats": res.threats,
            "license": res.detected_license,
            "repo_id": res.repo_id,
            "verified": res.identity_verified
        })

    # 3. Send Request
    headers = {
        "Content-Type": "application/json",
        "User-Agent": f"Veritensor-CLI/{__version__}"
    }
    if api_key:
        headers["X-API-Key"] = api_key

    try:
        # Timeout is crucial so CLI doesn't hang if server is down
        response = requests.post(target_url, json=payload, headers=headers, timeout=20)
        
        if response.status_code in (200, 201):
            logger.debug(f"Telemetry sent successfully to {target_url}")
        else:
            logger.warning(f"Telemetry failed: {response.status_code} - {response.text}")
            
    except requests.exceptions.RequestException as e:
        # Fail-Open: Network errors should not break the build
        logger.warning(f"Telemetry unreachable: {str(e)}")
