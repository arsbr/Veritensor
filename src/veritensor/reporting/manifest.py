# Copyright 2026 Veritensor Security Apache 2.0
# Manifest Generator: Creates a JSON snapshot of the scan state (Provenance).

import json
import datetime
import platform
from pathlib import Path
from typing import List
from veritensor.core.types import ScanResult

def generate_manifest(results: List[ScanResult], output_path: str = "veritensor-manifest.json") -> str:
    """
    Generates a structured JSON manifest of all scanned artifacts.
    Returns the path to the created file.
    """
    manifest = {
        "schema_version": "1.0",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "tool": {
            "name": "veritensor",
            "version": "1.6.1", 
            "python": platform.python_version(),
            "system": platform.system()
        },
        "summary": {
            "total_files": len(results),
            "passed": len([r for r in results if r.status == "PASS"]),
            "failed": len([r for r in results if r.status == "FAIL"]),
        },
        "artifacts": []
    }

    for res in results:
        artifact = {
            "path": res.file_path,
            "hash": res.file_hash,
            "status": res.status,
            "verified_origin": res.identity_verified,
            "license": res.detected_license,
            "threats": res.threats if res.status == "FAIL" else []
        }
        manifest["artifacts"].append(artifact)

    # Save to disk
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        
    return output_path
