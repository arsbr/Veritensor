# Copyright 2025 Veritensor Security
#
# This module generates SARIF v2.1.0 reports.
# It allows Veritensor to integrate natively with GitHub Advanced Security.

import json
from typing import List, Any
from veritensor.core.types import ScanResult  
from veritensor import __version__

# --- Constants ---
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "Veritensor Security Scanner"
TOOL_DRIVER_NAME = "Veritensor"

# --- Rule Definitions ---
VERITENSOR_RULES = [
    {
        "id": "VERITENSOR-001",
        "name": "RemoteCodeExecution",
        "shortDescription": {"text": "Critical RCE Risk Detected"},
        "fullDescription": {"text": "The model contains code that executes arbitrary system commands (e.g., os.system, subprocess)."},
        "defaultConfiguration": {"level": "error"},
        "properties": {"tags": ["security", "rce", "critical"]}
    },
    {
        "id": "VERITENSOR-002",
        "name": "UnsafeDeserialization",
        "shortDescription": {"text": "Unsafe Pickle Import"},
        "fullDescription": {"text": "The model imports modules that are not in the allowlist. This poses a security risk during deserialization."},
        "defaultConfiguration": {"level": "error"},
        "properties": {"tags": ["security", "pickle", "deserialization"]}
    },
    {
        "id": "VERITENSOR-003",
        "name": "KerasLambdaLayer",
        "shortDescription": {"text": "Malicious Keras Lambda Layer"},
        "fullDescription": {"text": "A Keras Lambda layer was detected. These layers can contain arbitrary Python bytecode."},
        "defaultConfiguration": {"level": "error"},
        "properties": {"tags": ["security", "keras", "rce"]}
    },
    {
        "id": "VERITENSOR-004",
        "name": "IntegrityMismatch",
        "shortDescription": {"text": "Model Hash Mismatch"},
        "fullDescription": {"text": "The file hash does not match the official registry (Hugging Face). The file may be corrupted or tampered with."},
        "defaultConfiguration": {"level": "warning"},
        "properties": {"tags": ["security", "integrity", "supply-chain"]}
    }
]


def generate_sarif_report(scan_results: List[ScanResult], tool_version: str = __version__) -> str:
    """
    Converts internal Veritensor scan results (Objects) into a SARIF JSON string.
    """
    
    sarif_results = []

    for file_res in scan_results:
        if file_res.status == "PASS":
            continue

        file_path = file_res.file_path
        threats = file_res.threats

        for threat_msg in threats:
            rule_id = _map_threat_to_rule_id(threat_msg)
            
            result = {
                "ruleId": rule_id,
                "level": "error",
                "message": {
                    "text": threat_msg
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": file_path
                            }
                        }
                    }
                ]
            }
            sarif_results.append(result)

    # Construct the full SARIF object
    report = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_DRIVER_NAME,
                        "fullName": TOOL_NAME,
                        "version": __version__,
                        "rules": VERITENSOR_RULES
                    }
                },
                "results": sarif_results
            }
        ]
    }

    return json.dumps(report, indent=2)


def _map_threat_to_rule_id(threat_msg: str) -> str:
    """
    Heuristic to map a raw threat string to a SARIF Rule ID.
    """
    msg_lower = threat_msg.lower()

    if "lambda" in msg_lower and "keras" in msg_lower:
        return "VERITENSOR-003"
    
    if "os." in msg_lower or "subprocess" in msg_lower or "eval" in msg_lower or "exec" in msg_lower:
        return "VERITENSOR-001"
    
    if "hash" in msg_lower or "mismatch" in msg_lower:
        return "VERITENSOR-004"

    # Fallback for generic unsafe imports or license issues
    return "VERITENSOR-002"
