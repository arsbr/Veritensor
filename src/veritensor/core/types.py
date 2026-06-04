from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

@dataclass
class ScanResult:
    file_path: str
    status: str = "PASS"  # PASS / FAIL
    threats: List[str] = field(default_factory=list)
    
    # Extended Metadata (Smart Attestation ready)
    file_hash: Optional[str] = None
    identity_verified: bool = False
    detected_license: Optional[str] = None
    repo_id: Optional[str] = None
    file_format: Optional[str] = None

    # --- Annex IV Metadata ---
    tensor_count: int = 0
    extracted_metadata: dict = field(default_factory=dict)
    
    bias_data: Optional[dict] = None
    
    def add_threat(self, message: str):
        self.threats.append(message)
        self.status = "FAIL"
