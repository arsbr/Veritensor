import logging
import requests
from typing import List, Any, Optional
from veritensor.engines.content.injection import scan_text

logger = logging.getLogger(__name__)

class VeritensorSecurityError(Exception):
    pass

class SecureUnstructuredScanner:
    def __init__(self, strict_mode: bool = True, enterprise_url: Optional[str] = None, api_key: Optional[str] = None):
        self.strict_mode = strict_mode
        self.enterprise_url = enterprise_url.rstrip('/') if enterprise_url else None
        self.api_key = api_key

    def verify(self, elements: List[Any], source_name: str = "unstructured_doc") -> List[Any]:
        logger.info(f"🛡️ Veritensor: Scanning {len(elements)} elements from {source_name}...")
        full_text = "\n".join([el.text for el in elements if hasattr(el, 'text')])
        
        threats = []
        if self.enterprise_url and self.api_key:
            try:
                res = requests.post(f"{self.enterprise_url}/scan/sync", json={"text": full_text[:50000]}, headers={"X-API-Key": self.api_key}, timeout=15)
                res.raise_for_status()
                if res.json().get("status") == "FAIL":
                    threats = res.json().get("threats", [])
            except Exception as e:
                logger.warning(f"Enterprise scan failed, falling back to local: {e}")
                threats = scan_text(full_text, source_name=source_name)
        else:
            threats = scan_text(full_text, source_name=source_name)

        if threats:
            threat_msg = "\n".join(threats)
            if self.strict_mode: raise VeritensorSecurityError(f"Blocked ingestion of {source_name}:\n{threat_msg}")
            else: logger.warning(f"⚠️ Veritensor Security Warning:\n{threat_msg}")

        return elements
