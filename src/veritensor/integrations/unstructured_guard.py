# Copyright 2026 Veritensor Security
# Unstructured.io Integration: Scans extracted elements before they hit the Vector DB.

import logging
from typing import List, Any
from veritensor.engines.content.injection import scan_text

logger = logging.getLogger(__name__)

class VeritensorSecurityError(Exception):
    pass

class SecureUnstructuredScanner:
    """
    Wrapper for Unstructured.io elements.
    Usage:
        elements = partition_pdf("resume.pdf")
        scanner = SecureUnstructuredScanner()
        clean_elements = scanner.verify(elements)
    """
    def __init__(self, strict_mode: bool = True):
        self.strict_mode = strict_mode

    def verify(self, elements: List[Any], source_name: str = "unstructured_doc") -> List[Any]:
        """
        Scans a list of Unstructured elements.
        Returns the elements if safe, raises Exception if malicious.
        """
        logger.info(f"🛡️ Veritensor: Scanning {len(elements)} elements from {source_name}...")
        
        # Unstructured elements have a .text attribute
        full_text = "\n".join([el.text for el in elements if hasattr(el, 'text')])
        
        threats = scan_text(full_text, source_name=source_name)

        if threats:
            threat_msg = "\n".join(threats)
            if self.strict_mode:
                raise VeritensorSecurityError(
                    f"Blocked ingestion of {source_name} due to security threats:\n{threat_msg}"
                )
            else:
                logger.warning(f"⚠️ Veritensor Security Warning for {source_name}:\n{threat_msg}")

        logger.info(f"✅ Veritensor: {source_name} is clean.")
        return elements
