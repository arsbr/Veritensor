# Copyright 2026 Veritensor Security Apache 2.0
# Unified RAG Security SDK

import logging
import requests
import re
from typing import List, Any, Optional

logger = logging.getLogger(__name__)

_SEVERITY_PATTERN = re.compile(r'(?:^|:\s*)(CRITICAL|HIGH|MEDIUM|LOW)', re.IGNORECASE)
_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

def _extract_max_severity(threats: List[str]) -> Optional[str]:
    """Extracts the highest severity from a list of threat strings, handling LINE formats."""
    max_val = 0
    max_sev = None
    for threat in threats:
        m = _SEVERITY_PATTERN.search(threat)
        if m:
            sev = m.group(1).upper()
            if _SEVERITY_ORDER.get(sev, 0) > max_val:
                max_val = _SEVERITY_ORDER[sev]
                max_sev = sev
    return max_sev

class RAGGuard:
    """
    Enterprise RAG Security Middleware.
    Filters malicious documents (Prompt Injections, PII) before they enter Vector DBs.
    """
    def __init__(self, api_key: str, endpoint: str = "http://localhost:8000/api/v1"):
        self.api_key = api_key
        self.endpoint = endpoint.rstrip('/')
        self.headers = {"X-API-Key": self.api_key, "Content-Type": "application/json"}

    def filter_documents(
        self, 
        documents: List[Any], 
        block_on: Optional[List[str]] = None, 
        text_attribute: str = "page_content"
    ) -> List[Any]:
        if block_on is None:
            block_on = ["CRITICAL", "HIGH"]

        if not documents:
            return []

        logger.info(f"🛡️ RAGGuard: Scanning {len(documents)} documents via Enterprise Control Plane...")

        payload_docs = []
        for i, doc in enumerate(documents):
            text = ""
            if hasattr(doc, text_attribute): text = getattr(doc, text_attribute)
            elif hasattr(doc, "text"): text = doc.text
            elif isinstance(doc, dict) and "text" in doc: text = doc["text"]
            elif isinstance(doc, str): text = doc
            payload_docs.append({"id": str(i), "text": text[:50000]})

        try:
            res = requests.post(
                f"{self.endpoint}/scan/batch", 
                json={"documents": payload_docs}, 
                headers=self.headers, 
                timeout=30
            )
            res.raise_for_status()
            scan_results = res.json().get("results", [])
        except Exception as e:
            logger.error(f"RAGGuard scan failed: {e}. Failing open (allowing documents).")
            return documents 

        # Map results by ID to prevent index mismatch issues
        result_map = {str(r.get("id")): r for r in scan_results}
        
        safe_documents = []
        blocked_count = 0

        for i, doc in enumerate(documents):
            doc_id = str(i)
            result = result_map.get(doc_id, {})
            
            if result.get("status") == "FAIL":
                max_sev = _extract_max_severity(result.get("threats", []))
                if max_sev and max_sev in block_on:
                    blocked_count += 1
                    logger.warning(f"RAGGuard Blocked Document {i}: {result.get('threats')}")
                    continue # Skip adding to safe_documents
            
            safe_documents.append(doc)

        logger.info(f"✅ RAGGuard: Allowed {len(safe_documents)}, Blocked {blocked_count}.")
        return safe_documents
