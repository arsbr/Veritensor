# Copyright 2026 Veritensor Security
# ChromaDB Integration: Vector DB Firewall

import logging
import requests
from typing import List, Dict, Any, Optional
from veritensor.engines.content.injection import scan_text

logger = logging.getLogger(__name__)

class VeritensorSecurityError(Exception):
    pass

class SecureChromaCollection:
    """
    A security wrapper around a ChromaDB Collection.
    Intercepts .add() and .upsert() calls to scan documents before vectorization.
    """
    def __init__(self, collection: Any, strict_mode: bool = True, enterprise_url: str = None, api_key: str = None):
        """
        :param collection: A chromadb.api.models.Collection.Collection object
        """
        self._collection = collection
        self.strict_mode = strict_mode
        self.enterprise_url = enterprise_url.rstrip('/') if enterprise_url else None
        self.api_key = api_key
        
    def __getattr__(self, name):
        """Delegate all other methods to the original collection."""
        return getattr(self._collection, name)

    def add(self, documents: List[str], metadatas: Optional[List[Dict]] = None, ids: List[str] = None, **kwargs):
        self._verify_documents(documents, ids)
        return self._collection.add(documents=documents, metadatas=metadatas, ids=ids, **kwargs)

    def upsert(self, documents: List[str], metadatas: Optional[List[Dict]] = None, ids: List[str] = None, **kwargs):
        self._verify_documents(documents, ids)
        return self._collection.upsert(documents=documents, metadatas=metadatas, ids=ids, **kwargs)

    def _verify_documents(self, documents: List[str], ids: List[str]):
        if not documents:
            return

        logger.info(f"🛡️ Veritensor: Scanning {len(documents)} documents before Vector DB insertion...")
        
         # Enterprise ML Scan (Batch)
        if self.enterprise_url and self.api_key:
            payload = {"documents": [{"id": ids[i] if ids else str(i), "text": doc} for i, doc in enumerate(documents)]}
            try:
                res = requests.post(f"{self.enterprise_url}/scan/batch", json=payload, headers={"X-API-Key": self.api_key}, timeout=30)
                res.raise_for_status()
                for item in res.json().get("results", []):
                    if item["status"] == "FAIL":
                        threat_msg = "\n".join(item["threats"])
                        if self.strict_mode: raise VeritensorSecurityError(f"Blocked document '{item['id']}':\n{threat_msg}")
                        else: logger.warning(f"⚠️ Vector DB Warning for '{item['id']}':\n{threat_msg}")
                return
            except requests.exceptions.RequestException as e:
                logger.warning(f"Enterprise server unreachable, falling back to local scan: {e}")

        # Local Fallback (Regex only)
        for i, doc_text in enumerate(documents):
            doc_id = ids[i] if ids and i < len(ids) else f"doc_{i}"
            threats = scan_text(doc_text, source_name=f"ChromaDB_Insert_{doc_id}")
            if threats:
                threat_msg = "\n".join(threats)
                if self.strict_mode: raise VeritensorSecurityError(f"Blocked document '{doc_id}':\n{threat_msg}")
                else: logger.warning(f"⚠️ Vector DB Warning for '{doc_id}':\n{threat_msg}")
