# Copyright 2026 Veritensor Security
# ChromaDB Integration: Vector DB Firewall

import logging
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
    def __init__(self, collection: Any, strict_mode: bool = True):
        """
        :param collection: A chromadb.api.models.Collection.Collection object
        """
        self._collection = collection
        self.strict_mode = strict_mode

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
        
        for i, doc_text in enumerate(documents):
            doc_id = ids[i] if ids and i < len(ids) else f"doc_{i}"
            threats = scan_text(doc_text, source_name=f"ChromaDB_Insert_{doc_id}")
            
            if threats:
                threat_msg = "\n".join(threats)
                if self.strict_mode:
                    raise VeritensorSecurityError(
                        f"Vector DB Firewall Blocked insertion of document '{doc_id}':\n{threat_msg}"
                    )
                else:
                    logger.warning(f"⚠️ Vector DB Warning for '{doc_id}':\n{threat_msg}")
