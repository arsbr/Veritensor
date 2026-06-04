# Copyright 2026 Veritensor Security Apache 2.0
# LangChain Integration: Secure Document Loader Wrapper

import logging
from pathlib import Path
from typing import List, Any, Optional

try:
    from langchain_core.document_loaders import BaseLoader
    from langchain_core.documents import Document
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    BaseLoader = object 

from veritensor.engines.content.injection import scan_document
from veritensor.integrations.enterprise_scanner import EnterpriseScanner

logger = logging.getLogger(__name__)

class VeritensorSecurityError(Exception):
    pass

class SecureLangChainLoader(BaseLoader):
    def __init__(self, file_path: str, base_loader: BaseLoader, strict_mode: bool = True, enterprise_url: Optional[str] = None, api_key: Optional[str] = None):
        if not LANGCHAIN_AVAILABLE:
            raise ImportError("LangChain is not installed. Run 'pip install langchain-core'")
            
        self.file_path = Path(file_path)
        self.base_loader = base_loader
        self.strict_mode = strict_mode
        self.enterprise_scanner = EnterpriseScanner(enterprise_url, api_key) if enterprise_url and api_key else None

    def load(self) -> List['Document']:
        logger.info(f"🛡️ Veritensor: Scanning {self.file_path.name} before ingestion...")
        if not self.file_path.exists(): raise FileNotFoundError(f"File not found: {self.file_path}")

        # Enterprise ML Scan or Local Regex Fallback
        if self.enterprise_scanner:
            threats = self.enterprise_scanner.scan_file_remotely(self.file_path)
        else:
            threats = scan_document(self.file_path)

        if threats:
            threat_msg = "\n".join(threats)
            if self.strict_mode: raise VeritensorSecurityError(f"Blocked ingestion of {self.file_path.name}:\n{threat_msg}")
            else: logger.warning(f"⚠️ Veritensor Security Warning:\n{threat_msg}")

        logger.info(f"✅ Veritensor: {self.file_path.name} is clean.")
        return self.base_loader.load()

    def lazy_load(self):
        self.load() 
        yield from self.base_loader.lazy_load()
