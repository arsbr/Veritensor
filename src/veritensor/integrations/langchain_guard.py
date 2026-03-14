# Copyright 2026 Veritensor Security Apache 2.0
# LangChain Integration: Secure Document Loader Wrapper

import logging
from pathlib import Path
from typing import List, Any

# Soft import so as not to break Veritensor if the user does not have a LangChain
try:
    from langchain_core.document_loaders import BaseLoader
    from langchain_core.documents import Document
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    BaseLoader = object # An inheritance stub

from veritensor.engines.content.injection import scan_document

logger = logging.getLogger(__name__)

class VeritensorSecurityError(Exception):
    """An exception that is thrown when threats are detected in the data."""
    pass

class SecureLangChainLoader(BaseLoader):
    """
    A wrapper for any LangChain loader. 
    Scans the file for Prompt Injections, PII, and Stealth attacks before uploading.
    """
    def __init__(self, file_path: str, base_loader: BaseLoader, strict_mode: bool = True):
        """
        :param file_path: The path to the file that is being uploaded.
        :param base_loader: An instance of the original loader (for example, PyPDFLoader).
        :param strict_mode: If True, throws an error. If False, it only writes to the log.
        """
        if not LANGCHAIN_AVAILABLE:
            raise ImportError("LangChain is not installed. Run 'pip install langchain-core'")
            
        self.file_path = Path(file_path)
        self.base_loader = base_loader
        self.strict_mode = strict_mode

    def load(self) -> List['Document']:
        """Перехватываем загрузку и сканируем файл."""
        logger.info(f"🛡️ Veritensor: Scanning {self.file_path.name} before ingestion...")
        
        if not self.file_path.exists():
            raise FileNotFoundError(f"File not found: {self.file_path}")

        # Start engine
        threats = scan_document(self.file_path)

        if threats:
            threat_msg = "\n".join(threats)
            if self.strict_mode:
                raise VeritensorSecurityError(
                    f"Blocked ingestion of {self.file_path.name} due to security threats:\n{threat_msg}"
                )
            else:
                logger.warning(f"⚠️ Veritensor Security Warning for {self.file_path.name}:\n{threat_msg}")

        # If there are no threats (or strict_mode=False), we give control to the original loader.
        logger.info(f"✅ Veritensor: {self.file_path.name} is clean. Proceeding with ingestion.")
        return self.base_loader.load()

    def lazy_load(self):
        """Поддержка ленивой загрузки (для больших файлов)."""
        # We scan the entire file once before streaming begins.
        self.load() # Will trigger a security check
        yield from self.base_loader.lazy_load()
