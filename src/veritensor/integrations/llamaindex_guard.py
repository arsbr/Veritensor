import logging
from pathlib import Path
from typing import List, Any, Optional

try:
    from llama_index.core.readers.base import BaseReader
    from llama_index.core.schema import Document
    LLAMAINDEX_AVAILABLE = True
except ImportError:
    LLAMAINDEX_AVAILABLE = False
    BaseReader = object

from veritensor.engines.content.injection import scan_document
from veritensor.integrations.enterprise_scanner import EnterpriseScanner

logger = logging.getLogger(__name__)

class VeritensorSecurityError(Exception):
    pass

class SecureLlamaIndexReader(BaseReader):
    def __init__(self, base_reader: BaseReader, strict_mode: bool = True, enterprise_url: Optional[str] = None, api_key: Optional[str] = None):
        if not LLAMAINDEX_AVAILABLE:
            raise ImportError("LlamaIndex is not installed. Run 'pip install llama-index-core'")
            
        self.base_reader = base_reader
        self.strict_mode = strict_mode
        self.enterprise_scanner = EnterpriseScanner(enterprise_url, api_key) if enterprise_url and api_key else None

    def load_data(self, file: Path, extra_info: dict = None) -> List['Document']:
        file_path = Path(file)
        logger.info(f"🛡️ Veritensor: Scanning {file_path.name} before ingestion...")

        if self.enterprise_scanner:
            threats = self.enterprise_scanner.scan_file_remotely(file_path)
        else:
            threats = scan_document(file_path)

        if threats:
            threat_msg = "\n".join(threats)
            if self.strict_mode: raise VeritensorSecurityError(f"Blocked ingestion of {file_path.name}:\n{threat_msg}")
            else: logger.warning(f"⚠️ Veritensor Security Warning:\n{threat_msg}")

        logger.info(f"✅ Veritensor: {file_path.name} is clean.")
        return self.base_reader.load_data(file, extra_info=extra_info)
