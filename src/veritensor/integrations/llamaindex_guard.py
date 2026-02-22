# Copyright 2026 Veritensor Security Apache 2.0
# LlamaIndex Integration: Secure Reader Wrapper

import logging
from pathlib import Path
from typing import List, Any

# Soft import so as not to break Veritensor if the user does not have a LlamaIndex
try:
    from llama_index.core.readers.base import BaseReader
    from llama_index.core.schema import Document
    LLAMAINDEX_AVAILABLE = True
except ImportError:
    LLAMAINDEX_AVAILABLE = False
    BaseReader = object

from veritensor.engines.content.injection import scan_document

logger = logging.getLogger(__name__)

class VeritensorSecurityError(Exception):
    pass

class SecureLlamaIndexReader(BaseReader):
    """
    A wrapper for any BaseReader from LlamaIndex.
    """
    def __init__(self, base_reader: BaseReader, strict_mode: bool = True):
        if not LLAMAINDEX_AVAILABLE:
            raise ImportError("LlamaIndex is not installed. Run 'pip install llama-index-core'")
            
        self.base_reader = base_reader
        self.strict_mode = strict_mode

    def load_data(self, file: Path, extra_info: dict = None) -> List['Document']:
        """Intercepting the file reading."""
        file_path = Path(file)
        logger.info(f"🛡️ Veritensor: Scanning {file_path.name} before ingestion...")

        threats = scan_document(file_path)

        if threats:
            threat_msg = "\n".join(threats)
            if self.strict_mode:
                raise VeritensorSecurityError(
                    f"Blocked ingestion of {file_path.name} due to security threats:\n{threat_msg}"
                )
            else:
                logger.warning(f"⚠️ Veritensor Security Warning for {file_path.name}:\n{threat_msg}")

        logger.info(f"✅ Veritensor: {file_path.name} is clean.")
        return self.base_reader.load_data(file, extra_info=extra_info)
