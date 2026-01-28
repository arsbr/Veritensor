# Copyright 2025 Veritensor Security Apache 2.0
# RAG Scanner: Detects Prompt Injections in text files.

import logging
from typing import List
from pathlib import Path
from veritensor.engines.static.rules import SignatureLoader, is_match

logger = logging.getLogger(__name__)

# Supported text formats for RAG scanning
TEXT_EXTENSIONS = {".txt", ".md", ".json", ".csv", ".xml", ".yaml", ".yml"}

def scan_text_file(file_path: Path) -> List[str]:
    threats = []
    signatures = SignatureLoader.get_prompt_injections()
    
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f):
               
                if len(line) > 4096: 
                    line = line[:4096] 
                
                if is_match(line, signatures):
                    for pattern in signatures:
                        if is_match(line, [pattern]):
                            threats.append(f"HIGH: Prompt Injection detected (line {i+1}): '{pattern}'")
                            return threats # Fail fast
                            
    except Exception as e:
        logger.warning(f"Failed to scan text file {file_path}: {e}")
        
    return threats

