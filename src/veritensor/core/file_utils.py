# Copyright 2026 Veritensor Security Apache 2.0
# File Utilities: Magic Numbers and Integrity Checks

import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Known Magic Numbers (Signatures)
FILE_SIGNATURES = {
    '.pdf': b'%PDF',
    '.png': b'\x89PNG\r\n\x1a\n',
    '.jpg': b'\xff\xd8\xff',
    '.jpeg': b'\xff\xd8\xff',
    '.zip': b'PK\x03\x04',
    '.whl': b'PK\x03\x04', # Wheels are zips
    '.docx': b'PK\x03\x04', # Docx are zips
    '.xlsx': b'PK\x03\x04', # Xlsx are zips
    '.exe': b'MZ',
    '.elf': b'\x7fELF',
    '.sh': b'#!', # Shebang
    '.py': [b'import ', b'#', b'from '] # Heuristic for scripts
}

def validate_file_extension(file_path: Path) -> Optional[str]:
    """
    Checks if the file header matches its extension.
    Returns a threat string if a mismatch is found (e.g. PDF file with EXE header).
    Returns None if safe or unknown.
    """
    ext = file_path.suffix.lower()
    
    # If we don't have a signature for this extension, skip
    if ext not in FILE_SIGNATURES:
        return None

    try:
        with open(file_path, "rb") as f:
            header = f.read(16) # Read enough bytes
            
        expected_sig = FILE_SIGNATURES[ext]
        
        # Handle list of signatures (like for .py)
        if isinstance(expected_sig, list):
            match = any(header.startswith(sig) for sig in expected_sig)
            # Scripts are hard to validate by magic number, so we are lenient
            # If it doesn't match, we don't flag it immediately unless it looks like binary
            if not match and header.startswith(b'MZ'):
                 return f"CRITICAL: Executable (MZ) disguised as script '{file_path.name}'"
            return None

        # Strict check for binaries
        if not header.startswith(expected_sig):
            # Check if it's actually an executable disguised
            if header.startswith(b'MZ') or header.startswith(b'\x7fELF'):
                return f"CRITICAL: Executable malware disguised as '{ext}' file: '{file_path.name}'"
            
            # General mismatch (e.g. PDF is actually a Text file - less critical, but suspicious)
            # We return None for minor mismatches to avoid noise, focusing on Malware masquerading.
            
    except Exception as e:
        logger.debug(f"Magic number check failed: {e}")
        
    return None
