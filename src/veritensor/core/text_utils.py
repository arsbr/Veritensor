# Copyright 2026 Veritensor Security Apache 2.0
# Text Utilities: Normalization, Steganography, and De-obfuscation

import unicodedata
import re
import base64
import binascii
from typing import List

# Patterns of invisible symbols (Zero-width spaces, controls)
# Often used to hide payloads or watermarksINVISIBLE_CHARS = {
    '\u200b', '\u200c', '\u200d', '\u2060', '\ufeff', 
    '\u202a', '\u202b', '\u202c', '\u202d', '\u202e'
}
SNOW_STEGO_PATTERN = re.compile(r'[ \t]{2,}$', re.MULTILINE)

# Pattern for potential Base64 strings (no spaces, length >= 20, valid chars)
B64_PATTERN = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')

def normalize_text(text: str) -> str:
    if not text: return ""
    return unicodedata.normalize('NFKC', text)

def detect_stealth_text(text: str) -> List[str]:
    threats = []
    invisible_count = sum(1 for char in text if char in INVISIBLE_CHARS)
    if invisible_count > 5:
        threats.append(f"MEDIUM: High count of invisible characters ({invisible_count}). Possible steganography.")
    
    matches = SNOW_STEGO_PATTERN.findall(text)
    if len(matches) > 10:
        threats.append("LOW: Anomalous trailing whitespace patterns. Possible Snow steganography.")
    return threats

def extract_base64_content(text: str) -> List[str]:
    """
    Finds Base64-encoded strings, decodes them, and returns the decoded text
    IF it looks like readable content (not binary garbage).
    """
    decoded_fragments = []
    
    # Find all potential base64 strings
    matches = B64_PATTERN.findall(text)
    
    for b64_str in matches:
        try:
            # Decode
            decoded_bytes = base64.b64decode(b64_str)
            
            # Try to decode as UTF-8
            decoded_text = decoded_bytes.decode('utf-8')
            
            # Heuristic: Is it readable text?
            # If it contains too many control characters, it's likely binary (image/zip), skip it.
            # We allow newlines, tabs, etc.
            if _is_readable_text(decoded_text):
                decoded_fragments.append(decoded_text)
                
        except (binascii.Error, UnicodeDecodeError):
            continue
            
    return decoded_fragments

def _is_readable_text(text: str) -> bool:
    """Checks if text is mostly printable characters."""
    if not text: return False
    # Allow some non-printable, but mostly should be text
    printable = sum(1 for c in text if c.isprintable() or c in '\n\r\t')
    return (printable / len(text)) > 0.9
