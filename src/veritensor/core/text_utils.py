# Copyright 2026 Veritensor Security Apache 2.0
# Text Utilities: Normalization, Steganography, and De-obfuscation

import unicodedata
import re
import base64
import binascii
from typing import List

# Zero-width spaces and control characters used for hiding text
INVISIBLE_CHARS = {
    '\u200b', '\u200c', '\u200d', '\u2060', '\ufeff', 
    '\u202a', '\u202b', '\u202c', '\u202d', '\u202e'
}

# Pattern for Snow/Whitespace steganography (trailing spaces/tabs)
SNOW_STEGO_PATTERN = re.compile(r'[ \t]{2,}$', re.MULTILINE)

# Pattern for potential Base64 strings (no spaces, length >= 20, valid chars)
B64_PATTERN = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')

def normalize_text(text: str) -> str:
    """
    Normalizes text to NFKC form to prevent Unicode bypass attacks.
    Example: 'I' (Cyrillic) -> 'I' (Latin).
    """
    if not text:
        return ""
    return unicodedata.normalize('NFKC', text)

def detect_stealth_text(text: str) -> List[str]:
    """
    Analyzes text for steganography and hiding techniques.
    """
    threats = []
    
    # 1. Zero-Width / Invisible Characters Check
    invisible_count = sum(1 for char in text if char in INVISIBLE_CHARS)
    if invisible_count > 5: # Threshold to avoid false positives
        threats.append(f"MEDIUM: High count of invisible characters ({invisible_count}). Possible steganography.")

    # 2. Whitespace Steganography (Snow)
    matches = SNOW_STEGO_PATTERN.findall(text)
    if len(matches) > 10: 
        threats.append("LOW: Anomalous trailing whitespace patterns. Possible Snow steganography.")

    return threats

def extract_base64_content(text: str) -> List[str]:
    """
    Finds Base64-encoded strings, decodes them, and returns the decoded text
    IF it looks like readable content.
    """
    decoded_fragments = []
    matches = B64_PATTERN.findall(text)
    
    for b64_str in matches:
        try:
            decoded_bytes = base64.b64decode(b64_str)
            decoded_text = decoded_bytes.decode('utf-8')
            
            if _is_readable_text(decoded_text):
                decoded_fragments.append(decoded_text)
                
        except (binascii.Error, UnicodeDecodeError):
            continue
            
    return decoded_fragments

def _is_readable_text(text: str) -> bool:
    """Checks if text is mostly printable characters."""
    if not text: return False
    printable = sum(1 for c in text if c.isprintable() or c in '\n\r\t')
    return (printable / len(text)) > 0.9
