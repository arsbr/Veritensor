# Copyright 2026 Veritensor Security Apache 2.0
# Text Utilities: Normalization and Steganography Detection

import unicodedata
import re
from typing import List, Tuple

# Patterns of invisible symbols (Zero-width spaces, controls)
# Often used to hide payloads or watermarks
INVISIBLE_CHARS = {
    '\u200b', # Zero Width Space
    '\u200c', # Zero Width Non-Joiner
    '\u200d', # Zero Width Joiner
    '\u2060', # Word Joiner
    '\ufeff', # Zero Width No-Break Space
    '\u202a', '\u202b', '\u202c', '\u202d', '\u202e' # Directional formatting
}

# Patterns for Snow/Whitespace steganography (tails of spaces/tabs at the end of lines)
SNOW_STEGO_PATTERN = re.compile(r'[ \t]{2,}$', re.MULTILINE)

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
    Returns a list of detected threats.
    """
    threats = []
    
    # 1. Zero-Width / Invisible Characters Check
    invisible_count = sum(1 for char in text if char in INVISIBLE_CHARS)
    if invisible_count > 5: # Threshold to avoid false positives on bad encoding
        threats.append(f"MEDIUM: High count of invisible characters ({invisible_count}). Possible steganography or obfuscation.")

    # 2. Whitespace Steganography (Snow)
    # Looking for an abnormal number of spaces at the end of lines
    matches = SNOW_STEGO_PATTERN.findall(text)
    if len(matches) > 10: # If a lot of lines end in a bunch of spaces
        threats.append("LOW: Anomalous trailing whitespace patterns. Possible Snow/Whitespace steganography.")

    return threats
