import pytest
from veritensor.core.text_utils import normalize_text, detect_stealth_text

def test_normalize_unicode():
    # Cyrillic 'a' vs Latin 'a'
    cyrillic_a = "\u0430"
    latin_a = "a"
    
    # Visual check (they look same)
    assert cyrillic_a != latin_a
    
    # Normalization check (NFKC converts compatible chars)
    # Note: NFKC doesn't always map Cyrillic to Latin directly unless they are compatibility chars,
    # but it handles half-width/full-width and other bypasses.
    # Let's test Full-width 'Ａ' (U+FF21) -> 'A'
    full_width_A = "\uff21"
    assert normalize_text(full_width_A) == "A"

def test_stealth_invisible_chars():
    # Text with Zero Width Spaces
    text = "Normal\u200bText\u200bHidden"
    threats = detect_stealth_text(text)
    assert len(threats) == 0 # 2 chars is below threshold 5

    # Heavy obfuscation
    heavy_text = "H\u200bi\u200bd\u200bd\u200be\u200bn"
    threats = detect_stealth_text(heavy_text)
    assert len(threats) > 0
    assert "invisible characters" in threats[0]

def test_stealth_snow_whitespace():
    # Text with trailing spaces (Snow steganography pattern)
    text = "Line1 \nLine2  \nLine3   \nLine4    \n" * 5
    threats = detect_stealth_text(text)
    assert len(threats) > 0
    assert "whitespace patterns" in threats[0]
