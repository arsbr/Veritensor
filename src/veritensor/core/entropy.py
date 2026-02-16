# Copyright 2026 Veritensor Security
# Entropy calculation for Secret Detection

import math
import re
from collections import Counter

# UUID Pattern (8-4-4-4-12 hex digits)
UUID_PATTERN = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)

def calculate_shannon_entropy(data: str) -> float:
    """
    Calculates the Shannon entropy of a string.
    """
    if not data:
        return 0.0
    
    entropy = 0.0
    length = len(data)
    counts = Counter(data)
    
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
        
    return entropy

def is_high_entropy(data: str, min_length: int = 16, threshold: float = 4.5) -> bool:
    """
    Heuristic to determine if a string looks like a secret key.
    Includes filters for common false positives (UUIDs, Paths).
    """
    # 1. Filter out common false positives
    if " " in data or "/" in data or "\\" in data:
        return False
    
    # 2. Check length
    if len(data) < min_length:
        return False

    # 3. UUID Filter (New)
    # UUIDs have high entropy but are not secrets
    if UUID_PATTERN.match(data):
        return False
        
    # 4. Check Entropy
    return calculate_shannon_entropy(data) > threshold
