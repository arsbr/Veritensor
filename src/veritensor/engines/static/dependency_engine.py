# Copyright 2026 Veritensor Security Apache 2.0
# Dependency Scanner: Detects Typosquatting and Malicious Packages in AI projects.

import logging
import re
from pathlib import Path
from typing import List, Set, Optional

logger = logging.getLogger(__name__)

# --- Threat Database ---
# Known malicious packages mimicking popular ML libraries
KNOWN_MALICIOUS = {
    "tourch", "pytorch-nightly-cpu", "request", "colorama-color", 
    "discord-py-slash-command", "py-cord-shell", "huggingface-cli",
    "pndas", "tenssorflow", "cryptographyy"
}

# Popular packages used for Typosquatting detection
POPULAR_PACKAGES = {
    "torch", "tensorflow", "requests", "numpy", "pandas", "scikit-learn",
    "transformers", "huggingface-hub", "flask", "django", "fastapi", "cryptography"
}

def scan_dependencies(file_path: Path) -> List[str]:
    """
    Main entry point for scanning dependency files (requirements.txt, pyproject.toml).
    """
    threats = []
    filename = file_path.name.lower()
    
    try:
        packages = set()
        
        # 1. Parse based on file format
        if filename == "requirements.txt":
            packages = _parse_requirements(file_path)
        elif filename == "pyproject.toml":
            packages = _parse_toml(file_path)
        
        if not packages:
            return []

        # 2. Analyze each package
        for pkg in packages:
            pkg_lower = pkg.lower().strip()
            if not pkg_lower: continue
            
            # A. Check against known malware list
            if pkg_lower in KNOWN_MALICIOUS:
                threats.append(f"CRITICAL: Known malicious package detected: '{pkg}'")
            
            # B. Check for Typosquatting (Edit distance analysis)
            for popular in POPULAR_PACKAGES:
                if pkg_lower != popular and _is_typo(pkg_lower, popular):
                    threats.append(f"HIGH: Potential Typosquatting: '{pkg}' looks very similar to '{popular}'")
                    break # One match is sufficient for an alert

    except Exception as e:
        logger.warning(f"Dependency scan failed for {file_path}: {e}")
        threats.append(f"WARNING: Dependency Scan Error: {str(e)}")

    return threats

def _is_typo(s1: str, s2: str) -> bool:
    """
    Implementation of Levenshtein distance (limited to distance = 1).
    Detects substitutions (turch), deletions (toch), or insertions (ttorch).
    """
    n, m = len(s1), len(s2)
    if abs(n - m) > 1: 
        return False

    # Case: Substitution (torch -> turch)
    if n == m:
        diffs = sum(1 for a, b in zip(s1, s2) if a != b)
        return diffs == 1
    
    # Case: Insertion or Deletion (torch -> toch or torch -> ttorch)
    if n > m:
        s1, s2 = s2, s1 # Ensure s2 is always the longer string
    
    i = j = diffs = 0
    while i < len(s1) and j < len(s2):
        if s1[i] != s2[j]:
            diffs += 1
            j += 1 # Skip the extra character in the longer string
            if diffs > 1: 
                return False
        else:
            i += 1
            j += 1
    return True

def _parse_requirements(path: Path) -> Set[str]:
    """Parses a standard requirements.txt file."""
    pkgs = set()
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
        for line in content.splitlines():
            line = line.strip()
            # Skip comments, flags, and direct links
            if not line or line.startswith(("#", "-", "git+", "http")): 
                continue
            
            # Strip version specifiers and environment markers (e.g., numpy>=1.0)
            name = re.split(r'[=<>~! ;]', line)[0]
            if name:
                pkgs.add(name.strip())
    except Exception:
        pass
    return pkgs

def _parse_toml(path: Path) -> Set[str]:
    """Safe parsing of dependencies from pyproject.toml using Regex."""
    pkgs = set()
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
        
        # Target [tool.poetry.dependencies] and [project.dependencies] sections
        # Use re.DOTALL to capture content within brackets
        dep_sections = re.findall(r'\[(?:.*dependencies)\](.*?)(?=\n\[|$)', content, re.DOTALL)
        
        for section in dep_sections:
            # Match keys in 'package = ...' format
            matches = re.findall(r'^\s*([a-zA-Z0-9_-]+)\s*=', section, re.MULTILINE)
            for m in matches:
                # Exclude standard TOML/Project keys
                if m.lower() not in {"python", "version", "name", "description"}:
                    pkgs.add(m.strip())
    except Exception:
        pass
    return pkgs
