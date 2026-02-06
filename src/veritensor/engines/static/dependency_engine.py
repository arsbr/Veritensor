# Copyright 2026 Veritensor Security Apache 2.0
# Dependency Scanner: Detects Typosquatting, Malware, and CVEs (via OSV.dev)

import logging
import re
import json
import requests
from pathlib import Path
from typing import List, Set, Dict, Optional

logger = logging.getLogger(__name__)

# --- Configuration ---
OSV_API_URL = "https://api.osv.dev/v1/querybatch"
MAX_LOCK_FILE_SIZE = 5 * 1024 * 1024  # 5 MB Limit for lock files

# --- Optional Imports ---
try:
    # Python 3.11+ native TOML support
    import tomllib
except ImportError:
    tomllib = None

# --- Known Malware DB (MVP) ---
KNOWN_MALICIOUS = {
    "tourch", "pytorch-nightly-cpu", "request", "colorama-color", 
    "discord-py-slash-command", "py-cord-slash", "huggingface-cli-tool",
    "pndas", "tenssorflow", "cryptographyy"
}

# Popular packages for Typosquatting checks
POPULAR_PACKAGES = {
    "torch", "tensorflow", "requests", "numpy", "pandas", "scikit-learn",
    "transformers", "huggingface-hub", "flask", "django", "fastapi", "boto3"
}

def scan_dependencies(file_path: Path) -> List[str]:
    """
    Scans dependency files for:
    1. Typosquatting (fake packages)
    2. Known Malware (names)
    3. Vulnerabilities (CVEs/OSV IDs via OSV.dev API)
    """
    threats = []
    filename = file_path.name.lower()
    
    try:
        # Dictionary mapping: { "package_name": "version_string" or None }
        dependencies = {}
        
        # 1. Parse File based on type
        if filename == "requirements.txt":
            dependencies = _parse_requirements(file_path)
        elif filename == "pyproject.toml":
            dependencies = _parse_pyproject(file_path)
        elif filename == "poetry.lock":
            dependencies = _parse_poetry_lock(file_path)
        elif filename == "pipfile.lock":
            dependencies = _parse_pipfile_lock(file_path)
        
        if not dependencies:
            return []

        # 2. Static Analysis (Typos & Malware)
        for pkg_name in dependencies.keys():
            pkg_norm = _normalize_name(pkg_name)
            
            # A. Check against Known Malware
            if pkg_norm in { _normalize_name(m) for m in KNOWN_MALICIOUS }:
                threats.append(f"CRITICAL: Known malicious package detected: '{pkg_name}'")
            
            # B. Typosquatting Check
            for popular in POPULAR_PACKAGES:
                pop_norm = _normalize_name(popular)
                if pkg_norm != pop_norm and _is_typo(pkg_norm, pop_norm):
                    threats.append(f"HIGH: Potential Typosquatting: '{pkg_name}' looks like '{popular}'")
                    break

        # 3. Dynamic Analysis (OSV.dev CVE Check)
        pinned_packages = {k: _clean_version(v) for k, v in dependencies.items() if v}
        pinned_packages = {k: v for k, v in pinned_packages.items() if v} # Filter out None
        
        if pinned_packages:
            cve_threats = _check_osv_batch(pinned_packages)
            threats.extend(cve_threats)

    except Exception as e:
        logger.warning(f"Dependency scan failed for {file_path}: {e}")
        threats.append(f"WARNING: Dependency Scan Error: {str(e)}")

    return threats

def _normalize_name(name: str) -> str:
    """Normalizes package names to lowercase and replaces underscores with hyphens."""
    return re.sub(r"[-_.]+", "-", name).lower()

def _is_typo(s1: str, s2: str) -> bool:
    """
    Calculates if s1 is a typo of s2 (Levenshtein Distance = 1).
    Handles substitutions, insertions, and deletions.
    """
    s1 = _normalize_name(s1)
    s2 = _normalize_name(s2)

    # 2. If they are identical after normalization, it's NOT a typo (Distance 0)
    if s1 == s2:
        return False

    n, m = len(s1), len(s2)
    if abs(n - m) > 1:
        return False

    if n == m:
        # Substitution case (e.g., torch -> turch)
        return sum(1 for a, b in zip(s1, s2) if a != b) == 1

    # Insertion/Deletion case: ensure s1 is shorter
    if n > m:
        s1, s2 = s2, s1
        n, m = m, n

    i = j = diffs = 0
    while i < n and j < m:
        if s1[i] != s2[j]:
            diffs += 1
            j += 1 # Skip char in longer string
            if diffs > 1:
                return False
        else:
            i += 1
            j += 1
    return True

def _clean_version(v: str) -> Optional[str]:
    """Cleans version strings for OSV API (removes operators like ^, ~, ==)."""
    if not v: return None
    v = re.sub(r'^[=~^<>! ]+', '', v).strip()
    # Skip git hashes, file paths, or unusually long strings
    if "git+" in v or "file:" in v or len(v) > 40 or not v:
        return None
    return v

def _check_osv_batch(packages: Dict[str, str]) -> List[str]:
    """Queries OSV.dev API in a single batch request."""
    threats = []
    payload = {"queries": []}
    pkg_list = [] 
    
    for name, version in packages.items():
        payload["queries"].append({
            "package": {"name": name, "ecosystem": "PyPI"},
            "version": version
        })
        pkg_list.append((name, version))
    
    if not payload["queries"]:
        return []
        
    try:
        response = requests.post(OSV_API_URL, json=payload, timeout=5)
        if response.status_code != 200:
            logger.debug(f"OSV API Error {response.status_code}: {response.text}")
            return []
            
        results = response.json().get("results", [])
        for i, res in enumerate(results):
            if "vulns" in res:
                name, ver = pkg_list[i]
                for vuln in res["vulns"]:
                    v_id = vuln.get("id", "UNKNOWN")
                    summary = vuln.get("summary", "Security vulnerability detected")
                    threats.append(f"HIGH: Vulnerability in {name}=={ver}: [{v_id}] {summary}")
                    
    except Exception as e:
        logger.debug(f"OSV connection failed: {e}")
        
    return threats

def _parse_requirements(path: Path) -> Dict[str, Optional[str]]:
    deps = {}
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "-", "git+", "http")): continue
            
            # Split by version operators or environment markers
            name_part = re.split(r'[=<>~! ;\[]', line)[0].strip()
            version_match = re.search(r'==([0-9a-zA-Z.-]+)', line)
            deps[name_part] = version_match.group(1) if version_match else None
    except Exception:
        pass
    return deps

def _parse_pyproject(path: Path) -> Dict[str, Optional[str]]:
    deps = {}
    try:
        if tomllib:
            with open(path, "rb") as f:
                data = tomllib.load(f)
            
            # 1. Poetry Style
            poetry = data.get("tool", {}).get("poetry", {})
            for section in ["dependencies", "dev-dependencies"]:
                for name, val in poetry.get(section, {}).items():
                    if name == "python": continue
                    deps[name] = val.get("version") if isinstance(val, dict) else str(val)
            
            # 2. PEP-621 Style
            project = data.get("project", {})
            for item in project.get("dependencies", []) + project.get("optional-dependencies", []):
                if isinstance(item, str):
                    name = re.split(r'[ ;\[>=<~!]', item)[0]
                    ver = re.search(r'==([0-9a-zA-Z.-]+)', item)
                    deps[name] = ver.group(1) if ver else None
        else:
            # Fallback regex parsing
            content = path.read_text(encoding="utf-8")
            matches = re.findall(r'^\s*([a-zA-Z0-9_-]+)\s*=\s*"(.*?)"', content, re.MULTILINE)
            for name, ver in matches:
                if name not in ["python", "version", "name"]:
                    deps[name] = ver
    except Exception: pass
    return deps

def _parse_poetry_lock(path: Path) -> Dict[str, Optional[str]]:
    deps = {}
    if path.stat().st_size > MAX_LOCK_FILE_SIZE: return {}
    try:
        if tomllib:
            with open(path, "rb") as f:
                data = tomllib.load(f)
                for pkg in data.get("package", []):
                    deps[pkg.get("name")] = pkg.get("version")
        else:
            content = path.read_text(encoding="utf-8")
            blocks = content.split("[[package]]")
            for block in blocks[1:]:
                n = re.search(r'name\s*=\s*"(.*?)"', block)
                v = re.search(r'version\s*=\s*"(.*?)"', block)
                if n and v: deps[n.group(1)] = v.group(1)
    except Exception: pass
    return deps

def _parse_pipfile_lock(path: Path) -> Dict[str, Optional[str]]:
    deps = {}
    if path.stat().st_size > MAX_LOCK_FILE_SIZE: return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for section in ["default", "develop"]:
            for name, info in data.get(section, {}).items():
                ver = info.get("version", "").lstrip("=")
                deps[name] = ver if ver and ver != "*" else None
    except Exception: pass
    return deps
