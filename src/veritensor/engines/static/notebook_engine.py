# Copyright 2026 Veritensor Security Apache 2.0
# Jupyter Notebook Scanner (.ipynb)

import json
import ast
import logging
from pathlib import Path
from typing import List, Any
from veritensor.engines.static.rules import get_severity, SignatureLoader, is_match

logger = logging.getLogger(__name__)

# Jupyter "Magic" commands that execute shell code
DANGEROUS_MAGICS = [
    "!", "%%bash", "%%sh", "%%script", "%%perl", "%%ruby", "%system"
]

# Limit output scanning to prevent DoS on large logs (Critical for stability)
MAX_OUTPUT_SCAN_SIZE = 50 * 1024  # 50 KB

def scan_notebook(file_path: Path) -> List[str]:
    """
    Parses .ipynb JSON and scans code, outputs, and markdown for threats.
    """
    threats = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            try:
                nb_data = json.load(f)
            except json.JSONDecodeError:
                return ["WARNING: Invalid JSON in .ipynb file"]
            
        if "cells" not in nb_data:
            return []

        # Load signatures
        secret_patterns = SignatureLoader.get_suspicious_strings()
        injection_patterns = SignatureLoader.get_prompt_injections()

        for i, cell in enumerate(nb_data["cells"]):
            cell_num = i + 1
            cell_type = cell.get("cell_type", "")
            source_list = cell.get("source", [])
            outputs_list = cell.get("outputs", [])
            
            source_text = _extract_text(source_list)

            # --- A. Code Cells ---
            if cell_type == "code":
                # 1. Magics (Shell Injection)
                for line in source_text.splitlines():
                    stripped = line.strip()
                    for magic in DANGEROUS_MAGICS:
                        if stripped.startswith(magic):
                            threats.append(f"HIGH: Jupyter Magic detected in cell {cell_num}: '{stripped[:30]}...'")

                # 2. AST (Python Code Analysis)
                # Cleaning magics while preserving line numbers
                clean_source = _clean_magics(source_text)
                if clean_source.strip():
                    threats.extend(_scan_ast(clean_source, cell_num))
                
                # 3. Output Secrets (Leaked Keys)
                for output in outputs_list:
                    output_type = output.get("output_type")
                    text_content = ""
                    if output_type == "stream":
                        text_content = _extract_text(output.get("text", []))
                    elif output_type == "execute_result":
                        data = output.get("data", {})
                        text_content = _extract_text(data.get("text/plain", []))
                    
                    if text_content:
                        # Optimization: Scan only the beginning of large outputs
                        scan_content = text_content[:MAX_OUTPUT_SCAN_SIZE]
                        if is_match(scan_content, secret_patterns):
                            # Double check to report exactly which pattern matched
                            for pat in secret_patterns:
                                if is_match(scan_content, [pat]):
                                    threats.append(f"CRITICAL: Leaked secret detected in Cell {cell_num} Output: '{pat}'")

            # --- B. Markdown Cells (RAG Security) ---
            elif cell_type == "markdown":
                # RAG Poisoning / Prompt Injection
                if is_match(source_text, injection_patterns):
                    for pat in injection_patterns:
                        if is_match(source_text, [pat]):
                            threats.append(f"HIGH: Prompt Injection detected in Markdown Cell {cell_num}: '{pat}'")
                
                # Phishing / XSS
                lower_source = source_text.lower()
                if "javascript:" in lower_source or "data:text/html" in lower_source:
                     threats.append(f"MEDIUM: Suspicious script/XSS in Markdown Cell {cell_num}")

    except Exception as e:
        logger.error(f"Failed to scan notebook {file_path}: {e}")
        threats.append(f"WARNING: Notebook Scan Error: {str(e)}")

    return threats

def _extract_text(content: Any) -> str:
    """Helper to handle both list of strings and single string formats."""
    if isinstance(content, list):
        return "".join(content)
    if isinstance(content, str):
        return content
    return ""

def _clean_magics(source: str) -> str:
    """Replaces magics with comments to allow AST parsing while keeping line numbers."""
    lines = []
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("!") or stripped.startswith("%"):
            lines.append("# " + line) 
        else:
            lines.append(line)
    return "\n".join(lines)

def _scan_ast(code: str, cell_num: int) -> List[str]:
    threats = []
    try:
        tree = ast.parse(code)
        
        for node in ast.walk(tree):
            # Check Imports
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = []
                if isinstance(node, ast.Import):
                    names = [n.name for n in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module]
                
                for name in names:
                    severity = get_severity(name, "*")
                    if severity == "CRITICAL":
                        threats.append(f"CRITICAL: Unsafe import in cell {cell_num}: '{name}'")

            # Check Function Calls
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name):
                        module = node.func.value.id
                        method = node.func.attr
                        severity = get_severity(module, method)
                        if severity:
                            threats.append(f"{severity}: Dangerous call in cell {cell_num}: {module}.{method}()")
                elif isinstance(node.func, ast.Name):
                    func_name = node.func.id
                    severity = get_severity("builtins", func_name)
                    if severity:
                        threats.append(f"{severity}: Dangerous call in cell {cell_num}: {func_name}()")
    except Exception:
        pass
    return threats
