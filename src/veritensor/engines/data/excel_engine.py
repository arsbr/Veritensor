# Copyright 2026 Veritensor Security Apache 2.0
# Excel Scanner (.xlsx, .xlsm)

import logging
from pathlib import Path
from typing import List

from veritensor.engines.static.rules import SignatureLoader, is_match
from veritensor.engines.content.pii import PIIScanner
from veritensor.core.text_utils import normalize_text

logger = logging.getLogger(__name__)

try:
    import openpyxl
    EXCEL_AVAILABLE = True
except ImportError:
    EXCEL_AVAILABLE = False

# Formula Injection triggers (DDE, CMD execution via Excel)
FORMULA_PREFIXES = ('=', '+', '-', '@')

def scan_excel(file_path: Path) -> List[str]:
    threats = []
    if not EXCEL_AVAILABLE:
        return ["WARNING: openpyxl not installed. Run 'pip install veritensor[data]'"]

    try:
        # read_only=True is faster and uses less memory
        wb = openpyxl.load_workbook(file_path, read_only=True, data_only=False)
        
        injections = SignatureLoader.get_prompt_injections()
        
        # Scan first 5 sheets (usually enough)
        for sheet in wb.worksheets[:5]:
            # Limit rows per sheet to prevent DoS
            for i, row in enumerate(sheet.iter_rows(values_only=True, max_row=1000)):
                for cell in row:
                    if not cell or not isinstance(cell, str):
                        continue
                    
                    # 1. Formula Injection
                    if cell.startswith(FORMULA_PREFIXES):
                        # Check for dangerous commands (cmd, powershell, http)
                        if any(x in cell.lower() for x in ['cmd', 'powershell', 'http', 'exec']):
                            threats.append(f"HIGH: Excel Formula Injection detected in {file_path.name}: '{cell[:50]}'")

                    # 2. Prompt Injection
                    norm_cell = normalize_text(cell)
                    if is_match(norm_cell, injections):
                        for pat in injections:
                            if is_match(norm_cell, [pat]):
                                threats.append(f"HIGH: Prompt Injection in Excel: '{pat}'")
                                return threats # Fail fast

                    # 3. PII (Sample check - checking every cell is too slow, maybe check first 100 chars)
                    if i < 50: # Check PII only in first 50 rows
                        pii = PIIScanner.scan(cell)
                        if pii:
                            threats.extend(pii)

        wb.close()
    except Exception as e:
        logger.warning(f"Excel scan error {file_path}: {e}")
        threats.append(f"WARNING: Excel Scan Error: {str(e)}")

    return threats
