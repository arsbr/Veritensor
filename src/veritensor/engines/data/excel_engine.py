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
    import defusedxml
    import openpyxl
    EXCEL_AVAILABLE = True
except ImportError:
    EXCEL_AVAILABLE = False

# Formula Injection triggers (DDE, CMD execution via Excel)
FORMULA_PREFIXES = ('=', '+', '-', '@')

def scan_excel(file_path: Path) -> List[str]:
    threats = []
    if not EXCEL_AVAILABLE:
        return ["WARNING: openpyxl is required for local Excel scanning. Run 'pip install openpyxl' or use the Enterprise Server."]

    try:
        # read_only=True is faster and uses less memory
        wb = openpyxl.load_workbook(file_path, read_only=True, data_only=False)
        
        injections = SignatureLoader.get_prompt_injections()
        
        # Scan first 5 sheets (usually enough)
        for sheet in wb.worksheets[:5]:
            # Limit rows per sheet to prevent DoS
            for i, row in enumerate(sheet.iter_rows(values_only=True, max_row=1000)):
                for cell in row:
                    # Convert all cell values to string before checking
                    # This catches numeric-coerced strings and dates
                    cell_str = str(cell) if cell is not None else ""
                    if not cell_str:
                        continue
                    
                    # 1. Formula Injection
                    if cell_str.startswith(FORMULA_PREFIXES):
                        if any(x in cell_str.lower() for x in ['cmd', 'powershell', 'http', 'exec']):
                            threats.append(f"HIGH: Excel Formula Injection detected in {file_path.name}: '{cell_str[:50]}'")

                    # 2. Prompt Injection
                    norm_cell = normalize_text(cell_str)
                    if is_match(norm_cell, injections):
                        for pat in injections:
                            if is_match(norm_cell, [pat]):
                                threats.append(f"HIGH: Prompt Injection in Excel: '{pat}'")
                                return threats 

                    # 3. PII (Sample check)
                    if i < 50: 
                        pii = PIIScanner.scan(cell_str)
                        if pii:
                            threats.extend(pii)

        wb.close()
    except Exception as e:
        logger.warning(f"Excel scan error {file_path}: {e}")
        threats.append(f"WARNING: Excel Scan Error: {str(e)}")

    return threats

