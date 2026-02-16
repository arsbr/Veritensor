# Copyright 2026 Veritensor Security Apache 2.0
# Archive Scanner (.zip, .tar)

import logging
import zipfile
import tarfile
from pathlib import Path
from typing import List
from veritensor.core.safe_zip import SafeZipReader, ZipBombError

logger = logging.getLogger(__name__)

DANGEROUS_EXTENSIONS = {
    ".exe", ".bat", ".ps1", ".sh", ".vbs", ".jar", ".apk", ".scr"
}

def scan_archive(file_path: Path) -> List[str]:
    threats = []
    ext = file_path.suffix.lower()

    try:
        if ext == ".zip" or ext == ".whl": # Wheels are zips too
            threats.extend(_scan_zip(file_path))
        elif ext in {".tar", ".gz", ".tgz"}:
            threats.extend(_scan_tar(file_path))
            
    except Exception as e:
        logger.warning(f"Archive scan error {file_path}: {e}")
        threats.append(f"WARNING: Archive Scan Error: {str(e)}")

    return threats

def _scan_zip(path: Path) -> List[str]:
    threats = []
    try:
        with zipfile.ZipFile(path, 'r') as z:
            # 1. Security Check (Zip Bomb)
            SafeZipReader.validate(z)
            
            # 2. File Listing Analysis
            for info in z.infolist():
                fname = info.filename
                fext = Path(fname).suffix.lower()
                
                # Check for executable malware inside archive
                if fext in DANGEROUS_EXTENSIONS:
                    threats.append(f"HIGH: Executable found inside archive: '{fname}'")
                
                # Check for nested archives (Zip Bomb trait)
                if fext in {".zip", ".tar", ".gz", ".rar"}:
                    threats.append(f"MEDIUM: Nested archive found: '{fname}' (Possible evasion)")

    except ZipBombError as e:
        threats.append(f"CRITICAL: {str(e)}")
    except zipfile.BadZipFile:
        pass
        
    return threats

def _scan_tar(path: Path) -> List[str]:
    threats = []
    try:
        # Tarfiles don't have a central directory like Zip, so we iterate
        with tarfile.open(path, 'r:*') as tar:
            for member in tar:
                if not member.isfile(): continue
                
                fname = member.name
                fext = Path(fname).suffix.lower()
                
                if fext in DANGEROUS_EXTENSIONS:
                    threats.append(f"HIGH: Executable found inside tarball: '{fname}'")
                    
    except tarfile.TarError:
        pass
    return threats
