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

MAX_ARCHIVE_FILES = 10000 # File limit to protect against endless loops

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
    threats =[]
    try:
        with zipfile.ZipFile(path, 'r') as z:
            SafeZipReader.validate(z)
            
            # Protection from a huge number of files 
            file_list = z.infolist()
            if len(file_list) > MAX_ARCHIVE_FILES:
                return[f"CRITICAL: Archive contains too many files (> {MAX_ARCHIVE_FILES}). Possible Zip Bomb."]

            for info in file_list:
                fname = info.filename
                fext = Path(fname).suffix.lower()
                
                if fext in DANGEROUS_EXTENSIONS:
                    threats.append(f"HIGH: Executable found inside archive: '{fname}'")
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
            file_count = 0
            
            for member in tar:
                file_count += 1
                
                # Protection against Tar bombs and infinite loops
                if file_count > MAX_ARCHIVE_FILES:
                    threats.append(f"CRITICAL: Archive contains too many files (> {MAX_ARCHIVE_FILES}). Possible Tar Bomb.")
                    break
                    
                if not member.isfile(): continue
                
                fname = member.name
                fext = Path(fname).suffix.lower()
                
                if fext in DANGEROUS_EXTENSIONS:
                    threats.append(f"HIGH: Executable found inside tarball: '{fname}'")
                    
    except tarfile.TarError:
        pass
    return threats
