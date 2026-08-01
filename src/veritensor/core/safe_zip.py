import zipfile
import logging
import os

logger = logging.getLogger(__name__)

class ZipBombError(Exception):
    pass

class SafeZipReader:
    # Limits: 2 GB decompressed, compression ratio 100x
    MAX_UNZIPPED_SIZE = 2 * 1024 * 1024 * 1024 
    MAX_RATIO = 20
    MIN_SIZE_FOR_RATIO = 10 * 1024 * 1024 

    @staticmethod
    def validate(zfile: zipfile.ZipFile):
        """
        Iterates through zip headers to detect Zip Bombs without extracting.
        """
        total_size = 0
        for info in zfile.infolist():
            # Protection against endless file names
            target = os.path.normpath(os.path.join("safe_root", info.filename))
            if not target.startswith("safe_root" + os.sep) and target != "safe_root":
                raise ZipBombError(f"Path traversal detected in ZIP entry: {info.filename}")

            # Checking the compression ratio
            if info.file_size > SafeZipReader.MIN_SIZE_FOR_RATIO and info.compress_size > 0:
                ratio = info.file_size / info.compress_size
                if ratio > SafeZipReader.MAX_RATIO:
                    raise ZipBombError(f"Zip Bomb detected! Ratio {ratio:.1f}x exceeds limit.")
            
            total_size += info.file_size
        
            # Checking the total size
            if total_size > SafeZipReader.MAX_UNZIPPED_SIZE:
                raise ZipBombError(f"Zip Bomb detected! Total unzipped size {total_size} bytes exceeds limit.")

    def read(self, zfile: zipfile.ZipFile, name: str) -> bytes:
        info = zfile.getinfo(name)
        if info.file_size > self.MAX_UNZIPPED_SIZE:
            raise ZipBombError(f"File {name} is too large")
        return zfile.read(name)
