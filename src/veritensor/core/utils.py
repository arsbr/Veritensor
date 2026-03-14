# src/veritensor/core/utils.py
import zipfile
import logging

logger = logging.getLogger(__name__)

# Security Limits for Zip Extraction
MAX_UNCOMPRESSED_SIZE = 1 * 1024 * 1024 * 1024  # 1 GB per file limit
MAX_RATIO = 100  # Compression ratio limit (10MB -> 1GB is suspicious)

class SafeZipReader:
    """
    Wrapper around zipfile.ZipFile to prevent Zip Bomb attacks (DoS).
    """
    def __init__(self, file, mode="r"):
        self.zip_file = zipfile.ZipFile(file, mode)

    def namelist(self):
        return self.zip_file.namelist()

    def read(self, name):
        """Reads a file from zip with security checks."""
        info = self.zip_file.getinfo(name)
        
        # Check 1: Uncompressed Size Limit
        if info.file_size > MAX_UNCOMPRESSED_SIZE:
            logger.warning(f"Zip Bomb prevention: File {name} is too large ({info.file_size} bytes). Skipping.")
            return b"" # Return empty to avoid crash, threat logic should handle empty context

        # Check 2: Compression Ratio (if compressed)
        if info.compress_size > 0:
            ratio = info.file_size / info.compress_size
            if ratio > MAX_RATIO:
                logger.warning(f"Zip Bomb prevention: File {name} has abnormal compression ratio ({ratio:.2f}). Skipping.")
                return b""

        return self.zip_file.read(name)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.zip_file.close()
