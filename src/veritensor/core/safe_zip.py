
import zipfile
import logging

logger = logging.getLogger(__name__)

class ZipBombError(Exception):
    pass

class SafeZipReader:
    # Limits: 2 GB decompressed, compression ratio 100x
    MAX_UNZIPPED_SIZE = 2 * 1024 * 1024 * 1024 
    MAX_RATIO = 100 

    @staticmethod
    def validate(zfile: zipfile.ZipFile):
        """
        Iterates through zip headers to detect Zip Bombs without extracting.
        """
        total_size = 0
        for info in zfile.infolist():
            # Protection against endless file names
            if len(info.filename) > 1024:
                raise ZipBombError(f"Filename too long in zip: {info.filename[:50]}...")

            # Checking the compression ratio
            if info.file_size > 0 and info.compress_size > 0:
                ratio = info.file_size / info.compress_size
                if ratio > SafeZipReader.MAX_RATIO:
                    raise ZipBombError(f"Zip Bomb detected! Ratio {ratio:.1f}x exceeds limit.")
            
            total_size += info.file_size
        
        # Checking the total size
        if total_size > SafeZipReader.MAX_UNZIPPED_SIZE:
             raise ZipBombError(f"Zip Bomb detected! Total unzipped size {total_size} bytes exceeds limit.")
