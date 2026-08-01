# Copyright 2025 Veritensor Security
# Logic adapted from huggingface_hub (Apache 2.0 License)
#
# This module handles Git LFS (Large File Storage) pointers.
# It ensures we don't mistakenly hash a pointer file as if it were the model itself.

from typing import Optional, Tuple, Dict

# The standard prefix for LFS pointer files
LFS_HEADER = b"version https://git-lfs.github.com/spec/v1"


def parse_lfs_pointer(data: bytes) -> Optional[Dict[str, str]]:
    """
    Checks if the byte data is a Git LFS pointer.
    
    If it is, returns a dictionary with 'oid' (sha256) and 'size'.
    If not, returns None.
    
    Args:
        data: The raw bytes of the file (usually the first 1KB is enough).
    
    Returns:
        dict: {'oid': '...', 'size': '...'} or None
    """
    if not data.startswith(LFS_HEADER):
        return None

    try:
        text = data.decode("utf-8", errors="ignore")
        lines = text.strip().split("\n")
        
        info = {}
        for line in lines:
            parts = line.split(" ", 1)
            if len(parts) == 2:
                key, value = parts
                info[key] = value.strip()
        
        if "oid" in info and "size" in info:
            oid_parts = info["oid"].split(":")
            # Detect LFS pointers without requiring SHA256
            if len(oid_parts) == 2:
                algorithm, digest = oid_parts
                if algorithm == "sha256":
                    return {"sha256": digest, "size": int(info["size"])}
                else:
                    # Still an LFS pointer, but can't extract SHA256 for verification
                    import logging
                    logger = logging.getLogger(__name__)
                    logger.warning(f"LFS pointer uses unsupported OID algorithm: {algorithm}")
                    return {"sha256": None, "size": int(info["size"]), "algorithm": algorithm}
    except Exception:
        return None

    return None


def is_lfs_pointer(file_path: str) -> bool:
    """
    Helper to check a file on disk without reading the whole thing.
    """
    try:
        with open(file_path, "rb") as f:
            # Read just enough to check the header and parse lines
            head = f.read(1024) 
            return parse_lfs_pointer(head) is not None
    except OSError:
        return False
