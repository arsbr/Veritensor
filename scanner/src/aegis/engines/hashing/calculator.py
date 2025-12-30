# Copyright 2025 Aegis Security
# Adapted from huggingface_hub (Apache 2.0 License)
#
# This module implements hashing logic identical to Hugging Face Hub
# to ensure we can verify file integrity against their registry.

import hashlib
from pathlib import Path
from typing import BinaryIO, Union, Optional

# Default chunk size used by Hugging Face (1MB).
# Using this specific size ensures consistent memory usage and performance.
DEFAULT_CHUNK_SIZE = 1024 * 1024


def calculate_sha256(
    file_input: Union[str, Path, BinaryIO], 
    chunk_size: Optional[int] = None
) -> str:
    """
    Computes the SHA256 hash of a file.
    
    This function handles both file paths and file-like objects.
    It reads the file in chunks to handle large ML models without 
    loading them entirely into RAM.

    Args:
        file_input: Path to the file or a file-like object (opened in 'rb' mode).
        chunk_size: Size of chunks to read. Defaults to 1MB.

    Returns:
        The hexadecimal SHA256 string.
    """
    chunk_size = chunk_size or DEFAULT_CHUNK_SIZE

    if isinstance(file_input, (str, Path)):
        with open(file_input, "rb") as f:
            return _compute_sha256_from_stream(f, chunk_size)
    else:
        # Assume it is a file-like object
        return _compute_sha256_from_stream(file_input, chunk_size)


def _compute_sha256_from_stream(fileobj: BinaryIO, chunk_size: int) -> str:
    """
    Internal helper to compute SHA256 from a stream.
    Matches logic from `huggingface_hub.utils.sha.sha_fileobj`.
    """
    sha = hashlib.sha256()
    
    # Save current position if possible to reset later (good practice),
    # though for streams like HTTP response it might not be seekable.
    start_pos = 0
    try:
        start_pos = fileobj.tell()
    except (OSError, AttributeError):
        pass # Stream might not be seekable

    while True:
        chunk = fileobj.read(chunk_size)
        if not chunk:
            break
        sha.update(chunk)
    
    # Try to reset cursor to start, so the file can be read again if needed
    try:
        fileobj.seek(start_pos)
    except (OSError, AttributeError):
        pass

    return sha.hexdigest()


def calculate_git_hash(data: bytes) -> str:
    """
    Computes the Git-SHA1 hash of bytes (Blob format).
    
    This is equivalent to running `git hash-object`.
    Used primarily for verifying small files (like config.json) or 
    LFS pointer files, not large model weights.

    Logic: sha1("blob " + filesize + "\0" + data)

    Args:
        data: The raw bytes of the file.

    Returns:
        The hexadecimal Git-SHA1 string.
    """
    # Logic taken from huggingface_hub/utils/sha.py
    sha = hashlib.sha1()
    sha.update(b"blob ")
    sha.update(str(len(data)).encode("utf-8"))
    sha.update(b"\0")
    sha.update(data)
    return sha.hexdigest()
