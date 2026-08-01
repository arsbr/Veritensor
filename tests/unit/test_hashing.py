import hashlib
from veritensor.engines.hashing.calculator import calculate_sha256

def test_calculate_sha256_regular_file(tmp_path):
    f = tmp_path / "model.bin"
    content = b"hello world"
    f.write_bytes(content)
    
    # Compute expected hash dynamically
    expected = hashlib.sha256(content).hexdigest()
    assert len(expected) == 64
    assert calculate_sha256(f) == expected

def test_calculate_sha256_lfs_pointer(tmp_path):
    # Creating a fake LFS pointer
    lfs_content = (
        "version https://git-lfs.github.com/spec/v1\n"
        "oid sha256:1111111111111111111111111111111111111111111111111111111111111111\n"
        "size 12345\n"
    )
    f = tmp_path / "model.lfs"
    f.write_text(lfs_content)

    # Veritensor should return the OID from the text, not the hash of the text itself!
    expected_oid = "1111111111111111111111111111111111111111111111111111111111111111"
    assert calculate_sha256(f) == expected_oid

# ── L-1 REGRESSION: calculate_sha256 must not return None ────────────────────

def test_l1_regression_non_sha256_lfs_returns_valid_hash(tmp_path):
    """
    L-1 regression: after fixing lfs.py to handle non-SHA256 OID algorithms,
    parse_lfs_pointer() can return {"sha256": None, ...}.
    calculator.py must detect this and fall back to hashing the pointer file
    itself — returning a valid hex string, NOT None.

    Returning None would:
    - Violate the -> str type annotation
    - Break hash comparison in HuggingFace verify_file_hash()
    - Store None as file_hash in ScanResult and manifests
    """
    future_algo_lfs = (
        "version https://git-lfs.github.com/spec/v1\n"
        "oid sha3:aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666000011112222333\n"
        "size 99999\n"
    )
    f = tmp_path / "future_model.lfs"
    f.write_text(future_algo_lfs)

    result = calculate_sha256(f)

    assert result is not None, (
        "L-1 regression: calculate_sha256 returned None for a non-SHA256 LFS pointer. "
        "It must fall back to hashing the pointer file content itself."
    )
    assert isinstance(result, str), f"Expected str, got {type(result)}"
    assert len(result) == 64, f"Expected 64-char hex SHA256, got len={len(result)}"


def test_sha256_lfs_pointer_still_uses_oid(tmp_path):
    """Regular SHA256 LFS pointers must still return the OID hash (not re-hash)."""
    expected_oid = "a" * 64
    lfs_content = (
        f"version https://git-lfs.github.com/spec/v1\n"
        f"oid sha256:{expected_oid}\n"
        f"size 12345\n"
    )
    f = tmp_path / "model.safetensors"
    f.write_text(lfs_content)

    assert calculate_sha256(f) == expected_oid
