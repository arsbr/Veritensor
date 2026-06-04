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
