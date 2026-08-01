"""
Tests for file_utils.py — magic number / file extension mismatch detection.
No tests existed before for this module.
"""
import pytest
from pathlib import Path
from veritensor.core.file_utils import validate_file_extension


# ── Happy path — file matches its extension ───────────────────────────────────

def test_valid_pdf_passes(tmp_path):
    f = tmp_path / "report.pdf"
    f.write_bytes(b"%PDF-1.4 ...\nsome content")
    assert validate_file_extension(f) is None


def test_valid_png_passes(tmp_path):
    f = tmp_path / "image.png"
    f.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
    assert validate_file_extension(f) is None


def test_valid_zip_passes(tmp_path):
    f = tmp_path / "archive.zip"
    f.write_bytes(b"PK\x03\x04" + b"\x00" * 20)
    assert validate_file_extension(f) is None


def test_valid_python_script_passes(tmp_path):
    f = tmp_path / "script.py"
    f.write_text("import os\nprint('hello')")
    assert validate_file_extension(f) is None


def test_valid_shell_script_passes(tmp_path):
    f = tmp_path / "run.sh"
    f.write_bytes(b"#!/bin/bash\necho hello")
    assert validate_file_extension(f) is None


# ── Malware masquerading as legitimate files ───────────────────────────────────

def test_exe_disguised_as_pdf_detected(tmp_path):
    """MZ header (Windows PE) inside a .pdf file must be flagged as CRITICAL."""
    f = tmp_path / "invoice.pdf"
    f.write_bytes(b"MZ\x90\x00\x03\x00" + b"\x00" * 100)  # PE header
    result = validate_file_extension(f)
    assert result is not None
    assert "CRITICAL" in result
    assert "invoice.pdf" in result


def test_exe_disguised_as_png_detected(tmp_path):
    """MZ header inside a .png must be flagged."""
    f = tmp_path / "logo.png"
    f.write_bytes(b"MZ" + b"\x00" * 100)
    result = validate_file_extension(f)
    assert result is not None
    assert "CRITICAL" in result


def test_elf_disguised_as_pdf_detected(tmp_path):
    """ELF binary (Linux executable) inside a .pdf must be flagged."""
    f = tmp_path / "document.pdf"
    f.write_bytes(b"\x7fELF" + b"\x00" * 100)
    result = validate_file_extension(f)
    assert result is not None
    assert "CRITICAL" in result


def test_exe_disguised_as_python_script_detected(tmp_path):
    """MZ header inside a .py file must be flagged."""
    f = tmp_path / "helper.py"
    f.write_bytes(b"MZ\x90\x00" + b"\x00" * 50)
    result = validate_file_extension(f)
    assert result is not None
    assert "CRITICAL" in result


def test_exe_disguised_as_zip_detected(tmp_path):
    """MZ header inside a .zip must be flagged."""
    f = tmp_path / "data.zip"
    f.write_bytes(b"MZ" + b"\x00" * 50)
    result = validate_file_extension(f)
    assert result is not None
    assert "CRITICAL" in result


# ── Unknown extension — should be skipped ────────────────────────────────────

def test_unknown_extension_returns_none(tmp_path):
    """Extensions not in FILE_SIGNATURES must be silently skipped."""
    f = tmp_path / "model.safetensors"
    f.write_bytes(b"\x00\x00\x00\x08" + b"\x00" * 100)
    assert validate_file_extension(f) is None


def test_txt_extension_returns_none(tmp_path):
    f = tmp_path / "notes.txt"
    f.write_text("some normal text content here")
    assert validate_file_extension(f) is None


# ── Edge cases ────────────────────────────────────────────────────────────────

def test_empty_file_does_not_crash(tmp_path):
    f = tmp_path / "empty.pdf"
    f.write_bytes(b"")
    # Should not raise — result depends on header read
    result = validate_file_extension(f)
    assert result is None or isinstance(result, str)


def test_text_content_in_pdf_not_flagged(tmp_path):
    """
    A .pdf containing plain text (not PE/ELF) should NOT produce a threat.
    validate_file_extension only flags known malware headers, not general mismatches.
    """
    f = tmp_path / "text_as_pdf.pdf"
    f.write_bytes(b"This is just some text content in a badly named file")
    assert validate_file_extension(f) is None
