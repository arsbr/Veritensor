import io
import zipfile
import pickle
from veritensor.engines.static.pickle_engine import scan_pickle_stream

def test_scan_pytorch_zip_recursive():
    """
    Checks that the engine can look inside Zip archives. (PyTorch .bin/.pt).
    """

    class Evil:
        def __reduce__(self):
            return (eval, ("print('pwned')",))
    
    evil_bytes = pickle.dumps(Evil())


    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as z:
        z.writestr("archive/data.pkl", evil_bytes)
        z.writestr("archive/version", "3")
    
    zip_bytes = buffer.getvalue()


    threats = scan_pickle_stream(zip_bytes)
    

    assert len(threats) > 0
    assert any("eval" in t for t in threats)

# ── C-6 REGRESSION: deque.pop(0) caused silent scan termination ───────────────

def test_c6_regression_scan_detects_evil_after_2050_strings():
    """
    C-6 regression: memo.pop(0) was called on a deque object.
    deque.pop() takes no arguments → TypeError → caught by except Exception:pass
    → genops loop terminates silently → ALL findings after the overflow are lost.

    This test verifies that an os.system STACK_GLOBAL placed after 2050 string
    constants is still detected (proving the loop did NOT terminate early).
    """
    import struct, io as _io

    buf = _io.BytesIO()

    # Step 1: flood the deque past maxlen=2048 via UNICODE opcode (protocol 0)
    # UNICODE opcode 'V' reads until newline — scan_pickle_stream tracks these.
    for i in range(2050):
        entry = f"dummy_string_{i:05d}"
        buf.write(b"V" + entry.encode("utf-8") + b"\n")

    # Step 2: push "os" and "system" via SHORT_BINUNICODE (protocol 4, opcode 0x8c)
    # These land in memo[-2] and memo[-1] respectively.
    for s in ("os", "system"):
        encoded = s.encode("utf-8")
        buf.write(b"\x8c" + bytes([len(encoded)]) + encoded)

    # Step 3: STACK_GLOBAL (opcode 0x93) — pops module/name from top of memo
    buf.write(b"\x93")

    # STOP
    buf.write(b".")

    threats = scan_pickle_stream(buf.getvalue())

    assert any("os" in t and "system" in t for t in threats), (
        "C-6 regression: os.system was not detected after 2050 string constants. "
        "This means memo.pop(0) raised TypeError and terminated the scan loop early."
    )


def test_c6_regression_function_returns_list_not_crashes():
    """Smoke test: scan of a large stream must always return list, never raise."""
    import io as _io

    buf = _io.BytesIO()
    for i in range(3000):
        s = f"s{i}"
        buf.write(b"V" + s.encode() + b"\n")
    buf.write(b".")

    result = scan_pickle_stream(buf.getvalue())
    assert isinstance(result, list)
