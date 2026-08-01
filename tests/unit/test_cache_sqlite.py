import pytest
import os
import time
from veritensor.core.cache import HashCache

def test_cache_init(tmp_path, mocker):
    """Verifies that the database and table are created correctly."""
    db_path = tmp_path / "init_test.db"
    mocker.patch("veritensor.core.cache.CACHE_FILE", db_path)
    
    cache = HashCache()
    try:
        assert db_path.exists()
    finally:
        cache.close()

def test_cache_set_get(tmp_path, mocker):
    """Verifies setting, getting, and mtime-based invalidation."""
    db_path = tmp_path / "logic_test.db"
    mocker.patch("veritensor.core.cache.CACHE_FILE", db_path)

    f = tmp_path / "model.pt"
    f.write_text("original content")
    
    cache = HashCache()
    
    try:
        # 1. Set the initial cache
        cache.set(f, "hash_v1")
        
        # 2. Get (Should be a HIT)
        assert cache.get(f) == "hash_v1"
        
        # 3. Simulate file modification with GUARANTEED mtime change
        # We manually set the access/modified time to 1 hour in the future 
        # to avoid CI clock precision issues.
        future_time = time.time() + 3600 
        f.write_text("modified content")
        os.utime(f, (future_time, future_time))
        
        # 4. Get (Should be a MISS)
        # The cache stores the mtime from when .set() was called. 
        # Since we just updated the file's mtime, it shouldn't match.
        result = cache.get(f)
        assert result is None, f"Expected cache miss, but got {result}"

    finally:
        # Always close to release the SQLite lock
        cache.close()

# ── C-4 REGRESSION: partial DB init must not raise AttributeError ─────────────

def test_c4_regression_partial_db_init_no_attribute_error(tmp_path, mocker):
    """
    C-4 regression: if _init_db fails after setting self.conn but before
    self.cursor, _cleanup_old_entries was called in __init__ and hit
    AttributeError: 'HashCache' object has no attribute 'cursor'.

    The fix adds: if not self.conn or not hasattr(self, 'cursor'): return
    """
    from veritensor.core.cache import HashCache
    import sqlite3

    db_path = tmp_path / "broken.db"
    mocker.patch("veritensor.core.cache.CACHE_FILE", db_path)

    # Force failure after conn is created but before cursor/table creation
    original_connect = sqlite3.connect

    call_count = [0]
    def patched_connect(*args, **kwargs):
        conn = original_connect(*args, **kwargs)
        call_count[0] += 1
        if call_count[0] == 1:
            # Make the cursor's execute fail on CREATE TABLE
            original_cursor = conn.cursor

            def bad_cursor():
                c = original_cursor()
                original_execute = c.execute

                exec_count = [0]
                def fail_on_create(sql, *a, **kw):
                    exec_count[0] += 1
                    if exec_count[0] >= 3:  # Fail on CREATE TABLE
                        raise sqlite3.OperationalError("Simulated DB error")
                    return original_execute(sql, *a, **kw)

                c.execute = fail_on_create
                return c

            conn.cursor = bad_cursor
        return conn

    mocker.patch("sqlite3.connect", side_effect=patched_connect)

        # Must not raise AttributeError
    try:
        cache = HashCache()
            # If init failed gracefully, conn should be None
        cache.close()
    except AttributeError as e:
        pytest.fail(
                    f"C-4 regression: HashCache raised AttributeError on partial init: {e}"
            )


def test_cache_cleanup_works_when_cursor_not_set(tmp_path, mocker):
    """
    Direct test: _cleanup_old_entries must return safely when cursor is absent.
    """
    from veritensor.core.cache import HashCache

    db_path = tmp_path / "test.db"
    mocker.patch("veritensor.core.cache.CACHE_FILE", db_path)

    cache = HashCache()
    # Simulate state where conn is set but cursor was never assigned
    cache.conn = object()  # truthy but not a real connection
    if hasattr(cache, "cursor"):
        delattr(cache, "cursor")

    # Must not raise
    try:
        cache._cleanup_old_entries()
    except AttributeError:
        pytest.fail("_cleanup_old_entries raised AttributeError when cursor not set")
    finally:
        cache.conn = None
        cache.close()