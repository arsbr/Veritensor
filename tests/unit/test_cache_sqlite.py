import pytest
import sqlite3
from veritensor.core.cache import HashCache, CACHE_FILE

@pytest.fixture
def mock_cache_path(tmp_path, mocker):
    """Redirects the cache file to a temp directory."""
    new_path = tmp_path / "cache.db"
    mocker.patch("veritensor.core.cache.CACHE_FILE", new_path)
    return new_path

def test_cache_init(mock_cache_path):
    cache = HashCache()
    assert mock_cache_path.exists()
    
    # Check if table exists
    conn = sqlite3.connect(str(mock_cache_path))
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='file_cache';")
    assert cursor.fetchone() is not None
    cache.close()

def test_cache_set_get(tmp_path, mocker):
    db_path = tmp_path / "unit_test_cache.db"
    mocker.patch("veritensor.core.cache.CACHE_FILE", db_path)

    #  Setup file
    f = tmp_path / "model.pt"
    f.write_text("original data")
    
    cache = HashCache()
    
    try:
        # Set hash
        cache.set(f, "hash_123")
        
        # Get hash (Should hit)
        retrieved = cache.get(f)
        assert retrieved == "hash_123"
        
        # Modify file (mtime changes)
        time.sleep(0.1) 
        f.write_text("new data")
        
        # Get hash (Should miss because mtime changed)
        retrieved_after_edit = cache.get(f)
        assert retrieved_after_edit is None

    finally:
        cache.close()
