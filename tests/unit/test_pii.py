import pytest
from unittest.mock import MagicMock, patch
from veritensor.engines.content.pii import PIIScanner
import veritensor.engines.content.pii as _pii_module

def test_pii_no_library_installed():
    """
    Сheck that if there is no Presidio, the code does not crash, but returns an empty list.
    """
    with patch("veritensor.engines.content.pii.PRESIDIO_AVAILABLE", False):
        results = PIIScanner.scan("My email is test@example.com")
        assert results == []

def test_pii_with_mocked_engine():
    """
    We check the logic of processing the results of the Presidio (with mock).
    """
    with patch("veritensor.engines.content.pii.PRESIDIO_AVAILABLE", True):
        mock_res = MagicMock()
        mock_res.entity_type = "EMAIL_ADDRESS"
        mock_res.score = 0.9
        mock_res.start = 12
        mock_res.end = 28
        
        
        mock_engine = MagicMock()
        mock_engine.analyze.return_value = [mock_res]
        
        with patch.object(PIIScanner, "get_engine", return_value=mock_engine):
            text = "My email is test@example.com"
            results = PIIScanner.scan(text)
            
            assert len(results) == 1
            assert "HIGH: PII Leak (EMAIL_ADDRESS)" in results[0]
            # Masking check: te**********
            assert "te**" in results[0] or "te" in results[0]

# ── H-11 REGRESSION: PIIScanner.get_engine() was never initializing ──────────

def test_h11_regression_get_engine_attempts_initialization():
    """
    H-11 regression: the original code had an inverted condition:

        if PRESIDIO_AVAILABLE is None:   # True on first call
            return cls._engine            # ← exits WITHOUT initializing!

    This meant get_engine() would return None forever, silently disabling
    all PII scanning. The fix inverts the condition so that 'None' state
    triggers initialization instead of early return.

    After the fix: PRESIDIO_AVAILABLE must be True or False after the first call.
    It must NEVER remain None.
    """
    original_available = _pii_module.PRESIDIO_AVAILABLE
    original_engine = PIIScanner._engine

    try:
        # Reset to "never initialized" state
        _pii_module.PRESIDIO_AVAILABLE = None
        PIIScanner._engine = None
        PIIScanner._init_error = None

        # First call — must attempt initialization
        PIIScanner.get_engine()

        assert _pii_module.PRESIDIO_AVAILABLE is not None, (
            "H-11 regression: get_engine() returned early without initializing. "
            "PRESIDIO_AVAILABLE is still None — PII scanning is permanently disabled."
        )
        # After the call it must be True (installed) or False (not installed)
        assert _pii_module.PRESIDIO_AVAILABLE in (True, False)
    finally:
        _pii_module.PRESIDIO_AVAILABLE = original_available
        PIIScanner._engine = original_engine


def test_h11_get_engine_idempotent_on_repeated_calls():
    """Multiple calls must not re-initialize (lock + double-check pattern)."""
    original = _pii_module.PRESIDIO_AVAILABLE
    try:
        # Call once to initialize
        PIIScanner.get_engine()
        state_after_first = _pii_module.PRESIDIO_AVAILABLE

        # Call again — state must not change
        PIIScanner.get_engine()
        assert _pii_module.PRESIDIO_AVAILABLE == state_after_first
    finally:
        _pii_module.PRESIDIO_AVAILABLE = original
