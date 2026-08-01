"""
Tests for entropy.py — Shannon entropy and secret key heuristics.
No tests existed before for this module.
"""
import pytest
from veritensor.core.entropy import calculate_shannon_entropy, is_high_entropy


class TestShannonEntropy:
    def test_empty_string_returns_zero(self):
        assert calculate_shannon_entropy("") == 0.0

    def test_single_char_repeated_returns_zero(self):
        # P(x) = 1.0 → H = -1.0 * log2(1.0) = 0.0
        assert calculate_shannon_entropy("aaaaaaa") == 0.0

    def test_two_equally_probable_chars_returns_one(self):
        # P(0) = P(1) = 0.5 → H = 1.0
        result = calculate_shannon_entropy("01010101")
        assert abs(result - 1.0) < 0.001

    def test_random_api_key_has_high_entropy(self):
        # Real-looking API key: high entropy expected
        assert calculate_shannon_entropy("aB3kR9mPqX2wLcYtNvZs") > 4.0

    def test_all_unique_chars_maximizes_entropy(self):
        # 16 unique chars → H = log2(16) = 4.0
        s = "0123456789abcdef"
        result = calculate_shannon_entropy(s)
        assert abs(result - 4.0) < 0.001

    def test_predictable_string_has_low_entropy(self):
        # "hello" repeated — few unique chars
        assert calculate_shannon_entropy("hellohellohello") < 3.0


class TestIsHighEntropy:
    def test_real_api_key_flagged(self):
        # Looks like a real secret: 32 hex chars, high entropy
        key = "aB3kR9mPqX2wLcYtNvZs5f8hJ4xG1pE7"
        assert is_high_entropy(key) is True

    def test_short_string_not_flagged(self):
        # Below min_length=16
        assert is_high_entropy("aB3kR9mP") is False

    def test_string_with_spaces_not_flagged(self):
        # Spaces = readable text, not a secret
        assert is_high_entropy("this is a long secret key") is False

    def test_string_with_slash_not_flagged(self):
        # Paths are excluded
        assert is_high_entropy("/usr/local/bin/python3/something/very/long") is False

    def test_string_with_backslash_not_flagged(self):
        assert is_high_entropy("C:\\Windows\\System32\\drivers\\etc\\hosts") is False

    def test_uuid_not_flagged(self):
        """UUID filter: UUIDs have high entropy but are NOT secrets."""
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        assert is_high_entropy(uuid) is False

    def test_another_uuid_not_flagged(self):
        uuid = "123e4567-e89b-12d3-a456-426614174000"
        assert is_high_entropy(uuid) is False

    def test_low_entropy_long_string_not_flagged(self):
        # 32 chars but only two unique: very low entropy
        assert is_high_entropy("aaaaaaaaaaaabbbbbbbbbbbbbbbbbbbb") is False

    def test_custom_threshold(self):
        """Custom min_length and threshold parameters work."""
        # With a very low threshold, almost everything is "high entropy"
        assert is_high_entropy("abcdefgh", min_length=4, threshold=1.0) is True

    def test_custom_min_length(self):
        # 10 chars, threshold=4.5, but min_length=20 → not flagged
        key = "aB3kR9mPqX"
        assert is_high_entropy(key, min_length=20) is False