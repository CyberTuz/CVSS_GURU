"""
Unit tests for CSRF token generation and validation.
"""
import time
from unittest.mock import patch


from app.csrf import (
    CSRF_TOKEN_MAX_AGE,
    generate_csrf_token,
    validate_csrf_token,
)


class TestGenerateToken:
    def test_returns_three_part_string(self):
        token = generate_csrf_token()
        parts = token.split(".")
        assert len(parts) == 3, f"Expected 3 parts, got {len(parts)}: {token}"

    def test_timestamp_is_current(self):
        before = int(time.time())
        token = generate_csrf_token()
        after = int(time.time())
        ts = int(token.split(".")[0])
        assert before <= ts <= after

    def test_nonce_is_unique(self):
        tokens = {generate_csrf_token().split(".")[1] for _ in range(50)}
        assert len(tokens) == 50, "Nonces should be unique"

    def test_signature_is_hex(self):
        sig = generate_csrf_token().split(".")[2]
        assert len(sig) == 64  # SHA-256 hex digest
        int(sig, 16)  # should not raise


class TestValidateToken:
    def test_valid_token_passes(self):
        token = generate_csrf_token()
        assert validate_csrf_token(token) is True

    def test_none_rejected(self):
        assert validate_csrf_token(None) is False

    def test_empty_string_rejected(self):
        assert validate_csrf_token("") is False

    def test_garbage_rejected(self):
        assert validate_csrf_token("not.a.valid.token") is False

    def test_two_parts_rejected(self):
        assert validate_csrf_token("123.abc") is False

    def test_tampered_signature_rejected(self):
        token = generate_csrf_token()
        parts = token.split(".")
        parts[2] = "0" * 64  # fake signature
        assert validate_csrf_token(".".join(parts)) is False

    def test_tampered_nonce_rejected(self):
        token = generate_csrf_token()
        parts = token.split(".")
        parts[1] = "deadbeef" * 4  # different nonce
        assert validate_csrf_token(".".join(parts)) is False

    def test_tampered_timestamp_rejected(self):
        token = generate_csrf_token()
        parts = token.split(".")
        parts[0] = "9999999999"  # future timestamp, valid sig won't match
        assert validate_csrf_token(".".join(parts)) is False

    def test_expired_token_rejected(self):
        # Generate a token with a timestamp in the past beyond max age
        expired_time = time.time() - CSRF_TOKEN_MAX_AGE - 60
        with patch("app.csrf.time") as mock_time:
            mock_time.time.return_value = expired_time
            token = generate_csrf_token()
        # Now validate with real time — should be expired
        assert validate_csrf_token(token) is False

    def test_non_numeric_timestamp_rejected(self):
        token = generate_csrf_token()
        parts = token.split(".")
        parts[0] = "notanumber"
        assert validate_csrf_token(".".join(parts)) is False

    def test_different_tokens_are_different(self):
        t1 = generate_csrf_token()
        t2 = generate_csrf_token()
        assert t1 != t2
        assert validate_csrf_token(t1) is True
        assert validate_csrf_token(t2) is True
