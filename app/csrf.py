"""
CSRF protection — HMAC-based double-submit token pattern.

How it works:
  1. `generate_csrf_token()` creates a signed token (timestamp + random + HMAC).
  2. The token is embedded in every HTML form as a hidden `<input name="csrf_token">`.
  3. `validate_csrf_token()` verifies the signature and checks the token age.
  4. The `require_csrf` FastAPI dependency extracts the token from form data
     and raises HTTP 403 if it's missing or invalid.

Tokens are stateless — no server-side storage needed.
"""

import hashlib
import hmac
import secrets
import time
from typing import Optional

from fastapi import Form, HTTPException, status

from app.auth import JWT_SECRET

# ── Configuration ────────────────────────────────────────────────────────────

# Derive a separate key from JWT_SECRET so CSRF tokens can't be confused with JWTs.
_CSRF_SECRET: str = hashlib.sha256(f"csrf:{JWT_SECRET}".encode()).hexdigest()

# Tokens older than this are rejected (seconds).
CSRF_TOKEN_MAX_AGE: int = 60 * 60 * 2  # 2 hours


# ── Token helpers ─────────────────────────────────────────────────────────────

def generate_csrf_token() -> str:
    """Create a signed CSRF token: ``timestamp.random.signature``."""
    ts = str(int(time.time()))
    nonce = secrets.token_hex(16)
    sig = hmac.new(
        _CSRF_SECRET.encode(), f"{ts}.{nonce}".encode(), hashlib.sha256
    ).hexdigest()
    return f"{ts}.{nonce}.{sig}"


def validate_csrf_token(token: Optional[str]) -> bool:
    """Return True if *token* is well-formed, correctly signed, and not expired."""
    if not token:
        return False
    parts = token.split(".")
    if len(parts) != 3:
        return False
    ts_str, nonce, sig = parts

    # Verify signature
    expected = hmac.new(
        _CSRF_SECRET.encode(), f"{ts_str}.{nonce}".encode(), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return False

    # Verify age
    try:
        ts = int(ts_str)
    except ValueError:
        return False
    if time.time() - ts > CSRF_TOKEN_MAX_AGE:
        return False

    return True


# ── FastAPI dependency ────────────────────────────────────────────────────────

async def require_csrf(csrf_token: Optional[str] = Form(None)):
    """Dependency that validates the CSRF token from form data.

    Raises HTTP 403 if the token is missing or invalid.
    """
    if not validate_csrf_token(csrf_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or expired form submission. Please reload the page and try again.",
        )
