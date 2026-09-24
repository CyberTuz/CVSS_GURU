"""
Authentication helpers — password hashing, JWT creation/verification,
and a FastAPI dependency to extract the current user from the session cookie.
"""

import hashlib
import hmac
import os
import time
import secrets
import warnings
from typing import Optional

import bcrypt
import jwt
from fastapi import Cookie, Depends, HTTPException, Request, status

from app.db import db_query

# ── Configuration ────────────────────────────────────────────────────────────

def _get_jwt_secret() -> str:
    secret = os.getenv("JWT_SECRET", "").strip()
    if secret:
        return secret

    # In production (SITE_URL starts with https://), JWT_SECRET is mandatory.
    # Without it, every restart invalidates all sessions — unacceptable in prod.
    site_url = os.getenv("SITE_URL", "")
    if site_url.startswith("https://"):
        raise RuntimeError(
            "JWT_SECRET is required in production. "
            "Generate one with: openssl rand -hex 32  "
            "and set it in your .env or environment variables."
        )

    # Local development — generate a random secret with a visible warning.
    warnings.warn(
        "JWT_SECRET is not set. A random secret will be used — all sessions "
        "will be invalidated on every restart. Set JWT_SECRET in your .env.",
        RuntimeWarning,
        stacklevel=2,
    )
    return secrets.token_hex(32)

JWT_SECRET: str = _get_jwt_secret()
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_SECONDS = 60 * 60 * 24 * 30   # 30 days
COOKIE_NAME = "cvss_session"

# ── Password helpers ──────────────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


# ── JWT helpers ───────────────────────────────────────────────────────────────

def create_session_token(user_id: int, username: str) -> str:
    payload = {
        "sub": str(user_id),
        "username": username,
        "iat": int(time.time()),
        "exp": int(time.time()) + JWT_EXPIRE_SECONDS,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_session_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError:
        return None


# ── FastAPI dependencies ──────────────────────────────────────────────────────

async def get_current_user(
    cvss_session: Optional[str] = Cookie(default=None)
) -> Optional[dict]:
    """
    Returns the user dict {id, username, email, created_at, last_login, api_key_prefix, email_verified}
    if the session cookie is valid and the user still exists in DB, otherwise None.
    """
    from app.config import LOCAL_MODE

    if LOCAL_MODE or not cvss_session:
        return None
    payload = decode_session_token(cvss_session)
    if not payload:
        return None
    rows = await db_query(
        "SELECT id, username, email, created_at, last_login, api_key_prefix, "
        "email_verified_at IS NOT NULL AS email_verified FROM users WHERE id = %s",
        [int(payload["sub"])],
    )
    return rows[0] if rows else None


def require_user(user: Optional[dict] = Depends(get_current_user)) -> dict:
    """Dependency that raises 401 if the user is not authenticated."""
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )
    return user


def generate_api_key() -> str:
    """Return a cryptographically random 64-character hex API key."""
    return secrets.token_hex(32)


def hash_api_key(key: str) -> str:
    """API keys are stored only as SHA-256 hex digests (they are high-entropy random
    tokens, so a fast hash is appropriate). The plaintext is shown to the user once."""
    return hashlib.sha256(key.encode()).hexdigest()


def api_key_prefix(key: str) -> str:
    """First characters of a key, stored so the profile can say which key is active."""
    return key[:8]


async def require_api_key(request: Request) -> dict:
    """
    FastAPI dependency for /api/v1/* routes.

    Authentication order:
      1. RapidAPI proxy — if X-RapidAPI-Proxy-Secret matches, the request is
         trusted and a synthetic user dict is returned (no DB lookup).
         RapidAPI handles auth and quotas on their side.
      2. Local API key — extracted from Authorization: Bearer <key> or X-API-Key.
         Returns the matching user dict or raises HTTP 401.
    """
    from app.config import LOCAL_MODE, RAPIDAPI_PROXY_SECRET, RAPIDAPI_CONFIGURED

    # ── Local mode: no database, no API keys ──────────────────────────────────
    if LOCAL_MODE:
        return {
            "id": 0,
            "username": "_local",
            "email": "",
            "created_at": "",
            "last_login": None,
            "api_key_prefix": None,
            "_local": True,  # marker for quota bypass
        }

    # ── RapidAPI proxy bypass ─────────────────────────────────────────────────

    if RAPIDAPI_CONFIGURED:
        proxy_secret = request.headers.get("X-RapidAPI-Proxy-Secret", "")
        if proxy_secret and hmac.compare_digest(proxy_secret, RAPIDAPI_PROXY_SECRET):
            # Return a synthetic user — quotas are handled by RapidAPI.
            # RapidAPI also tells us who is calling and on which plan (for logs).
            return {
                "id": 0,
                "username": "_rapidapi",
                "email": "proxy@rapidapi.com",
                "created_at": "",
                "last_login": None,
                "api_key_prefix": None,
                "_rapidapi": True,  # marker for quota bypass
                "rapidapi_user": request.headers.get("X-RapidAPI-User", "")[:100],
                "rapidapi_plan": request.headers.get("X-RapidAPI-Subscription", "")[:50],
            }

    # ── Local API key auth ────────────────────────────────────────────────────
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        key = auth_header[7:].strip()
    elif "X-API-Key" in request.headers:
        key = request.headers["X-API-Key"].strip()
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required",
        )

    if not key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required",
        )

    rows = await db_query(
        "SELECT id, username, email, created_at, last_login, api_key_prefix "
        "FROM users WHERE api_key_hash = %s",
        [hash_api_key(key)],
    )
    if not rows:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )
    return rows[0]
