"""
API usage module — monthly free quota for local API keys.

Every registered user gets FREE_TIER_MONTHLY_LIMIT calls per calendar month.
Higher volumes are served through RapidAPI, which handles its own auth and
quotas, so proxied requests are never counted here.

Provides:
  - get_current_year_month()       UTC 'YYYY-MM' string
  - get_usage(user_id, ...)        current-month call count
  - increment_usage(user_id, ...)  atomic upsert, returns new count
  - usage_would_block(usage)       pure helper for tests
  - get_limit_error_body(usage)    pure helper for tests
  - check_usage_limit(request)     FastAPI dependency
"""

from __future__ import annotations

import datetime
from typing import Optional

from fastapi import Depends, HTTPException, Request, status

from app.auth import require_api_key

from app.config import FREE_TIER_MONTHLY_LIMIT, RAPIDAPI_URL
from app.db import db_query
from app.logging_config import get_logger

logger = get_logger("usage")


# ── Pure utility functions ────────────────────────────────────────────────────

def get_current_year_month() -> str:
    """Return the current UTC year-month as 'YYYY-MM'."""
    now = datetime.datetime.now(datetime.timezone.utc)
    return now.strftime("%Y-%m")


async def get_usage(user_id: int, year_month: Optional[str] = None) -> int:
    """
    Return the API call count for user_id in the given month.
    Defaults to the current calendar month.
    Returns 0 if no record exists yet.
    """
    ym = year_month or get_current_year_month()
    rows = await db_query(
        "SELECT call_count FROM api_usage WHERE user_id = %s AND year_month = %s",
        [user_id, ym],
    )
    return rows[0]["call_count"] if rows else 0


async def increment_usage(user_id: int, year_month: Optional[str] = None) -> int:
    """
    Atomically increment the call count for user_id in the given month by 1.
    Uses INSERT … ON CONFLICT DO UPDATE (upsert) for atomicity.
    Returns the new count after increment.
    """
    ym = year_month or get_current_year_month()
    try:
        rows = await db_query(
            """
            INSERT INTO api_usage (user_id, year_month, call_count)
            VALUES (%s, %s, 1)
            ON CONFLICT (user_id, year_month)
            DO UPDATE SET call_count = api_usage.call_count + 1
            RETURNING call_count
            """,
            [user_id, ym],
        )
        return rows[0]["call_count"]
    except Exception as exc:
        logger.error("increment_usage_failed", extra={"user_id": user_id, "error": str(exc)})
        raise


# ── Pure helpers (extracted for testability) ──────────────────────────────────

def usage_would_block(usage: int) -> bool:
    """Return True if a request should be blocked (429) given the current usage."""
    return usage >= FREE_TIER_MONTHLY_LIMIT


def get_limit_error_body(usage: int) -> dict:
    """Return the 429 error body dict."""
    body = {
        "error": "Monthly API limit reached",
        "limit": FREE_TIER_MONTHLY_LIMIT,
        "used": usage,
    }
    if RAPIDAPI_URL:
        body["rapidapi_url"] = RAPIDAPI_URL
    return body


# ── FastAPI dependency ────────────────────────────────────────────────────────

async def check_usage_limit(request: Request, user: dict = Depends(require_api_key)) -> None:
    """
    FastAPI dependency for /api/v1/* routes.

    Raises HTTP 429 once a user has exhausted their monthly quota.
    Increments the usage counter for allowed requests, and logs every API call
    (channel, caller, plan) so usage can be followed without RapidAPI's dashboard.

    RapidAPI-proxied requests are exempt — RapidAPI enforces its own quotas —
    and so is local mode, which has no database.
    ``user`` comes from require_api_key, which FastAPI runs once per request.
    """
    if user.get("_local"):
        return

    if user.get("_rapidapi"):
        logger.info(
            "api_call",
            extra={
                "channel": "rapidapi",
                "path": request.url.path,
                "rapidapi_user": user.get("rapidapi_user", ""),
                "rapidapi_plan": user.get("rapidapi_plan", ""),
            },
        )
        return

    user_id: int = user["id"]
    usage = await get_usage(user_id)

    if usage_would_block(usage):
        logger.info("api_quota_exceeded", extra={"user_id": user_id, "used": usage})
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=get_limit_error_body(usage),
        )

    # Allowed — increment counter (best-effort, never fail the request)
    try:
        await increment_usage(user_id)
    except Exception as exc:
        logger.error("usage_increment_failed", extra={"user_id": user_id, "error": str(exc)})
    logger.info(
        "api_call",
        extra={"channel": "api_key", "path": request.url.path, "user_id": user_id, "used": usage + 1},
    )
