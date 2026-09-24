"""
Sliding-window rate limiter shared by all workers.

With a database configured, hits are stored in PostgreSQL (table rate_limit_hits),
so the limit is the same whichever gunicorn worker serves the request and it
survives restarts and deploys. Without a database (LOCAL_MODE, tests) an
in-memory store is used instead.

Usage::

    from app.rate_limit import auth_limiter

    if not await auth_limiter.allow(ip):
        ...  # HTTP 429 / error message

If the database is temporarily unreachable the limiter fails open (allows the
request) rather than locking every user out; the error is logged.
"""

import random
import time
from typing import Dict, List

from app.logging_config import get_logger

logger = get_logger("rate_limit")


def _use_database() -> bool:
    from app.config import LOCAL_MODE
    from app.db import database_configured

    return database_configured() and not LOCAL_MODE


class RateLimiter:
    """At most *max_requests* hits per *window_seconds* for each key (typically a client IP)."""

    def __init__(self, bucket: str, max_requests: int, window_seconds: int) -> None:
        self.bucket = bucket
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._store: Dict[str, List[float]] = {}  # in-memory fallback

    # ── Public API ────────────────────────────────────────────────────────────

    async def allow(self, key: str) -> bool:
        """Record a hit and return True if it is within the limit."""
        if await self.remaining(key) == 0:
            return False
        await self.hit(key)
        return True

    async def remaining(self, key: str) -> int:
        """How many hits are still allowed in the current window."""
        return max(0, self.max_requests - await self._count(key))

    async def retry_after(self, key: str) -> int:
        """Seconds until the oldest hit in the window expires (0 if not limited)."""
        if await self.remaining(key) > 0:
            return 0
        oldest = await self._oldest(key)
        return max(1, int(oldest + self.window_seconds - time.time()) + 1) if oldest else 0

    async def hit(self, key: str) -> None:
        """Record a hit without checking (e.g. count only successful sign-ups)."""
        if _use_database():
            from app.db import db_execute

            try:
                await db_execute(
                    "INSERT INTO rate_limit_hits (bucket, key) VALUES (%s, %s)", [self.bucket, key]
                )
                # Opportunistic cleanup keeps the table small without a cron job
                if random.random() < 0.02:
                    await db_execute("DELETE FROM rate_limit_hits WHERE hit_at < now() - interval '1 day'")
            except Exception as exc:
                logger.error("rate_limit_db_error", extra={"bucket": self.bucket, "error": str(exc)})
            return
        self._store.setdefault(key, []).append(time.time())

    # ── Storage backends ──────────────────────────────────────────────────────

    async def _count(self, key: str) -> int:
        if _use_database():
            from app.db import db_query

            try:
                rows = await db_query(
                    "SELECT count(*) AS n FROM rate_limit_hits "
                    "WHERE bucket = %s AND key = %s AND hit_at > now() - make_interval(secs => %s)",
                    [self.bucket, key, self.window_seconds],
                )
                return rows[0]["n"]
            except Exception as exc:
                logger.error("rate_limit_db_error", extra={"bucket": self.bucket, "error": str(exc)})
                return 0  # fail open
        cutoff = time.time() - self.window_seconds
        self._store[key] = [ts for ts in self._store.get(key, []) if ts > cutoff]
        return len(self._store[key])

    async def _oldest(self, key: str) -> float | None:
        if _use_database():
            from app.db import db_query

            try:
                rows = await db_query(
                    "SELECT extract(epoch FROM min(hit_at)) AS ts FROM rate_limit_hits "
                    "WHERE bucket = %s AND key = %s AND hit_at > now() - make_interval(secs => %s)",
                    [self.bucket, key, self.window_seconds],
                )
                return float(rows[0]["ts"]) if rows and rows[0]["ts"] is not None else None
            except Exception:
                return None
        timestamps = self._store.get(key, [])
        return min(timestamps) if timestamps else None


# ── Pre-configured limiters ──────────────────────────────────────────────────

# Login / forgot password: 5 attempts per 5 minutes per IP
auth_limiter = RateLimiter("auth", max_requests=5, window_seconds=300)

# Registration: 3 created accounts per 30 minutes per IP (failed submissions are not counted)
register_limiter = RateLimiter("register", max_requests=3, window_seconds=1800)

# Failed logins per account (key: lower-cased username): stops password guessing
# spread over many IPs. 10 failures per 15 minutes.
login_account_limiter = RateLimiter("login_user", max_requests=10, window_seconds=900)

# "Resend verification email": 3 per hour per user id
verify_email_limiter = RateLimiter("verify_email", max_requests=3, window_seconds=3600)
