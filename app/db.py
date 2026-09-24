"""
Database module — PostgreSQL via psycopg 3 (async) with a small connection pool.

Usage:
    from app.db import db_execute, db_query

    rows = await db_query("SELECT id FROM users WHERE email = %s", [email])
    await db_execute("UPDATE users SET last_login = now() WHERE id = %s", [user_id])

Each call runs in its own transaction: committed on success, rolled back on error.
Queries never block the event loop, so one slow query does not stall other
requests handled by the same worker. The pool is created lazily on first use,
so the app can start (e.g. in LOCAL_MODE or tests) without a database.

Windows note: psycopg's async mode needs the Selector event loop (see run.py).
"""

import asyncio
import os
from typing import Any

from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

_pool: AsyncConnectionPool | None = None
_pool_lock = asyncio.Lock()


def database_configured() -> bool:
    return bool(os.getenv("DATABASE_URL", ""))


async def _get_pool() -> AsyncConnectionPool:
    global _pool
    if _pool is None:
        async with _pool_lock:
            if _pool is None:
                # Read at call time so load_dotenv() in main.py has already run.
                dsn = os.getenv("DATABASE_URL", "")
                if not dsn:
                    raise RuntimeError("DATABASE_URL is not set in environment variables.")
                pool = AsyncConnectionPool(
                    dsn,
                    min_size=1,
                    max_size=int(os.getenv("DB_POOL_SIZE", "4")),
                    # Seconds a request waits for a connection before failing (instead of hanging)
                    timeout=float(os.getenv("DB_POOL_TIMEOUT", "5")),
                    kwargs={"row_factory": dict_row, "connect_timeout": 5},
                    open=False,
                )
                await pool.open(wait=False)
                _pool = pool
    return _pool


async def close_pool() -> None:
    """Close all pooled connections (called on application shutdown)."""
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None


async def db_execute(sql: str, params: list[Any] | None = None) -> int:
    """Execute a write statement (INSERT / UPDATE / DELETE / DDL). Returns rows affected."""
    pool = await _get_pool()
    async with pool.connection() as conn:
        cur = await conn.execute(sql, params or None)
        return cur.rowcount


async def db_query(sql: str, params: list[Any] | None = None) -> list[dict]:
    """Execute a read statement (or a write with RETURNING) and return rows as dicts."""
    pool = await _get_pool()
    async with pool.connection() as conn:
        cur = await conn.execute(sql, params or None)
        return await cur.fetchall()
