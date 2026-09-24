"""
Tests for the PostgreSQL access layer that do not need a running database.
"""

import asyncio

import pytest

import app.db as db


class TestPool:
    def test_missing_database_url_raises_runtime_error(self, monkeypatch):
        """Startup relies on RuntimeError to skip migrations when no DB is configured."""
        monkeypatch.delenv("DATABASE_URL", raising=False)
        monkeypatch.setattr(db, "_pool", None)
        with pytest.raises(RuntimeError, match="DATABASE_URL"):
            asyncio.get_event_loop().run_until_complete(db.db_query("SELECT 1"))

    def test_close_pool_without_pool_is_noop(self, monkeypatch):
        monkeypatch.setattr(db, "_pool", None)
        asyncio.get_event_loop().run_until_complete(db.close_pool())
        assert db._pool is None


class TestMigrations:
    def test_versions_are_unique_and_ordered(self):
        from scripts.migrate import MIGRATIONS

        versions = [v for v, _, _ in MIGRATIONS]
        assert versions == sorted(versions)
        assert len(versions) == len(set(versions))

    def test_no_sqlite_syntax_left(self):
        """Guard against pasting SQLite-only syntax into PostgreSQL migrations."""
        from scripts.migrate import MIGRATIONS

        sql = " ".join(s for _, _, stmts in MIGRATIONS for s in stmts).upper()
        for token in ("AUTOINCREMENT", "STRFTIME", "COLLATE NOCASE", "DATETIME("):
            assert token not in sql
