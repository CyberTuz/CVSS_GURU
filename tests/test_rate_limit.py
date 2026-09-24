"""
Tests for the sliding-window rate limiter (in-memory backend: the test suite
runs without a database, see conftest.py).
"""

import asyncio
from unittest.mock import patch

from app.rate_limit import RateLimiter


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def limiter(max_requests, window_seconds):
    return RateLimiter("test", max_requests=max_requests, window_seconds=window_seconds)


class TestRateLimiterAllow:
    def test_allows_up_to_limit(self):
        lim = limiter(3, 60)
        assert [run(lim.allow("ip1")) for _ in range(3)] == [True, True, True]

    def test_blocks_after_limit(self):
        lim = limiter(3, 60)
        for _ in range(3):
            run(lim.allow("ip1"))
        assert run(lim.allow("ip1")) is False

    def test_blocked_requests_are_not_recorded(self):
        lim = limiter(2, 60)
        run(lim.allow("ip1"))
        run(lim.allow("ip1"))
        assert run(lim.allow("ip1")) is False
        assert run(lim.allow("ip1")) is False
        assert len(lim._store["ip1"]) == 2

    def test_keys_are_independent(self):
        lim = limiter(1, 60)
        assert run(lim.allow("ip1")) is True
        assert run(lim.allow("ip2")) is True
        assert run(lim.allow("ip1")) is False
        assert run(lim.allow("ip2")) is False

    def test_window_expiry_allows_again(self):
        lim = limiter(2, 10)
        with patch("app.rate_limit.time") as mock_time:
            mock_time.time.return_value = 1000.0
            assert run(lim.allow("ip1")) is True
            assert run(lim.allow("ip1")) is True
            assert run(lim.allow("ip1")) is False
            mock_time.time.return_value = 1011.0  # past the window
            assert run(lim.allow("ip1")) is True


class TestRateLimiterRemaining:
    def test_full_remaining_at_start(self):
        assert run(limiter(5, 60).remaining("ip1")) == 5

    def test_remaining_decreases(self):
        lim = limiter(5, 60)
        run(lim.allow("ip1"))
        run(lim.allow("ip1"))
        assert run(lim.remaining("ip1")) == 3

    def test_remaining_never_negative(self):
        lim = limiter(1, 60)
        run(lim.allow("ip1"))
        run(lim.allow("ip1"))
        assert run(lim.remaining("ip1")) == 0

    def test_hit_records_without_checking(self):
        lim = limiter(1, 60)
        run(lim.hit("ip1"))
        run(lim.hit("ip1"))
        assert run(lim.remaining("ip1")) == 0


class TestRateLimiterRetryAfter:
    def test_zero_when_not_limited(self):
        assert run(limiter(5, 60).retry_after("ip1")) == 0

    def test_positive_when_limited(self):
        lim = limiter(2, 60)
        run(lim.allow("ip1"))
        run(lim.allow("ip1"))
        assert 0 < run(lim.retry_after("ip1")) <= 61

    def test_retry_after_decreases_over_time(self):
        lim = limiter(1, 100)
        with patch("app.rate_limit.time") as mock_time:
            mock_time.time.return_value = 1000.0
            run(lim.allow("ip1"))
            mock_time.time.return_value = 1050.0
            assert 40 <= run(lim.retry_after("ip1")) <= 52


class TestBackendSelection:
    def test_database_backend_used_when_configured(self):
        lim = limiter(1, 60)

        async def one_hit(*a, **k):
            return [{"n": 1}]

        with patch("app.rate_limit._use_database", return_value=True), \
             patch("app.db.db_query", side_effect=one_hit):
            assert run(lim.remaining("ip1")) == 0
        assert "ip1" not in lim._store  # the in-memory store was not used

    def test_database_errors_fail_open(self):
        lim = limiter(1, 60)

        async def broken(*a, **k):
            raise RuntimeError("db down")

        with patch("app.rate_limit._use_database", return_value=True), \
             patch("app.db.db_query", side_effect=broken), \
             patch("app.db.db_execute", side_effect=broken):
            assert run(lim.allow("ip1")) is True


class TestPreConfiguredLimiters:
    def test_auth_limiter_config(self):
        from app.rate_limit import auth_limiter
        assert (auth_limiter.max_requests, auth_limiter.window_seconds) == (5, 300)

    def test_register_limiter_config(self):
        from app.rate_limit import register_limiter
        assert (register_limiter.max_requests, register_limiter.window_seconds) == (3, 1800)

    def test_ai_limiter_config(self):
        from app.routers.ai_scorer import ai_limiter
        assert (ai_limiter.max_requests, ai_limiter.window_seconds) == (10, 3600)


class TestRegistrationLimit:
    """Failed form submissions must not count against the sign-up limit."""

    def test_invalid_submissions_do_not_consume_the_limit(self):
        from fastapi.testclient import TestClient
        from main import app
        from app.csrf import generate_csrf_token
        from app.rate_limit import register_limiter

        register_limiter._store.clear()
        client = TestClient(app)
        for _ in range(6):
            r = client.post("/register", data={
                "username": "limit_check", "email": "limit@example.invalid",
                "password": "Password-1111", "password_confirm": "Password-2222",
                "csrf_token": generate_csrf_token(),
            })
            assert "Passwords do not match" in r.text
        assert run(register_limiter.remaining("testclient")) == register_limiter.max_requests
