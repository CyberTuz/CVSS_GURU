"""
Tests for LOCAL_MODE: single-user local runs without database, auth or CAPTCHA.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class TestLocalModeAuth:
    def test_session_cookie_ignored_without_db(self):
        """get_current_user must not touch the DB in local mode, even with a cookie."""
        from app.auth import get_current_user

        with patch("app.config.LOCAL_MODE", True), \
             patch("app.auth.db_query", side_effect=AssertionError("DB must not be queried")):
            assert _run(get_current_user(cvss_session="any-token")) is None

    def test_api_key_not_required(self):
        """require_api_key returns a local user without any key header or DB lookup."""
        from app.auth import require_api_key

        request = MagicMock()
        request.headers = {}
        with patch("app.config.LOCAL_MODE", True), \
             patch("app.auth.db_query", side_effect=AssertionError("DB must not be queried")):
            user = _run(require_api_key(request))
        assert user["_local"] is True

    def test_api_key_still_required_by_default(self):
        """Without local mode, a request with no key is rejected."""
        from fastapi import HTTPException
        from app.auth import require_api_key

        request = MagicMock()
        request.headers = {}
        with patch("app.config.LOCAL_MODE", False), patch("app.config.RAPIDAPI_CONFIGURED", False):
            with pytest.raises(HTTPException) as exc_info:
                _run(require_api_key(request))
        assert exc_info.value.status_code == 401

    def test_quota_skipped(self):
        """check_usage_limit must not read or write usage in local mode."""
        from app.usage import check_usage_limit

        with patch("app.config.LOCAL_MODE", True), \
             patch("app.usage.get_usage") as mock_usage, \
             patch("app.usage.increment_usage") as mock_inc:
            _run(check_usage_limit(MagicMock(), {"id": 0, "_local": True}))
        mock_usage.assert_not_called()
        mock_inc.assert_not_called()


class TestLocalModeAIScorer:
    """With no OpenRouter key configured the endpoint answers 503 — reaching that
    point proves the login gate, CAPTCHA and rate limit were all passed."""

    @pytest.fixture(autouse=True)
    def client(self):
        from main import app

        with patch("app.routers.ai_scorer.OPENROUTER_API_KEY", ""):
            self.client = TestClient(app, raise_server_exceptions=False)
            yield

    def test_no_captcha_needed_in_local_mode(self):
        with patch("app.config.LOCAL_MODE", True):
            r = self.client.post("/api/ai-score", data={"description": "SQL injection in login form"})
        assert r.status_code == 503

    def test_used_cookie_does_not_gate_in_local_mode(self):
        self.client.cookies.set("ai_scorer_used", "1")
        with patch("app.config.LOCAL_MODE", True):
            r = self.client.post("/api/ai-score", data={"description": "SQL injection in login form"})
        assert r.status_code == 503

    def test_captcha_required_by_default(self):
        with patch("app.config.LOCAL_MODE", False), \
             patch("app.config.RECAPTCHA_CONFIGURED", True), \
             patch("app.routers.ai_scorer._verify_recaptcha", AsyncMock(return_value=False)):
            r = self.client.post("/api/ai-score", data={"description": "SQL injection in login form"})
        assert r.status_code == 400
        assert "CAPTCHA" in r.json()["error"]

    def test_missing_captcha_keys_fail_closed(self):
        """Without reCAPTCHA keys the endpoint must refuse rather than run unprotected."""
        with patch("app.config.LOCAL_MODE", False), patch("app.config.RECAPTCHA_CONFIGURED", False):
            r = self.client.post("/api/ai-score", data={"description": "SQL injection in login form"})
        assert r.status_code == 503
        assert "CAPTCHA" in r.json()["error"]
