"""reCAPTCHA on the account forms, per-account login limit, email verification gates, emails."""
import asyncio
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from app.auth import get_current_user
from app.csrf import generate_csrf_token
from main import app


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


@pytest.fixture
def client():
    return TestClient(app, base_url="https://testserver")


def _user(verified: bool) -> dict:
    return {
        "id": 42, "username": "alice", "email": "alice@example.invalid",
        "created_at": None, "last_login": None, "api_key_prefix": None, "email_verified": verified,
    }


@pytest.fixture
def as_user():
    def _set(verified: bool):
        app.dependency_overrides[get_current_user] = lambda: _user(verified)
    yield _set
    app.dependency_overrides.clear()


# ── check_form_captcha policy ────────────────────────────────────────────────

class TestFormCaptchaPolicy:
    def test_skipped_in_local_mode(self):
        from app.recaptcha import check_form_captcha

        with patch("app.config.LOCAL_MODE", True), patch("app.recaptcha.verify_recaptcha") as v:
            assert run(check_form_captcha("", "1.2.3.4", "login")) is True
        v.assert_not_called()

    def test_lets_through_without_keys(self):
        from app.recaptcha import check_form_captcha

        with patch("app.config.LOCAL_MODE", False), patch("app.config.RECAPTCHA_CONFIGURED", False), \
             patch("app.recaptcha.verify_recaptcha") as v:
            assert run(check_form_captcha("", "1.2.3.4", "login")) is True
        v.assert_not_called()

    def test_verifies_with_the_form_action(self):
        from app.recaptcha import check_form_captcha

        with patch("app.config.LOCAL_MODE", False), patch("app.config.RECAPTCHA_CONFIGURED", True), \
             patch("app.recaptcha.verify_recaptcha", AsyncMock(return_value=False)) as v:
            assert run(check_form_captcha("tok", "1.2.3.4", "register")) is False
        v.assert_awaited_once_with("tok", "1.2.3.4", "register")


# ── Forms reject a failed CAPTCHA before touching the database ───────────────

class TestFormsRequireCaptcha:
    @pytest.mark.parametrize("path, data", [
        ("/login", {"username": "alice", "password": "x"}),
        ("/register", {"username": "alice", "email": "a@example.invalid",
                       "password": "Password-1", "password_confirm": "Password-1"}),
        ("/forgot-password", {"email": "a@example.invalid"}),
    ])
    def test_failed_captcha_is_rejected(self, client, path, data):
        from app.rate_limit import auth_limiter

        auth_limiter._store.clear()
        with patch("app.routers.auth.check_form_captcha", AsyncMock(return_value=False)), \
             patch("app.routers.auth.db_query", AsyncMock()) as db:
            r = client.post(path, data={**data, "csrf_token": generate_csrf_token()})
        assert "anti-bot check failed" in r.text
        db.assert_not_called()

    def test_forms_carry_the_recaptcha_action(self, client):
        with patch("app.config.RECAPTCHA_SITE_KEY", "site-key"), patch("app.deps.RECAPTCHA_SITE_KEY", "site-key"):
            pages = {p: client.get(p).text for p in ("/login", "/register", "/forgot-password")}
        assert 'data-recaptcha-action="login"' in pages["/login"]
        assert 'data-recaptcha-action="register"' in pages["/register"]
        assert 'data-recaptcha-action="forgot_password"' in pages["/forgot-password"]


# ── Per-account login limit ──────────────────────────────────────────────────

class TestLoginAccountLimit:
    def test_blocks_after_ten_failures_for_the_same_username(self, client):
        from app.rate_limit import login_account_limiter

        login_account_limiter._store.clear()
        with patch("app.routers.auth.auth_limiter.allow", AsyncMock(return_value=True)), \
             patch("app.routers.auth.db_query", AsyncMock(return_value=[])):
            for _ in range(10):
                r = client.post("/login", data={"username": "Victim", "password": "guess",
                                                "csrf_token": generate_csrf_token()})
                assert "Invalid username or password" in r.text
            r = client.post("/login", data={"username": "victim", "password": "guess",
                                            "csrf_token": generate_csrf_token()})
        assert "Too many attempts" in r.text
        assert "retry-after" in r.headers
        login_account_limiter._store.clear()


# ── Email verification gates ─────────────────────────────────────────────────

class TestVerificationGates:
    def test_unverified_user_cannot_generate_api_key(self, client, as_user):
        as_user(False)
        with patch("app.routers.auth.db_execute", AsyncMock()) as db:
            r = client.post("/api/user/regenerate-api-key", data={"csrf_token": generate_csrf_token()})
        assert r.status_code == 403
        assert "Confirm your email first" in r.text
        db.assert_not_called()

    def test_verified_user_gets_a_key(self, client, as_user):
        as_user(True)
        with patch("app.routers.auth.db_execute", AsyncMock()):
            r = client.post("/api/user/regenerate-api-key", data={"csrf_token": generate_csrf_token()})
        assert r.status_code == 200 and "Your new API key" in r.text

    def test_ai_scorer_needs_verified_email_after_free_use(self, client, as_user):
        as_user(False)
        client.cookies.set("ai_scorer_used", "1")
        r = client.post("/api/ai-score", data={"description": "SQL injection in login form"})
        assert r.status_code == 403 and r.json()["error"] == "email_not_verified"

    def test_resend_is_rate_limited_per_user(self, client, as_user):
        from app.rate_limit import verify_email_limiter

        verify_email_limiter._store.clear()
        as_user(False)
        with patch("app.routers.auth.db_execute", AsyncMock()), \
             patch("app.routers.auth.send_email") as send:
            texts = [client.post("/api/user/resend-verification",
                                 data={"csrf_token": generate_csrf_token()}).text for _ in range(4)]
        assert all("Sent to" in t for t in texts[:3])
        assert "Too many emails" in texts[3]
        assert send.call_count == 3
        verify_email_limiter._store.clear()

    def test_invalid_link_redirects_with_message(self, client):
        with patch("app.routers.auth.db_query", AsyncMock(return_value=[])):
            r = client.get("/verify-email/nope", follow_redirects=False)
        assert r.status_code == 302 and r.headers["location"] == "/login?verified=invalid"

    def test_valid_link_confirms_the_account(self, client):
        with patch("app.routers.auth.db_query", AsyncMock(return_value=[{"user_id": 7, "expired": False}])), \
             patch("app.routers.auth.db_execute", AsyncMock()) as db:
            r = client.get("/verify-email/tok", follow_redirects=False)
        assert r.headers["location"] == "/login?verified=1"
        assert "email_verified_at" in db.call_args_list[0].args[0]


# ── Emails ───────────────────────────────────────────────────────────────────

class TestEmails:
    def test_verification_email_has_link_and_expiry(self):
        from app.routers.auth import _verification_email

        html = _verification_email("bob<x>", "https://cvss.guru/verify-email/abc")
        assert "https://cvss.guru/verify-email/abc" in html
        assert "bob&lt;x&gt;" in html and "48 hours" in html

    def test_deletion_email_only_for_confirmed_addresses(self, client, as_user):
        for verified, expected in ((True, 1), (False, 0)):
            as_user(verified)
            with patch("app.routers.auth.db_query", AsyncMock(return_value=[{"password": "h"}])), \
                 patch("app.routers.auth.db_execute", AsyncMock()), \
                 patch("app.routers.auth.verify_password", return_value=True), \
                 patch("app.routers.auth.send_email") as send:
                r = client.post("/api/user/delete-account", data={
                    "confirm_password": "pw", "csrf_token": generate_csrf_token()}, follow_redirects=False)
            assert r.status_code == 302
            assert send.call_count == expected
            if expected:
                assert "has been deleted" in send.call_args.args[1]

    def test_htmx_delete_navigates_instead_of_swapping_the_home_page(self, client, as_user):
        as_user(True)
        with patch("app.routers.auth.db_query", AsyncMock(return_value=[{"password": "h"}])), \
             patch("app.routers.auth.db_execute", AsyncMock()), \
             patch("app.routers.auth.verify_password", return_value=True), \
             patch("app.routers.auth.send_email"):
            r = client.post("/api/user/delete-account", headers={"HX-Request": "true"},
                            data={"confirm_password": "pw", "csrf_token": generate_csrf_token()},
                            follow_redirects=False)
        assert r.status_code == 200 and r.text == ""
        assert r.headers["hx-redirect"] == "/"
        assert "cvss_session=" in r.headers["set-cookie"] and "Max-Age=0" in r.headers["set-cookie"]
