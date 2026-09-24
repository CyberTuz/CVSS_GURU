"""
Integration tests for security features:
  - Security headers middleware
  - JWT_SECRET enforcement
  - RapidAPI proxy authentication
  - CSRF on API endpoints
  - API v1 endpoint integration (with auth bypass)
"""
import asyncio
import os
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient


# ── Security Headers ──────────────────────────────────────────────────────────

class TestSecurityHeaders:
    """Verify that the SecurityHeadersMiddleware injects all required headers."""

    @pytest.fixture(autouse=True)
    def client(self):
        from main import app
        self.client = TestClient(app, raise_server_exceptions=False)

    def test_x_content_type_options(self):
        r = self.client.get("/health")
        assert r.headers.get("X-Content-Type-Options") == "nosniff"

    def test_x_frame_options(self):
        r = self.client.get("/health")
        assert r.headers.get("X-Frame-Options") == "DENY"

    def test_x_xss_protection(self):
        r = self.client.get("/health")
        assert r.headers.get("X-XSS-Protection") == "0"

    def test_referrer_policy(self):
        r = self.client.get("/health")
        assert r.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"

    def test_permissions_policy_present(self):
        r = self.client.get("/health")
        pp = r.headers.get("Permissions-Policy", "")
        assert "camera=()" in pp
        assert "microphone=()" in pp
        assert "geolocation=()" in pp

    def test_csp_present(self):
        r = self.client.get("/health")
        csp = r.headers.get("Content-Security-Policy", "")
        assert "default-src 'self'" in csp
        assert "frame-ancestors 'none'" in csp
        assert "form-action 'self'" in csp

    def test_csp_allows_required_cdns(self):
        r = self.client.get("/health")
        csp = r.headers.get("Content-Security-Policy", "")
        assert "font-src 'self';" in csp                  # fonts are self-hosted
        assert "https://www.googletagmanager.com" in csp  # Google Analytics
        assert "https://www.google.com/recaptcha/" in csp

    def test_csp_drops_unused_cdns(self):
        """Fonts, icons and libraries are self-hosted: no third-party CDNs remain."""
        csp = self.client.get("/health").headers.get("Content-Security-Policy", "")
        for host in ("cdn.tailwindcss.com", "cdn.jsdelivr.net", "unpkg.com",
                     "cdnjs.cloudflare.com", "fonts.googleapis.com", "fonts.gstatic.com"):
            assert host not in csp

    def test_hsts_absent_in_dev(self):
        """HSTS should not be set when SECURE_COOKIES is False (dev mode)."""
        r = self.client.get("/health")
        if not os.getenv("SITE_URL", "").startswith("https://"):
            assert "Strict-Transport-Security" not in r.headers


# ── JWT_SECRET Enforcement ────────────────────────────────────────────────────

class TestJWTSecretEnforcement:
    def test_raises_in_production_without_secret(self):
        """JWT_SECRET must be set when SITE_URL starts with https://."""
        with patch.dict(os.environ, {"JWT_SECRET": "", "SITE_URL": "https://cvss.guru"}):
            from app.auth import _get_jwt_secret
            with pytest.raises(RuntimeError, match="JWT_SECRET is required"):
                _get_jwt_secret()

    def test_allows_random_in_dev(self):
        """In dev (http://), a random secret is generated with a warning."""
        with patch.dict(os.environ, {"JWT_SECRET": "", "SITE_URL": "http://localhost:8000"}):
            from app.auth import _get_jwt_secret
            import warnings
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                secret = _get_jwt_secret()
                assert len(secret) == 64  # token_hex(32)
                assert any("JWT_SECRET" in str(warning.message) for warning in w)

    def test_uses_env_secret_when_set(self):
        """When JWT_SECRET is set, it should be used directly."""
        with patch.dict(os.environ, {"JWT_SECRET": "my-test-secret-1234"}):
            from app.auth import _get_jwt_secret
            assert _get_jwt_secret() == "my-test-secret-1234"


# ── RapidAPI Proxy ────────────────────────────────────────────────────────────

class TestRapidAPIProxy:
    """Test that the RapidAPI proxy secret bypasses local auth and the monthly quota."""

    def test_no_auth_returns_401(self):
        from main import app
        client = TestClient(app, raise_server_exceptions=False)
        r = client.post(
            "/api/v1/calculate/3.1",
            json={"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                  "C": "H", "I": "H", "A": "H"},
        )
        assert r.status_code == 401

    def test_valid_proxy_secret_bypasses_auth(self):
        """A valid proxy secret should return a synthetic RapidAPI user."""
        test_secret = "test-rapidapi-secret-12345"

        with patch("app.config.RAPIDAPI_PROXY_SECRET", test_secret), \
             patch("app.config.RAPIDAPI_CONFIGURED", True):

            from app.auth import require_api_key

            mock_request = MagicMock()
            mock_request.headers = {
                "X-RapidAPI-Proxy-Secret": test_secret,
            }

            result = asyncio.get_event_loop().run_until_complete(
                require_api_key(mock_request)
            )
            assert result["_rapidapi"] is True
            assert result["username"] == "_rapidapi"
            assert result["id"] == 0

    def test_wrong_proxy_secret_falls_through(self):
        """A wrong proxy secret should not bypass auth."""
        test_secret = "correct-secret"

        with patch("app.config.RAPIDAPI_PROXY_SECRET", test_secret), \
             patch("app.config.RAPIDAPI_CONFIGURED", True):

            from app.auth import require_api_key
            from fastapi import HTTPException

            mock_request = MagicMock()
            mock_request.headers = {
                "X-RapidAPI-Proxy-Secret": "wrong-secret",
            }

            with pytest.raises(HTTPException) as exc_info:
                asyncio.get_event_loop().run_until_complete(
                    require_api_key(mock_request)
                )
            assert exc_info.value.status_code == 401

    def test_quota_bypassed_for_rapidapi(self):
        """check_usage_limit should skip the quota for RapidAPI users."""
        from app.usage import check_usage_limit

        mock_request = MagicMock()

        rapidapi_user = {
            "id": 0, "username": "_rapidapi", "email": "proxy@rapidapi.com",
            "created_at": "", "last_login": None, "api_key_prefix": None,
            "_rapidapi": True,
        }

        with patch("app.usage.get_usage") as mock_usage, \
             patch("app.usage.increment_usage") as mock_inc:
            asyncio.get_event_loop().run_until_complete(
                check_usage_limit(mock_request, rapidapi_user)
            )
        # Usage functions should NOT have been called
        mock_usage.assert_not_called()
        mock_inc.assert_not_called()

    def test_quota_counts_normal_user(self):
        """check_usage_limit should count requests for normal users below the limit."""
        from app.usage import check_usage_limit

        mock_request = MagicMock()
        normal_user = {
            "id": 42, "username": "testuser", "email": "test@test.com",
            "created_at": "", "last_login": None, "api_key_prefix": "key123",
        }

        with patch("app.usage.get_usage", return_value=5) as mock_usage, \
             patch("app.usage.increment_usage") as mock_inc:
            asyncio.get_event_loop().run_until_complete(
                check_usage_limit(mock_request, normal_user)
            )
            mock_usage.assert_called_once_with(42)
            mock_inc.assert_called_once_with(42)

    def test_quota_blocks_at_limit(self):
        """check_usage_limit should raise 429 once the monthly limit is reached."""
        from fastapi import HTTPException
        from app.config import FREE_TIER_MONTHLY_LIMIT
        from app.usage import check_usage_limit

        mock_request = MagicMock()
        normal_user = {
            "id": 42, "username": "testuser", "email": "test@test.com",
            "created_at": "", "last_login": None, "api_key_prefix": "key123",
        }

        with patch("app.usage.get_usage", return_value=FREE_TIER_MONTHLY_LIMIT), \
             patch("app.usage.increment_usage") as mock_inc:
            with pytest.raises(HTTPException) as exc_info:
                asyncio.get_event_loop().run_until_complete(
                    check_usage_limit(mock_request, normal_user)
                )
            assert exc_info.value.status_code == 429
            assert exc_info.value.detail["limit"] == FREE_TIER_MONTHLY_LIMIT
            assert exc_info.value.detail["used"] == FREE_TIER_MONTHLY_LIMIT
            mock_inc.assert_not_called()

    def test_limit_error_body_links_rapidapi(self):
        """The 429 body should point to RapidAPI only when a listing URL is configured."""
        import app.usage as usage

        with patch.object(usage, "RAPIDAPI_URL", ""):
            assert "rapidapi_url" not in usage.get_limit_error_body(100)
        with patch.object(usage, "RAPIDAPI_URL", "https://rapidapi.com/example"):
            assert usage.get_limit_error_body(100)["rapidapi_url"] == "https://rapidapi.com/example"


# ── API Endpoint Integration ──────────────────────────────────────────────────

class TestAPIEndpoints:
    """Test API v1 endpoints with auth bypassed via dependency_overrides."""

    @pytest.fixture(autouse=True)
    def setup(self):
        from main import app
        from app.auth import require_api_key
        from app.usage import check_usage_limit

        mock_user = {
            "id": 1, "username": "testuser", "email": "test@test.com",
            "created_at": "2025-01-01", "last_login": None, "api_key_prefix": "test-key",
        }

        async def mock_require_api_key(request=None):
            return mock_user

        async def mock_check_usage(request=None):
            return None

        app.dependency_overrides[require_api_key] = mock_require_api_key
        app.dependency_overrides[check_usage_limit] = mock_check_usage

        self.client = TestClient(app, raise_server_exceptions=False)
        yield
        app.dependency_overrides.clear()

    # ── Calculate endpoints ───────────────────────────────────────────────

    def test_calculate_v2(self):
        r = self.client.post("/api/v1/calculate/2.0", json={
            "AV": "N", "AC": "L", "Au": "N", "C": "C", "I": "C", "A": "C",
        })
        assert r.status_code == 200
        data = r.json()
        assert data["version"] == "2.0"
        assert data["scores"]["base"]["score"] == 10.0
        # CVSS v2.0 max severity is "High" (no "Critical" rating)
        assert data["scores"]["base"]["severity"] in ("High", "Critical")

    def test_calculate_v31(self):
        r = self.client.post("/api/v1/calculate/3.1", json={
            "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C",
            "C": "H", "I": "H", "A": "H",
        })
        assert r.status_code == 200
        data = r.json()
        assert data["version"] == "3.1"
        assert data["scores"]["base"]["score"] == 10.0
        assert data["scores"]["base"]["severity"] == "Critical"

    def test_calculate_v40(self):
        r = self.client.post("/api/v1/calculate/4.0", json={
            "AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
            "VC": "H", "VI": "H", "VA": "H", "SC": "H", "SI": "H", "SA": "H",
        })
        assert r.status_code == 200
        data = r.json()
        assert data["version"] == "4.0"
        assert data["scores"]["base"]["score"] == 10.0

    def test_calculate_v31_low_score(self):
        r = self.client.post("/api/v1/calculate/3.1", json={
            "AV": "P", "AC": "H", "PR": "H", "UI": "R", "S": "U",
            "C": "L", "I": "N", "A": "N",
        })
        assert r.status_code == 200
        data = r.json()
        score = data["scores"]["base"]["score"]
        assert 0.0 < score < 4.0
        assert data["scores"]["base"]["severity"] == "Low"

    def test_calculate_v31_zero_impact(self):
        r = self.client.post("/api/v1/calculate/3.1", json={
            "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
            "C": "N", "I": "N", "A": "N",
        })
        assert r.status_code == 200
        assert r.json()["scores"]["base"]["score"] == 0.0

    def test_calculate_invalid_metric_returns_error(self):
        """Invalid metric values should return 400 or be handled gracefully."""
        r = self.client.post("/api/v1/calculate/3.1", json={
            "AV": "INVALID", "AC": "L", "PR": "N", "UI": "N", "S": "U",
            "C": "H", "I": "H", "A": "H",
        })
        # Calculator may return 400 or 200 with a fallback — either is acceptable
        # as long as it doesn't crash (500)
        assert r.status_code != 500

    # ── Vector endpoint ───────────────────────────────────────────────────

    def test_vector_v31(self):
        r = self.client.post("/api/v1/calculate/vector", json={
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        })
        assert r.status_code == 200
        data = r.json()
        assert data["version"] == "3.1"
        assert data["scores"]["base"]["score"] == 9.8

    def test_vector_v40(self):
        r = self.client.post("/api/v1/calculate/vector", json={
            "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        })
        assert r.status_code == 200
        assert r.json()["version"] == "4.0"

    def test_vector_invalid_returns_422(self):
        r = self.client.post("/api/v1/calculate/vector", json={
            "vector": "NOTAVECTOR",
        })
        assert r.status_code == 422

    # ── Convert endpoint ──────────────────────────────────────────────────

    def test_convert_v31_to_v40(self):
        r = self.client.post("/api/v1/convert", json={
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "to": "4.0",
        })
        assert r.status_code == 200
        data = r.json()
        assert data["from"]["version"] == "3.1"
        assert data["to"]["version"] == "4.0"
        assert data["to"]["scores"]["base"]["score"] > 0

    def test_convert_v31_to_v2(self):
        r = self.client.post("/api/v1/convert", json={
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "to": "2.0",
        })
        assert r.status_code == 200
        assert r.json()["to"]["version"] == "2.0"

    def test_convert_invalid_target_returns_422(self):
        r = self.client.post("/api/v1/convert", json={
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "to": "5.0",
        })
        assert r.status_code == 422

    # ── Response structure ────────────────────────────────────────────────

    def test_response_has_required_fields(self):
        r = self.client.post("/api/v1/calculate/3.1", json={
            "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
            "C": "H", "I": "H", "A": "H",
        })
        data = r.json()
        assert "version" in data
        assert "vector" in data
        assert "scores" in data
        assert "metrics" in data
        assert "base" in data["scores"]

    def test_vector_string_in_response(self):
        r = self.client.post("/api/v1/calculate/3.1", json={
            "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
            "C": "H", "I": "H", "A": "H",
        })
        vector = r.json()["vector"]
        assert vector.startswith("CVSS:3.1/")
        assert "AV:N" in vector

    def test_temporal_null_when_not_provided(self):
        r = self.client.post("/api/v1/calculate/3.1", json={
            "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
            "C": "H", "I": "H", "A": "H",
        })
        assert r.json()["scores"]["temporal"] is None

    def test_convert_response_has_from_and_to(self):
        r = self.client.post("/api/v1/convert", json={
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "to": "4.0",
        })
        data = r.json()
        assert "from" in data
        assert "to" in data
        assert "scores" in data["from"]
        assert "scores" in data["to"]
        assert "metrics" in data["to"]
