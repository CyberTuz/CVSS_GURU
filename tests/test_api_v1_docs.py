"""API v1: OpenAPI examples match real output, RapidAPI spec, auth lookup, logging, error shape."""
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from main import app

_USER = {"id": 42, "username": "u", "email": "u@example.invalid", "created_at": "", "last_login": None,
         "api_key_prefix": "abcd1234"}


@pytest.fixture(scope="module")
def client():
    return TestClient(app, base_url="https://testserver")


@pytest.fixture
def authed():
    """Authenticate every API call as _USER with a working quota counter."""
    with patch("app.auth.db_query", AsyncMock(return_value=[_USER])) as lookup, \
         patch("app.usage.get_usage", AsyncMock(return_value=0)), \
         patch("app.usage.increment_usage", AsyncMock()):
        yield lookup


def _drop_none(value):
    if isinstance(value, dict):
        return {k: _drop_none(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_drop_none(v) for v in value]
    return value


class TestOpenAPIExamples:
    def test_spec_has_server_and_examples(self, client):
        spec = client.get("/openapi.json").json()
        assert spec["servers"][0]["url"].startswith("https://")
        for path, methods in spec["paths"].items():
            if not path.startswith("/api/v1/"):
                continue
            for op in methods.values():
                assert "example" in op["responses"]["200"]["content"]["application/json"], path
                assert "example" in op["responses"]["401"]["content"]["application/json"], path

    def test_post_examples_are_the_real_responses(self, client, authed):
        spec = client.get("/openapi.json").json()
        checked = 0
        for path, methods in spec["paths"].items():
            op = methods.get("post")
            if not path.startswith("/api/v1/") or not op:
                continue
            request = op["requestBody"]["content"]["application/json"]["example"]
            expected = op["responses"]["200"]["content"]["application/json"]["example"]
            r = client.post(path, json=request, headers={"X-API-Key": "k"})
            assert r.status_code == 200, (path, r.text)
            assert _drop_none(r.json()) == expected, path
            checked += 1
        assert checked == 6


class TestRapidAPISpec:
    def test_rapidapi_spec_is_clean(self, client):
        spec = client.get("/openapi-rapidapi.json").json()
        assert spec["openapi"] == "3.0.3"
        assert spec["servers"][0]["url"].startswith("https://")
        assert "securitySchemes" not in spec.get("components", {})
        assert all(p.startswith("/api/v1/") for p in spec["paths"])
        text = str(spec)
        assert "X-API-Key" not in text and "'type': 'null'" not in text
        for methods in spec["paths"].values():
            for op in methods.values():
                assert "security" not in op and "429" not in op["responses"]

    def test_main_spec_still_documents_local_keys(self, client):
        spec = client.get("/openapi.json").json()
        assert "ApiKeyHeader" in spec["components"]["securitySchemes"]


class TestAuthAndLogging:
    def test_api_key_is_looked_up_once_per_request(self, client, authed):
        r = client.post("/api/v1/calculate/vector", headers={"X-API-Key": "k"},
                        json={"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
        assert r.status_code == 200
        assert authed.await_count == 1

    def test_rapidapi_calls_are_logged_with_user_and_plan(self, client):
        with patch("app.config.RAPIDAPI_CONFIGURED", True), \
             patch("app.config.RAPIDAPI_PROXY_SECRET", "s3cret"), \
             patch("app.usage.get_usage") as usage, \
             patch("app.usage.logger") as log:
            r = client.post("/api/v1/calculate/vector",
                            headers={"X-RapidAPI-Proxy-Secret": "s3cret", "X-RapidAPI-User": "acme",
                                     "X-RapidAPI-Subscription": "PRO"},
                            json={"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
        assert r.status_code == 200
        usage.assert_not_called()
        event, = [c for c in log.info.call_args_list if c.args[0] == "api_call"]
        assert event.kwargs["extra"] == {"channel": "rapidapi", "path": "/api/v1/calculate/vector",
                                         "rapidapi_user": "acme", "rapidapi_plan": "PRO"}

    def test_wrong_proxy_secret_needs_a_key(self, client):
        with patch("app.config.RAPIDAPI_CONFIGURED", True), patch("app.config.RAPIDAPI_PROXY_SECRET", "s3cret"):
            r = client.post("/api/v1/calculate/vector", headers={"X-RapidAPI-Proxy-Secret": "nope"},
                            json={"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
        assert r.status_code == 401 and r.json() == {"success": False, "error": "API key required"}


class TestErrorShape:
    def test_endpoint_errors_have_success_false(self, client, authed):
        r = client.post("/api/v1/calculate/vector", headers={"X-API-Key": "k"}, json={"vector": "garbage"})
        assert r.status_code == 422
        assert r.json() == {"success": False, "error": "Cannot detect CVSS version from vector string."}

    def test_quota_error_is_flat(self, client):
        from app.config import FREE_TIER_MONTHLY_LIMIT

        with patch("app.auth.db_query", AsyncMock(return_value=[_USER])), \
             patch("app.usage.get_usage", AsyncMock(return_value=FREE_TIER_MONTHLY_LIMIT)):
            r = client.post("/api/v1/calculate/vector", headers={"X-API-Key": "k"},
                            json={"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
        assert r.status_code == 429
        body = r.json()
        assert body["success"] is False and body["error"] == "Monthly API limit reached"
        assert body["limit"] == body["used"] == FREE_TIER_MONTHLY_LIMIT


class TestInteractiveDocs:
    def test_swagger_ui_is_self_hosted(self, client):
        html = client.get("/docs").text
        assert "/static/vendor/swagger/swagger-ui-bundle.js" in html
        assert "cdn.jsdelivr.net" not in html and "fastapi.tiangolo.com" not in html

    def test_redoc_redirects_to_docs(self, client):
        r = client.get("/redoc", follow_redirects=False)
        assert r.status_code == 301 and r.headers["location"] == "/docs"


class TestValidation:
    def test_invalid_metric_value_is_400(self, client, authed):
        body = {"AV": "Z", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"}
        r = client.post("/api/v1/calculate/3.1", headers={"X-API-Key": "k"}, json=body)
        assert r.status_code == 400 and "'AV'" in r.json()["error"]

    def test_incomplete_vector_is_400(self, client, authed):
        r = client.post("/api/v1/calculate/vector", headers={"X-API-Key": "k"}, json={"vector": "CVSS:3.1/AV:N"})
        assert r.status_code == 400 and "Missing base metric" in r.json()["error"]

    def test_v4_modified_metrics_are_accepted(self, client, authed):
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MAV:L/MSI:S"
        r = client.post("/api/v1/calculate/vector", headers={"X-API-Key": "k"}, json={"vector": vector})
        assert r.status_code == 200
        r = client.post("/api/v1/convert", headers={"X-API-Key": "k"}, json={"vector": vector, "to": "3.1"})
        assert r.status_code == 200
