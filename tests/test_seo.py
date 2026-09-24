"""
Tests for SEO output (meta tags, crawler files, redirects) and reCAPTCHA verification.
"""

import asyncio
import json
import re
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.config import SITE_URL
from app.seo import PAGES


@pytest.fixture(scope="module")
def client():
    from main import app

    return TestClient(app, raise_server_exceptions=False)


class TestPageMeta:
    @pytest.mark.parametrize("key", list(PAGES))
    def test_public_pages_have_unique_meta_and_valid_jsonld(self, client, key):
        page = PAGES[key]
        html = client.get(page["path"]).text
        assert html.count("<title>") == 1
        assert f"<title>{page['title']}</title>" in html.replace("&amp;", "&")
        assert f'<link rel="canonical" href="{SITE_URL}{page["path"]}">' in html
        assert 'name="robots" content="index, follow' in html
        assert 'property="og:image"' in html
        ld = re.search(r'<script type="application/ld\+json">(.*?)</script>', html, re.S).group(1)
        types = {node["@type"] for node in json.loads(ld)["@graph"]}
        assert {"Organization", "WebSite", "WebPage", page["schema"]} <= types

    def test_home_has_h1(self, client):
        assert "<h1" in client.get("/").text

    def test_documentation_is_rendered_server_side(self, client):
        html = client.get("/documentation").text
        assert 'id="severity-ratings"' in html and "<table>" in html
        assert "marked.min.js" not in html


class TestCrawlerFiles:
    def test_robots_allows_crawlers_and_points_to_sitemap(self, client):
        body = client.get("/robots.txt").text
        assert "User-agent: *\nAllow: /" in body
        assert "User-agent: GPTBot" in body and "User-agent: ClaudeBot" in body
        assert f"Sitemap: {SITE_URL}/sitemap.xml" in body

    def test_sitemap_lists_every_public_page(self, client):
        r = client.get("/sitemap.xml")
        assert r.headers["content-type"].startswith("application/xml")
        for page in PAGES.values():
            assert f"<loc>{SITE_URL}{page['path']}</loc>" in r.text

    def test_llms_txt(self, client):
        body = client.get("/llms.txt").text
        assert body.startswith("# CVSS Guru\n\n> ")
        assert f"{SITE_URL}/documentation" in body

    def test_llms_full_contains_guide_and_api(self, client):
        body = client.get("/llms-full.txt").text
        assert "# CVSS Guide" in body and "/api/v1" in body


class TestRedirectsAnd404:
    @pytest.mark.parametrize("host", ["cvss.help", "www.cvss.info", "www.cvss.guru"])
    def test_alias_hosts_redirect_permanently(self, client, host):
        r = client.get("/cve-search?id=1", headers={"host": host}, follow_redirects=False)
        assert r.status_code == 301
        assert r.headers["location"] == f"{SITE_URL}/cve-search?id=1"

    def test_html_404_is_noindex(self, client):
        r = client.get("/does-not-exist", headers={"accept": "text/html"})
        assert r.status_code == 404 and 'content="noindex' in r.text

    def test_api_404_stays_json(self, client):
        r = client.get("/api/nope", headers={"accept": "text/html"})
        assert r.status_code == 404 and r.json()["success"] is False


class TestHead:
    @pytest.mark.parametrize("path", ["/", "/documentation", "/robots.txt", "/sitemap.xml"])
    def test_head_answers_like_get_without_body(self, client, path):
        r = client.head(path)
        assert r.status_code == 200
        assert r.content == b""
        assert "content-security-policy" in r.headers

    def test_head_on_post_only_route_is_405(self, client):
        assert client.head("/api/ai-score").status_code == 405

    def test_head_alias_host_redirects(self, client):
        r = client.head("/", headers={"host": "cvss.help"}, follow_redirects=False)
        assert r.status_code == 301 and r.content == b""


class TestRecaptcha:
    def _verify(self, google_reply):
        from app.routers import ai_scorer

        resp = MagicMock()
        resp.json.return_value = google_reply
        mock_client = MagicMock()
        mock_client.__aenter__.return_value.post = AsyncMock(return_value=resp)
        with patch("app.routers.ai_scorer.httpx.AsyncClient", return_value=mock_client), \
             patch("app.config.RECAPTCHA_MIN_SCORE", 0.5):
            return asyncio.get_event_loop().run_until_complete(ai_scorer._verify_recaptcha("tok", "1.2.3.4"))

    def test_accepts_human_score_for_right_action(self):
        assert self._verify({"success": True, "action": "ai_score", "score": 0.9}) is True

    def test_rejects_low_score(self):
        assert self._verify({"success": True, "action": "ai_score", "score": 0.1}) is False

    def test_rejects_wrong_action(self):
        assert self._verify({"success": True, "action": "login", "score": 0.9}) is False

    def test_rejects_failed_verification(self):
        assert self._verify({"success": False, "error-codes": ["invalid-input-response"]}) is False

    def test_rejects_empty_token_without_calling_google(self):
        from app.routers import ai_scorer

        with patch("app.routers.ai_scorer.httpx.AsyncClient") as mock_client:
            ok = asyncio.get_event_loop().run_until_complete(ai_scorer._verify_recaptcha("", "1.2.3.4"))
        assert ok is False
        mock_client.assert_not_called()


class TestFavicon:
    def test_favicon_ico_is_served(self, client):
        r = client.get("/favicon.ico")
        assert r.status_code == 200
        assert r.headers["content-type"] == "image/x-icon"
        assert r.content[:4] == b"\x00\x00\x01\x00"  # ICO magic number


class TestAssets:
    @pytest.mark.parametrize("path", ["/", "/ai-scorer", "/documentation", "/login"])
    def test_compiled_tailwind_is_linked_and_versioned(self, client, path):
        html = client.get(path).text
        assert "cdn.tailwindcss.com" not in html
        assert re.search(r'href="/static/css/app\.css\?v=[0-9a-f]{10}"', html)

    def test_versioned_static_file_is_served_with_long_cache(self, client):
        r = client.get("/static/css/app.css?v=anything")
        assert r.status_code == 200
        assert "immutable" in r.headers["cache-control"]


class TestPrivacyPage:
    def test_privacy_page_names_controller_and_contact(self, client):
        from app.config import CONTACT_EMAIL, PRIVACY_CONTROLLER

        r = client.get("/privacy")
        assert r.status_code == 200
        assert PRIVACY_CONTROLLER in r.text and f"mailto:{CONTACT_EMAIL}" in r.text
        assert 'content="noindex' in r.text  # legal page, not a search landing page

    def test_footer_links_privacy_policy(self, client):
        assert 'href="/privacy"' in client.get("/").text
