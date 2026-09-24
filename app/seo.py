"""
SEO registry — single source of truth for the public, indexable pages.

Used by:
  - partials/seo.html      (<title>, meta description, canonical, Open Graph, JSON-LD)
  - /sitemap.xml           (URLs and lastmod)
  - /llms.txt              (page list for AI assistants)

Pages that are not listed here (login, profile, password reset, ...) are
rendered with <meta name="robots" content="noindex">.
"""

import datetime
import json
import os
from functools import lru_cache

from app.config import CONTACT_EMAIL, GITHUB_URL, SITE_NAME, SITE_URL

_APP_DIR = os.path.dirname(os.path.abspath(__file__))
_TEMPLATES = os.path.join(_APP_DIR, "templates")

PAGES: dict[str, dict] = {
    "home": {
        "path": "/",
        "title": "CVSS Calculator for v4.0, v3.1, v3.0 & v2.0 — Free Online | CVSS Guru",
        "nav_title": "CVSS Calculator",
        "description": (
            "Free CVSS calculator for CVSS v4.0, v3.1, v3.0 and v2.0. Score vulnerabilities "
            "metric by metric, get the vector string, convert between versions and share results."
        ),
        "schema": "WebApplication",
        "sources": ["index.html", "macros.html"],
        "changefreq": "monthly",
        "priority": "1.0",
    },
    "ai-scorer": {
        "path": "/ai-scorer",
        "title": "AI CVSS Scorer — CVSS v3.1 Score from a Vulnerability Description | CVSS Guru",
        "nav_title": "AI Scorer",
        "description": (
            "Describe a vulnerability in plain English and get a suggested CVSS v3.1 base vector "
            "with a justification for every metric, benchmarked against NVD scores."
        ),
        "schema": "WebApplication",
        "sources": ["ai_scorer.html"],
        "changefreq": "monthly",
        "priority": "0.8",
    },
    "cve-search": {
        "path": "/cve-search",
        "title": "CVE Search — CVSS Scores for Any CVE from NVD | CVSS Guru",
        "nav_title": "CVE Search",
        "description": (
            "Look up any CVE ID and see its official CVSS v4.0, v3.1, v3.0 and v2.0 scores and "
            "vectors from the NVD, then open them in the calculator or converter."
        ),
        "schema": "WebApplication",
        "sources": ["cve_search.html"],
        "changefreq": "monthly",
        "priority": "0.8",
    },
    "documentation": {
        "path": "/documentation",
        "title": "CVSS Guide — Metrics, Versions and Scoring Examples Explained | CVSS Guru",
        "nav_title": "CVSS Guide",
        "description": (
            "Complete guide to CVSS: what every metric means in v2.0, v3.0, v3.1 and v4.0, how scores "
            "and severities are calculated, and worked examples with real CVEs."
        ),
        "schema": "TechArticle",
        "sources": ["documentation.html", "../docs/cvss_guide.md"],
        "changefreq": "monthly",
        "priority": "0.9",
    },
    "api-reference": {
        "path": "/api-reference",
        "title": "CVSS API — REST API for CVSS Scoring, Conversion and CVE Lookup | CVSS Guru",
        "nav_title": "API Reference",
        "description": (
            "REST API to calculate CVSS v2.0, v3.0, v3.1 and v4.0 scores, parse vector strings, "
            "convert between versions and look up CVE scores. JSON in, JSON out."
        ),
        "schema": "WebAPI",
        "sources": ["api_reference.html"],
        "changefreq": "monthly",
        "priority": "0.7",
    },
}


def page_url(key: str) -> str:
    return f"{SITE_URL}{PAGES[key]['path']}"


def lastmod(key: str) -> datetime.date:
    """Most recent modification date of the files that make up a page."""
    times = []
    for src in PAGES[key]["sources"]:
        path = os.path.normpath(os.path.join(_TEMPLATES, src))
        if os.path.exists(path):
            times.append(os.path.getmtime(path))
    ts = max(times) if times else datetime.datetime.now().timestamp()
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).date()


def _page_node(key: str) -> dict:
    page = PAGES[key]
    url = page_url(key)
    node: dict = {"@id": f"{url}#main", "url": url, "name": page["nav_title"], "description": page["description"]}

    if page["schema"] == "WebApplication":
        node.update({
            "@type": "WebApplication",
            "applicationCategory": "SecurityApplication",
            "operatingSystem": "Any (web browser)",
            "isAccessibleForFree": True,
            "offers": {"@type": "Offer", "price": "0", "priceCurrency": "EUR"},
            "publisher": {"@id": f"{SITE_URL}/#organization"},
        })
        if key == "home":
            node["featureList"] = [
                "CVSS v4.0 calculator", "CVSS v3.1 calculator", "CVSS v3.0 calculator",
                "CVSS v2.0 calculator", "Conversion between CVSS versions",
                "Vector string parsing and generation", "Shareable score links",
            ]
    elif page["schema"] == "TechArticle":
        node.update({
            "@type": "TechArticle",
            "headline": page["title"].split(" | ")[0],
            "about": {"@type": "Thing", "name": "Common Vulnerability Scoring System (CVSS)"},
            "author": {"@id": f"{SITE_URL}/#organization"},
            "publisher": {"@id": f"{SITE_URL}/#organization"},
            "dateModified": lastmod(key).isoformat(),
            "inLanguage": "en",
        })
    elif page["schema"] == "WebAPI":
        node.update({
            "@type": "WebAPI",
            "documentation": url,
            "provider": {"@id": f"{SITE_URL}/#organization"},
        })
    return node


@lru_cache(maxsize=None)
def jsonld(key: str) -> str:
    """JSON-LD @graph for a page (Organization, WebSite, WebPage, page entity, breadcrumbs)."""
    page = PAGES[key]
    url = page_url(key)
    graph = [
        {
            "@type": "Organization",
            "@id": f"{SITE_URL}/#organization",
            "name": SITE_NAME,
            "url": f"{SITE_URL}/",
            "logo": f"{SITE_URL}/static/brand/icon-512.png",
            "email": CONTACT_EMAIL,
            "sameAs": [GITHUB_URL],
        },
        {
            "@type": "WebSite",
            "@id": f"{SITE_URL}/#website",
            "url": f"{SITE_URL}/",
            "name": SITE_NAME,
            "description": PAGES["home"]["description"],
            "publisher": {"@id": f"{SITE_URL}/#organization"},
            "inLanguage": "en",
        },
        {
            "@type": "WebPage",
            "@id": url,
            "url": url,
            "name": page["title"],
            "description": page["description"],
            "isPartOf": {"@id": f"{SITE_URL}/#website"},
            "mainEntity": {"@id": f"{url}#main"},
            "primaryImageOfPage": f"{SITE_URL}/static/og-image.png",
            "dateModified": lastmod(key).isoformat(),
            "inLanguage": "en",
        },
        _page_node(key),
    ]
    if key != "home":
        graph.append({
            "@type": "BreadcrumbList",
            "itemListElement": [
                {"@type": "ListItem", "position": 1, "name": SITE_NAME, "item": f"{SITE_URL}/"},
                {"@type": "ListItem", "position": 2, "name": page["nav_title"], "item": url},
            ],
        })
    # "</" must not appear inside a <script> block
    return json.dumps({"@context": "https://schema.org", "@graph": graph}, ensure_ascii=False).replace("</", "<\\/")


def seo_page(key: str) -> dict:
    """Template helper: everything partials/seo.html needs for one page."""
    page = PAGES[key]
    return {
        "key": key,
        "title": page["title"],
        "description": page["description"],
        "url": page_url(key),
        "jsonld": jsonld(key),
    }
