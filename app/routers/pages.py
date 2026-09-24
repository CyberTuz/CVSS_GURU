"""
Page routes — HTML pages plus the crawler files (robots.txt, sitemap.xml, llms.txt).
"""

import os

from fastapi import APIRouter, Depends, Request
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, Response

from app.auth import get_current_user
from app.config import (
    CONTACT_EMAIL,
    FREE_TIER_MONTHLY_LIMIT,
    GITHUB_URL,
    PRIVACY_CONTROLLER,
    RAPIDAPI_URL,
    SITE_NAME,
    SITE_URL,
    UNVERIFIED_ACCOUNT_TTL_DAYS,
)
from app.cvss_calculators.descriptions import CVSS_DESCRIPTIONS
from app.deps import templates
from app.docs_render import guide_html, read_guide
from app.seo import PAGES, lastmod, page_url

router = APIRouter(include_in_schema=False)

# Crawler files change only on deploy; let CDNs and bots cache them for a day.
_CRAWLER_CACHE = {"Cache-Control": "public, max-age=86400"}


@router.get("/", response_class=HTMLResponse)
async def home(request: Request, current_user=Depends(get_current_user)):
    """Home page with all calculators."""
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "current_user": current_user, "descriptions": CVSS_DESCRIPTIONS},
    )


@router.get("/documentation", response_class=HTMLResponse)
async def documentation(request: Request, current_user=Depends(get_current_user)):
    """CVSS guide, rendered server-side from app/docs/cvss_guide.md."""
    return templates.TemplateResponse(
        "documentation.html",
        {"request": request, "current_user": current_user, "guide_html": guide_html()},
    )


@router.get("/ai-scorer", response_class=HTMLResponse)
async def ai_scorer_page(request: Request, current_user=Depends(get_current_user)):
    """AI Scorer page."""
    from app.config import OPENROUTER_API_KEY, OPENROUTER_MODEL

    return templates.TemplateResponse(
        "ai_scorer.html",
        {
            "request": request,
            "current_user": current_user,
            "ai_configured": bool(OPENROUTER_API_KEY),
            "ai_model": OPENROUTER_MODEL,
        },
    )


@router.get("/cve-search", response_class=HTMLResponse)
async def cve_search_page(request: Request, current_user=Depends(get_current_user)):
    """CVE Search page."""
    return templates.TemplateResponse(
        "cve_search.html",
        {"request": request, "current_user": current_user},
    )


@router.get("/api-reference", response_class=HTMLResponse)
async def api_reference(request: Request, current_user=Depends(get_current_user)):
    """API Reference page."""
    return templates.TemplateResponse(
        "api_reference.html",
        {
            "request": request,
            "current_user": current_user,
            "monthly_limit": FREE_TIER_MONTHLY_LIMIT,
            "rapidapi_url": RAPIDAPI_URL,
        },
    )


# Bump when the content of templates/privacy.html changes
PRIVACY_POLICY_UPDATED = "24 September 2026"


@router.get("/privacy", response_class=HTMLResponse)
async def privacy_page(request: Request, current_user=Depends(get_current_user)):
    """Privacy & cookie policy (GDPR information notice)."""
    return templates.TemplateResponse(
        "privacy.html",
        {
            "request": request,
            "current_user": current_user,
            "site_name": SITE_NAME,
            "privacy_controller": PRIVACY_CONTROLLER,
            "contact_email": CONTACT_EMAIL,
            "policy_updated": PRIVACY_POLICY_UPDATED,
            "unverified_ttl_days": UNVERIFIED_ACCOUNT_TTL_DAYS,
        },
    )


# ── Crawler files ─────────────────────────────────────────────────────────────

_FAVICON = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "static", "favicon.ico")


@router.get("/favicon.ico")
async def favicon():
    return FileResponse(_FAVICON, media_type="image/x-icon", headers={"Cache-Control": "public, max-age=604800"})


# Search engines and AI assistants/answer engines are explicitly welcome on the
# public pages. Remove a user agent from this list to opt it out.
_AI_AGENTS = [
    "GPTBot", "OAI-SearchBot", "ChatGPT-User",
    "ClaudeBot", "Claude-SearchBot", "Claude-User",
    "PerplexityBot", "Perplexity-User",
    "Google-Extended", "Applebot-Extended", "CCBot",
]
_DISALLOW = ["/api/", "/reset-password/"]


@router.get("/robots.txt", response_class=PlainTextResponse)
async def robots_txt():
    rules = "\n".join(f"Disallow: {path}" for path in _DISALLOW)
    ai_agents = "\n".join(f"User-agent: {ua}" for ua in _AI_AGENTS)
    body = (
        f"# CVSS Guru — {SITE_URL}\n"
        "# cvss.help, cvss.info and www.cvss.guru permanently redirect here.\n\n"
        f"User-agent: *\nAllow: /\n{rules}\n\n"
        "# AI assistants and answer engines may read and cite the public pages.\n"
        f"{ai_agents}\nAllow: /\n{rules}\n\n"
        f"Sitemap: {SITE_URL}/sitemap.xml\n"
    )
    return PlainTextResponse(body, headers=_CRAWLER_CACHE)


@router.get("/sitemap.xml")
async def sitemap_xml():
    urls = "".join(
        "  <url>\n"
        f"    <loc>{page_url(key)}</loc>\n"
        f"    <lastmod>{lastmod(key).isoformat()}</lastmod>\n"
        f"    <changefreq>{page['changefreq']}</changefreq>\n"
        f"    <priority>{page['priority']}</priority>\n"
        "  </url>\n"
        for key, page in PAGES.items()
    )
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"{urls}</urlset>\n"
    )
    return Response(xml, media_type="application/xml", headers=_CRAWLER_CACHE)


def _llms_summary() -> str:
    """llms.txt (https://llmstxt.org): what the site is and where the content lives."""
    tools = "\n".join(
        f"- [{PAGES[k]['nav_title']}]({page_url(k)}): {PAGES[k]['description']}"
        for k in ("home", "ai-scorer", "cve-search")
    )
    return f"""# CVSS Guru

> CVSS Guru ({SITE_URL}) is a free web toolkit for the Common Vulnerability Scoring System (CVSS):
> a calculator for CVSS v4.0, v3.1, v3.0 and v2.0, a converter between versions, an AI scorer that
> suggests a CVSS v3.1 vector from a plain-language vulnerability description, a CVE lookup backed by
> the NVD, a complete CVSS guide and a REST API. No account is needed for the web tools.

Scores follow the FIRST CVSS specifications. Severity bands (v3.x/v4.0): None 0.0, Low 0.1–3.9,
Medium 4.0–6.9, High 7.0–8.9, Critical 9.0–10.0. CVSS v2.0 has no Critical band.

## Tools

{tools}

## Documentation

- [CVSS Guide]({page_url('documentation')}): {PAGES['documentation']['description']} Full text: {SITE_URL}/llms-full.txt
- [API Reference]({page_url('api-reference')}): {PAGES['api-reference']['description']}

## Linking to results

- Calculator with a vector pre-filled: {SITE_URL}/?calc=v31&vector=CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
  (calc = v2, v3, v31 or v4)
- Converter pre-filled: {SITE_URL}/?tool=converter&from=3.1&vector=CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Optional

- [Source code]({GITHUB_URL}): open source (MIT)
"""


@router.get("/llms.txt", response_class=PlainTextResponse)
async def llms_txt():
    return PlainTextResponse(_llms_summary(), headers=_CRAWLER_CACHE)


@router.get("/llms-full.txt", response_class=PlainTextResponse)
async def llms_full_txt():
    from app.routers.api_v1 import router as api_router

    endpoints = "\n".join(
        f"- {', '.join(sorted(r.methods))} {r.path}: {(r.description or r.summary or '').strip().splitlines()[0] if (r.description or r.summary) else ''}"
        for r in api_router.routes
        if getattr(r, "methods", None)
    )
    body = (
        _llms_summary()
        + "\n---\n\n# REST API endpoints\n\n"
        + f"Base URL: {SITE_URL}/api/v1 — JSON requests and responses, API key in the "
        + "`Authorization: Bearer <key>` or `X-API-Key` header "
        + f"({FREE_TIER_MONTHLY_LIMIT} free calls per month per key; higher volumes through RapidAPI). "
        + f"OpenAPI spec: {SITE_URL}/openapi.json. Details: "
        + f"{page_url('api-reference')}\n\n{endpoints}\n\n---\n\n"
        + read_guide()
    )
    return PlainTextResponse(body, headers=_CRAWLER_CACHE)
