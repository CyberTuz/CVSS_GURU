"""
Shared application dependencies.

Calculator instances are created once at import time and reused across all
requests. Import from here instead of instantiating in each router.
"""

import hashlib
import os
from functools import lru_cache

from fastapi import Request
from fastapi.templating import Jinja2Templates

from app.config import (
    APP_VERSION,
    CONTACT_EMAIL,
    DONATE_URL,
    GA_MEASUREMENT_ID,
    GITHUB_URL,
    LOCAL_MODE,
    RECAPTCHA_SITE_KEY,
    SITE_URL,
)
from app.seo import seo_page
from app.cvss_calculators.cvss2 import CVSS2Calculator
from app.cvss_calculators.cvss3 import CVSS3Calculator
from app.cvss_calculators.cvss31 import CVSS31Calculator
from app.cvss_calculators.cvss4 import CVSS4Calculator

# ── CVSS Calculators ──────────────────────────────────────────────────────────

cvss2_calc = CVSS2Calculator()
cvss3_calc = CVSS3Calculator()
cvss31_calc = CVSS31Calculator()
cvss4_calc = CVSS4Calculator()

# ── Jinja2 Templates ──────────────────────────────────────────────────────────

templates = Jinja2Templates(directory="app/templates")


_STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


@lru_cache(maxsize=256)
def _asset_version(path: str, mtime: float) -> str:
    with open(os.path.join(_STATIC_DIR, path), "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()[:10]


def static_url(path: str) -> str:
    """URL of a static asset with a content hash (?v=...).

    Static files are served with a one-year immutable cache; the hash changes
    whenever the file changes, so browsers always fetch the new version.
    """
    clean = path.lstrip("/")
    full = os.path.join(_STATIC_DIR, clean)
    if not os.path.isfile(full):
        return f"/static/{clean}"
    return f"/static/{clean}?v={_asset_version(clean, os.path.getmtime(full))}"


def client_ip(request: Request) -> str:
    """Visitor IP behind the reverse proxy (Traefik sets X-Forwarded-For / X-Real-IP)."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "unknown"


# Globals available in every template
templates.env.globals.update(
    {
        "ga_measurement_id": GA_MEASUREMENT_ID,
        "recaptcha_site_key": RECAPTCHA_SITE_KEY,
        "site_url": SITE_URL,
        "seo_page": seo_page,
        "static_url": static_url,
        "local_mode": LOCAL_MODE,
        "app_version": APP_VERSION,
        "contact_email": CONTACT_EMAIL,
        "github_url": GITHUB_URL,
        "donate_url": DONATE_URL,
    }
)
