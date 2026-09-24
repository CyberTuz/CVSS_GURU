"""
Application configuration — all environment variables and site-wide constants.
Import this module wherever you need config values instead of reading os.getenv() directly.
"""

import logging as _logging
import os

# ── Local mode ────────────────────────────────────────────────────────────────

# LOCAL_MODE=true runs the app for a single user on their own machine:
# no database, no login/registration, no API keys or quotas, and no CAPTCHA
# on the AI Scorer. Never enable it on a public deployment.
LOCAL_MODE: bool = os.getenv("LOCAL_MODE", "").strip().lower() in ("1", "true", "yes", "on")

if LOCAL_MODE:
    _logging.getLogger("app.config").warning(
        "LOCAL_MODE is enabled — authentication, database and CAPTCHA are disabled. "
        "Do not use this setting on a public server."
    )

# ── Google Analytics 4 ───────────────────────────────────────────────────────

# Measurement ID (G-XXXXXXXXXX). Empty = analytics disabled.
GA_MEASUREMENT_ID: str = os.getenv("GA_MEASUREMENT_ID", "").strip()

# ── Site / SEO ────────────────────────────────────────────────────────────────

SITE_URL: str = os.getenv("SITE_URL", "https://cvss.guru")

SITE_NAME: str = "CVSS Guru"
APP_VERSION: str = "1.0.0"  # shown in the footer, /health and the OpenAPI spec

# Privacy policy: data controller shown on /privacy (GDPR Art. 13 asks for the
# identity of the controller — e.g. "CVSS Guru, operated by Jane Doe (Italy)").
PRIVACY_CONTROLLER: str = os.getenv("PRIVACY_CONTROLLER", "CVSS Guru")
CONTACT_EMAIL: str = os.getenv("CONTACT_EMAIL", "info@cvss.guru")

# Footer links: source code and donations
GITHUB_URL: str = "https://github.com/CyberTuz/CVSS_GURU"
DONATE_URL: str = "https://ko-fi.com/cybertuz"

# Hosts that 301-redirect to SITE_URL (www + alias domains), keeping path and query
DOMAIN_ALIASES: list[str] = [
    "www.cvss.guru",
    "cvss.help",
    "www.cvss.help",
    "cvss.info",
    "www.cvss.info",
]

# ── NVD API ───────────────────────────────────────────────────────────────────

NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")
NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# ── OpenRouter / AI Scorer ────────────────────────────────────────────────────

OPENROUTER_API_KEY: str = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_MODEL: str = os.getenv("OPENROUTER_MODEL", "openai/gpt-6-luna")
OPENROUTER_BASE_URL: str = "https://openrouter.ai/api/v1"
# Optional reasoning effort for models that think before answering
# (minimal|low|medium|high). Empty = provider default.
OPENROUTER_REASONING_EFFORT: str = os.getenv("OPENROUTER_REASONING_EFFORT", "").strip().lower()
OPENROUTER_TIMEOUT: float = float(os.getenv("OPENROUTER_TIMEOUT", "60"))

# ── Google reCAPTCHA v3 (AI Scorer, login, sign-up, forgot password) ─────────

# Keys from https://www.google.com/recaptcha/admin (type: reCAPTCHA v3).
# Without them the AI Scorer refuses requests, while the account forms skip the
# check and log a warning. In LOCAL_MODE nothing is checked.
RECAPTCHA_SITE_KEY: str = os.getenv("RECAPTCHA_SITE_KEY", "").strip()
RECAPTCHA_SECRET_KEY: str = os.getenv("RECAPTCHA_SECRET_KEY", "").strip()
# Minimum score (0.0 bot … 1.0 human) accepted
RECAPTCHA_MIN_SCORE: float = float(os.getenv("RECAPTCHA_MIN_SCORE", "0.5"))
RECAPTCHA_CONFIGURED: bool = bool(RECAPTCHA_SITE_KEY and RECAPTCHA_SECRET_KEY)

# ── Cookie security ──────────────────────────────────────────────────────────
#
# SECURE_COOKIES controls the `Secure` flag on the session cookie.
#
# Resolution order (first match wins):
#   1. SECURE_COOKIES env var set explicitly ("true" / "false")
#   2. Auto-detected from SITE_URL: https:// → True, http:// → False
#
# This means production (https://cvss.guru) gets Secure=True automatically
# with zero config, while local dev (http://localhost) stays False.

def _resolve_secure_cookies() -> bool:
    explicit = os.getenv("SECURE_COOKIES", "").strip().lower()
    if explicit == "true":
        return True
    if explicit == "false":
        return False
    # Auto-detect from SITE_URL
    return SITE_URL.startswith("https://")

SECURE_COOKIES: bool = _resolve_secure_cookies()

# ── AI Rate Limit ─────────────────────────────────────────────────────────────

AI_RATE_WINDOW: int = 3600   # seconds (1 hour)
AI_RATE_MAX: int = 10        # max requests per window per IP

# ── Email / SMTP ──────────────────────────────────────────────────────────────

SMTP_HOST: str = os.getenv("SMTP_HOST", "")
SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER: str = os.getenv("SMTP_USER", "")
SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM: str = os.getenv("SMTP_FROM", "")
SMTP_USE_TLS: bool = os.getenv("SMTP_USE_TLS", "true").strip().lower() == "true"

EMAIL_CONFIGURED: bool = bool(SMTP_HOST and SMTP_FROM)

if not EMAIL_CONFIGURED:
    _logging.getLogger("app.config").debug(
        "SMTP not configured — account emails (verification, password reset) are disabled. "
        "Set SMTP_HOST, SMTP_FROM (and optionally SMTP_USER, SMTP_PASSWORD)."
    )

# ── Account emails ────────────────────────────────────────────────────────────

PASSWORD_RESET_TOKEN_EXPIRE: int = 60 * 30  # 30 minutes
EMAIL_VERIFY_TOKEN_EXPIRE: int = 60 * 60 * 48  # 48 hours
# Accounts whose email was never confirmed are deleted after this many days
UNVERIFIED_ACCOUNT_TTL_DAYS: int = 7

# ── RapidAPI ──────────────────────────────────────────────────────────────────

# Secret shared between RapidAPI and this server.
# RapidAPI sends it in the X-RapidAPI-Proxy-Secret header on every proxied request.
# When set, requests with a valid proxy secret bypass local API key auth and the
# monthly quota (RapidAPI handles both on their side).
RAPIDAPI_PROXY_SECRET: str = os.getenv("RAPIDAPI_PROXY_SECRET", "")

RAPIDAPI_CONFIGURED: bool = bool(RAPIDAPI_PROXY_SECRET)

# Public RapidAPI listing, linked when a local API key hits its monthly quota.
RAPIDAPI_URL: str = os.getenv("RAPIDAPI_URL", "")

if RAPIDAPI_CONFIGURED:
    _logging.getLogger("app.config").info(
        "RapidAPI proxy secret configured — proxied requests will bypass local auth and quota."
    )

# ── API usage quota ───────────────────────────────────────────────────────────

# Monthly calls allowed per local API key. Higher volumes go through RapidAPI.
FREE_TIER_MONTHLY_LIMIT: int = 100
