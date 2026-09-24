"""
Security headers middleware.

Adds standard security headers to every HTTP response:
  - X-Content-Type-Options: nosniff
  - X-Frame-Options: DENY
  - X-XSS-Protection: 0  (modern browsers use CSP instead; legacy header disabled)
  - Referrer-Policy: strict-origin-when-cross-origin
  - Permissions-Policy: restricts camera, microphone, geolocation, etc.
  - Content-Security-Policy: self-hosted assets only, plus Google Analytics/reCAPTCHA
  - Strict-Transport-Security: HSTS with 1-year max-age (only when SECURE_COOKIES is True)
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.config import SECURE_COOKIES


_GA = " https://www.googletagmanager.com https://*.google-analytics.com https://*.analytics.google.com"
_RECAPTCHA = " https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/"

_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'" + _GA + _RECAPTCHA + "; "
    "style-src 'self' 'unsafe-inline'; "
    "font-src 'self'; "
    "img-src 'self' data:" + _GA + "; "
    "connect-src 'self'" + _GA + " https://www.google.com/recaptcha/; "
    "frame-src https://www.google.com/recaptcha/ https://recaptcha.google.com/recaptcha/; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self';"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Inject security headers into every response."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Prevent MIME-type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # Disable legacy XSS filter (CSP is the modern replacement)
        response.headers["X-XSS-Protection"] = "0"

        # Control referrer information
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Restrict browser features
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), "
            "payment=(), usb=(), magnetometer=(), gyroscope=()"
        )

        # Content Security Policy
        # Fonts, icons and libraries are self-hosted (app/static/vendor);
        # the only third parties are Google Analytics 4 and Google reCAPTCHA v3.
        response.headers["Content-Security-Policy"] = _CSP

        # HSTS — only on HTTPS (production)
        if SECURE_COOKIES:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )

        return response
