"""
Google reCAPTCHA v3 verification (AI Scorer, login, sign-up, forgot password).

The browser gets a token with ``grecaptcha.execute(site_key, {action})``
(see partials/recaptcha_form.html) and posts it as ``recaptcha_token``.
"""

import httpx

from app.logging_config import get_logger

logger = get_logger("recaptcha")

RECAPTCHA_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"


async def verify_recaptcha(token: str, remote_ip: str, action: str) -> bool:
    """Verify a token with Google: success, expected action and minimum score."""
    from app.config import RECAPTCHA_MIN_SCORE, RECAPTCHA_SECRET_KEY

    if not token:
        return False
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                RECAPTCHA_VERIFY_URL,
                data={"secret": RECAPTCHA_SECRET_KEY, "response": token, "remoteip": remote_ip},
            )
            result = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.error("recaptcha_verify_error", extra={"error": str(exc)})
        return False

    ok = (
        result.get("success") is True
        and result.get("action") == action
        and float(result.get("score", 0)) >= RECAPTCHA_MIN_SCORE
    )
    if not ok:
        logger.info(
            "recaptcha_rejected",
            extra={
                "expected_action": action,
                "score": result.get("score"),
                "action": result.get("action"),
                "errors": result.get("error-codes"),
            },
        )
    return ok


async def check_form_captcha(token: str, remote_ip: str, action: str) -> bool:
    """CAPTCHA check for the account forms (login, sign-up, forgot password).

    Skipped in LOCAL_MODE. Without keys it lets the request through (and logs a
    warning): these forms are also rate limited, and locking everyone out of
    their account over a missing setting would be worse. The AI Scorer, which
    spends money, fails closed instead.
    """
    from app.config import LOCAL_MODE, RECAPTCHA_CONFIGURED

    if LOCAL_MODE:
        return True
    if not RECAPTCHA_CONFIGURED:
        logger.warning("recaptcha_not_configured", extra={"action": action})
        return True
    return await verify_recaptcha(token, remote_ip, action)
