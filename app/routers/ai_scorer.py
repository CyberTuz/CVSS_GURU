"""
AI Scorer router.

POST /api/ai-score — score a vulnerability description via OpenRouter
                     (protected by Google reCAPTCHA v3)
"""

import json
import secrets

import httpx
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import JSONResponse

from app.auth import get_current_user
from app.config import (
    AI_RATE_MAX,
    AI_RATE_WINDOW,
    OPENROUTER_API_KEY,
    OPENROUTER_BASE_URL,
    OPENROUTER_MODEL,
    OPENROUTER_REASONING_EFFORT,
    OPENROUTER_TIMEOUT,
    SITE_URL,
)
from app.ai_prompt import build_messages, parse_ai_json
from app.cvss_calculators.cvss31 import CVSS31Calculator
from app.db import db_execute
from app.deps import client_ip
from app.rate_limit import RateLimiter
from app.recaptcha import verify_recaptcha
from app.logging_config import get_logger

router = APIRouter()

# AI requests per IP per hour (shared across workers when a database is configured)
ai_limiter = RateLimiter("ai", max_requests=AI_RATE_MAX, window_seconds=AI_RATE_WINDOW)
logger = get_logger("routers.ai_scorer")


# ── Helpers ───────────────────────────────────────────────────────────────────

RECAPTCHA_ACTION = "ai_score"


async def _verify_recaptcha(token: str, remote_ip: str) -> bool:
    return await verify_recaptcha(token, remote_ip, RECAPTCHA_ACTION)


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/api/ai-score", response_class=JSONResponse, include_in_schema=False)
async def api_ai_score(
    request: Request,
    description: str = Form(...),
    recaptcha_token: str = Form(""),
    current_user=Depends(get_current_user),
):
    """Score a vulnerability description using AI via OpenRouter.

    First request is free (no login required).
    Subsequent requests require the user to be logged in.
    Tracked via the 'ai_scorer_used' cookie.

    In LOCAL_MODE the login gate, CAPTCHA, rate limit and DB logging are skipped.
    """
    from app.config import LOCAL_MODE, RECAPTCHA_CONFIGURED

    # ── Free-first-use gate ───────────────────────────────────────────────────
    # If the cookie is already set and the user is not logged in, block.
    already_used = request.cookies.get("ai_scorer_used") == "1"
    if already_used and not current_user and not LOCAL_MODE:
        return JSONResponse(
            status_code=401,
            content={
                "success": False,
                "error": "login_required",
                "message": "You've used your free analysis. Sign in to continue.",
            },
        )

    # After the free analysis, the account must have a confirmed email address:
    # otherwise signing up with a made-up address would bypass the gate.
    if already_used and current_user and not current_user.get("email_verified") and not LOCAL_MODE:
        return JSONResponse(
            status_code=403,
            content={
                "success": False,
                "error": "email_not_verified",
                "message": "Please confirm your email address (check your inbox or your profile page) to keep using the AI Scorer.",
            },
        )

    ip = client_ip(request)

    if not LOCAL_MODE:
        # Fail closed: without CAPTCHA keys the endpoint would be open to bots
        # spending the OpenRouter credit.
        if not RECAPTCHA_CONFIGURED:
            return JSONResponse(
                status_code=503,
                content={"success": False, "error": "CAPTCHA is not configured on this server."},
            )
        if not await _verify_recaptcha(recaptcha_token, ip):
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": "CAPTCHA verification failed. Please try again."},
            )

    if not LOCAL_MODE and not await ai_limiter.allow(ip):
        return JSONResponse(
            status_code=429,
            content={"success": False, "error": f"Rate limit exceeded. You can submit up to {AI_RATE_MAX} requests per hour."},
        )

    if not OPENROUTER_API_KEY:
        return JSONResponse(
            status_code=503,
            content={"success": False, "error": "AI scoring is not configured. Set OPENROUTER_API_KEY in environment."},
        )

    if len(description.strip()) < 20:
        return JSONResponse(
            status_code=422,
            content={"success": False, "error": "Description is too short. Please provide more detail about the vulnerability."},
        )

    body = {
        "model": OPENROUTER_MODEL,
        "messages": build_messages(description.strip()),
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
        "max_tokens": 6000,
    }
    if OPENROUTER_REASONING_EFFORT:
        body["reasoning"] = {"effort": OPENROUTER_REASONING_EFFORT}

    try:
        async with httpx.AsyncClient(timeout=OPENROUTER_TIMEOUT) as client:
            response = await client.post(
                f"{OPENROUTER_BASE_URL}/chat/completions",
                headers={
                    "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": SITE_URL,
                    "X-Title": "CVSS Guru AI Scorer",
                },
                json=body,
            )
            response.raise_for_status()
    except httpx.TimeoutException:
        return JSONResponse(status_code=504, content={"success": False, "error": "AI request timed out. Please try again."})
    except httpx.HTTPStatusError as exc:
        logger.error("openrouter_error", extra={"status": exc.response.status_code, "body": exc.response.text[:200]})
        return JSONResponse(status_code=502, content={"success": False, "error": "AI service returned an error. Please try again."})

    try:
        content = response.json()["choices"][0]["message"]["content"]
        ai_result = parse_ai_json(content)
    except (KeyError, IndexError, ValueError) as exc:
        logger.error("ai_parse_error", extra={"error": str(exc)})
        return JSONResponse(status_code=502, content={"success": False, "error": "Could not parse AI response. Please try again."})

    # Validate metric values
    valid_values = {
        "AV": {"N", "A", "L", "P"},
        "AC": {"L", "H"},
        "PR": {"N", "L", "H"},
        "UI": {"N", "R"},
        "S": {"U", "C"},
        "C": {"N", "L", "H"},
        "I": {"N", "L", "H"},
        "A": {"N", "L", "H"},
    }
    raw_metrics = ai_result.get("metrics", {})
    # Models occasionally answer "Network" or " n " instead of "N"
    metrics = {k: str(raw_metrics.get(k, "")).strip().upper()[:1] for k in valid_values}
    for key, allowed in valid_values.items():
        if metrics.get(key) not in allowed:
            return JSONResponse(
                status_code=502,
                content={"success": False, "error": f"AI returned an invalid value for metric {key}. Please try again."},
            )

    vector = (
        f"CVSS:3.1/AV:{metrics['AV']}/AC:{metrics['AC']}/PR:{metrics['PR']}"
        f"/UI:{metrics['UI']}/S:{metrics['S']}/C:{metrics['C']}/I:{metrics['I']}/A:{metrics['A']}"
    )
    score_result = CVSS31Calculator().calculate(metrics)

    result_payload = {
        "success": True,
        "score": score_result.get("base_score"),
        "severity": score_result.get("base_severity"),
        "vector": vector,
        "metrics": metrics,
        "reasoning": ai_result.get("reasoning", {}),
        "summary": ai_result.get("summary", ""),
        "confidence": ai_result.get("confidence", "medium"),
        "model": OPENROUTER_MODEL,
    }

    if LOCAL_MODE:
        return JSONResponse(content=result_payload)

    # Persist query (best-effort — never fail the request)
    try:
        await db_execute(
            "INSERT INTO ai_scorer_queries (user_id, description, result_json) VALUES (%s, %s, %s::jsonb)",
            [current_user["id"] if current_user else None, description.strip(), json.dumps(result_payload)],
        )
        # Retention: 90 days (see /privacy). Cheap opportunistic purge, no cron needed.
        if secrets.randbelow(50) == 0:
            await db_execute("DELETE FROM ai_scorer_queries WHERE created_at < now() - interval '90 days'")
    except Exception:
        pass

    # Set the "used" cookie so anonymous users are gated on the next request.
    # Logged-in users don't need it (they're always allowed), but we set it
    # anyway so the gate works correctly if they later log out.
    response = JSONResponse(content=result_payload)
    response.set_cookie(
        "ai_scorer_used",
        "1",
        max_age=60 * 60 * 24 * 365,  # 1 year
        httponly=True,
        samesite="lax",
    )
    return response
