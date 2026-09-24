"""
Authentication routes.

GET  /register
POST /register
GET  /login
POST /login
GET  /logout
GET  /profile
GET  /verify-email/{token}
POST /api/user/resend-verification
GET  /forgot-password
POST /forgot-password
GET  /reset-password/{token}
POST /reset-password/{token}
POST /api/user/delete-account
"""

import asyncio
import datetime
import hashlib
import secrets
from html import escape

from fastapi import APIRouter, BackgroundTasks, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.auth import (
    COOKIE_NAME,
    create_session_token,
    api_key_prefix,
    generate_api_key,
    hash_api_key,
    get_current_user,
    hash_password,
    require_user,
    verify_password,
)
from app.config import (
    CONTACT_EMAIL,
    EMAIL_CONFIGURED,
    EMAIL_VERIFY_TOKEN_EXPIRE,
    FREE_TIER_MONTHLY_LIMIT,
    PASSWORD_RESET_TOKEN_EXPIRE,
    RAPIDAPI_URL,
    SECURE_COOKIES,
    SITE_NAME,
    SITE_URL,
    UNVERIFIED_ACCOUNT_TTL_DAYS,
)
from app.usage import get_usage
from app.csrf import generate_csrf_token, require_csrf
from app.db import db_execute, db_query
from app.deps import client_ip, templates
from app.logging_config import get_logger
from app.email import email_layout, send_email
from app.rate_limit import auth_limiter, login_account_limiter, register_limiter, verify_email_limiter
from app.recaptcha import check_form_captcha

router = APIRouter(include_in_schema=False)
logger = get_logger("routers.auth")


_COOKIE_MAX_AGE = 60 * 60 * 24 * 30  # 30 days

_RATE_LIMIT_MSG = "Too many attempts. Please wait a few minutes and try again."
_CAPTCHA_MSG = (
    "The anti-bot check failed. Please try again — if it keeps failing, "
    "disable content blockers for this page."
)

_STRONG = 'style="color: #e4e4e7;"'


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# ── Email verification helpers ────────────────────────────────────────────────

async def _issue_verification_link(user_id: int) -> str:
    """Replace the user's verification token and return the link to email.

    Only the SHA-256 of the token is stored.
    """
    token = secrets.token_urlsafe(32)
    await db_execute("DELETE FROM email_verification_tokens WHERE user_id = %s", [user_id])
    await db_execute(
        "INSERT INTO email_verification_tokens (user_id, token_hash, expires_at) "
        "VALUES (%s, %s, now() + make_interval(secs => %s))",
        [user_id, _hash_token(token), EMAIL_VERIFY_TOKEN_EXPIRE],
    )
    return f"{SITE_URL}/verify-email/{token}"


def _verification_email(username: str, url: str) -> str:
    return email_layout(
        "Confirm your email address",
        [
            f"Hi <strong {_STRONG}>{escape(username)}</strong>,",
            f"thanks for signing up to {SITE_NAME}. Please confirm your email address to generate "
            "API keys and keep using the AI Scorer:",
        ],
        button=("Confirm email", url),
        note=(
            f"This link expires in {EMAIL_VERIFY_TOKEN_EXPIRE // 3600} hours. If you didn't create this account, "
            f"just ignore this email: unconfirmed accounts are deleted automatically after "
            f"{UNVERIFIED_ACCOUNT_TTL_DAYS} days."
        ),
    )


def _account_deleted_email(username: str) -> str:
    when = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return email_layout(
        "Your account has been deleted",
        [
            f"Hi <strong {_STRONG}>{escape(username)}</strong>,",
            f"as requested, your {SITE_NAME} account and all its data (API key, usage counters "
            f"and AI Scorer history) were permanently deleted on {when}.",
            "Thanks for having used the site. The calculator, converter and CVE search remain "
            "available without an account.",
        ],
        note=(
            "If you did not request this, someone knew your password: write to "
            f'<a href="mailto:{CONTACT_EMAIL}" style="color: #d4940a;">{CONTACT_EMAIL}</a>.'
        ),
    )


async def _purge_unverified_accounts() -> None:
    """Delete accounts whose email was never confirmed (also frees squatted emails)."""
    try:
        await db_execute(
            "DELETE FROM users WHERE email_verified_at IS NULL "
            "AND created_at < now() - make_interval(days => %s)",
            [UNVERIFIED_ACCOUNT_TTL_DAYS],
        )
    except Exception as exc:
        logger.error("unverified_purge_failed", extra={"error": str(exc)})


def _snippet(text: str, success: bool) -> str:
    """Small HTMX feedback box (profile page)."""
    if success:
        return (
            '<div class="flex items-center gap-2 px-4 py-3 rounded-lg text-sm mt-3"'
            ' style="background:rgba(34,197,94,0.08);border:1px solid rgba(34,197,94,0.2);color:#4ade80;">'
            f'<i class="ph ph-check-circle"></i>{text}</div>'
        )
    return (
        '<div class="flex items-center gap-2 px-4 py-3 rounded-lg text-sm mt-3"'
        ' style="background:rgba(248,113,113,0.08);border:1px solid rgba(248,113,113,0.2);color:#f87171;">'
        f'<i class="ph ph-warning-circle"></i>{text}</div>'
    )


# ── Register ──────────────────────────────────────────────────────────────────

@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request, user=Depends(get_current_user)):
    if user:
        return RedirectResponse("/profile", status_code=302)
    return templates.TemplateResponse(
        "register.html",
        {"request": request, "active_category": None, "csrf_token": generate_csrf_token()},
    )


@router.post("/register", response_class=HTMLResponse)
async def register_post(
    request: Request,
    background_tasks: BackgroundTasks,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
    recaptcha_token: str = Form(""),
    _csrf=Depends(require_csrf),
):
    username = username.strip()
    email = email.strip()

    # ── Rate limit ────────────────────────────────────────────────────────────
    # Only successful sign-ups are counted (see below), so typos in the form
    # do not lock people out.
    ip = client_ip(request)
    if await register_limiter.remaining(ip) == 0:
        retry = await register_limiter.retry_after(ip)
        return templates.TemplateResponse(
            "register.html",
            {
                "request": request,
                "active_category": None,
                "error": _RATE_LIMIT_MSG,
                "form": {"username": username, "email": email},
                "csrf_token": generate_csrf_token(),
            },
            headers={"Retry-After": str(retry)},
        )

    error = None

    if not await check_form_captcha(recaptcha_token, ip, "register"):
        error = _CAPTCHA_MSG
    elif len(username) < 3 or len(username) > 32:
        error = "Username must be between 3 and 32 characters."
    elif not username.replace("_", "").replace("-", "").isalnum():
        error = "Username may only contain letters, numbers, hyphens and underscores."
    elif "@" not in email or len(email) > 254 or any(c.isspace() for c in email):
        error = "Please enter a valid email address."
    elif len(password) < 8:
        error = "Password must be at least 8 characters."
    elif password != password_confirm:
        error = "Passwords do not match."
    else:
        await _purge_unverified_accounts()
        existing = await db_query(
            "SELECT id FROM users WHERE username = %s OR email = %s",
            [username, email],
        )
        if existing:
            error = "Username or email is already registered."

    if error:
        return templates.TemplateResponse(
            "register.html",
            {
                "request": request,
                "active_category": None,
                "error": error,
                "form": {"username": username, "email": email},
                "csrf_token": generate_csrf_token(),
            },
        )

    pw_hash = await asyncio.to_thread(hash_password, password)
    # No API key at sign-up: the user generates one from the profile and sees it once.
    rows = await db_query(
        "INSERT INTO users (username, email, password) VALUES (%s, %s, %s) RETURNING id, username",
        [username, email, pw_hash],
    )
    user = rows[0]
    await register_limiter.hit(ip)  # record the created account

    verify_url = await _issue_verification_link(user["id"])
    background_tasks.add_task(
        send_email, email, f"{SITE_NAME} — Confirm your email address",
        _verification_email(user["username"], verify_url),
    )
    logger.info("user_registered", extra={"user_id": user["id"]})

    token = create_session_token(user["id"], user["username"])
    response = RedirectResponse("/profile", status_code=302)
    response.set_cookie(
        COOKIE_NAME,
        token,
        httponly=True,
        samesite="lax",
        secure=SECURE_COOKIES,
        max_age=_COOKIE_MAX_AGE,
    )
    return response


# ── Login ─────────────────────────────────────────────────────────────────────

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, user=Depends(get_current_user), reset: str = "", verified: str = ""):
    if user:
        suffix = f"?verified={verified}" if verified else ""
        return RedirectResponse(f"/profile{suffix}", status_code=302)
    ctx = {"request": request, "active_category": None, "csrf_token": generate_csrf_token()}
    if reset == "1":
        ctx["success"] = "Password reset successfully. You can now sign in with your new password."
    elif verified == "1":
        ctx["success"] = "Email confirmed. Sign in to continue."
    elif verified == "invalid":
        ctx["error"] = "This confirmation link is invalid or has expired. Sign in to request a new one."
    return templates.TemplateResponse("login.html", ctx)


@router.post("/login", response_class=HTMLResponse)
async def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    recaptcha_token: str = Form(""),
    _csrf=Depends(require_csrf),
):
    username = username.strip()

    def _error(message: str, headers: dict | None = None):
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "active_category": None,
                "error": message,
                "form": {"username": username},
                "csrf_token": generate_csrf_token(),
            },
            headers=headers,
        )

    # ── Rate limits: per IP, then failed attempts per account ────────────────
    ip = client_ip(request)
    if not await auth_limiter.allow(ip):
        return _error(_RATE_LIMIT_MSG, {"Retry-After": str(await auth_limiter.retry_after(ip))})

    if not await check_form_captcha(recaptcha_token, ip, "login"):
        return _error(_CAPTCHA_MSG)

    account_key = username.lower()
    if await login_account_limiter.remaining(account_key) == 0:
        logger.warning("login_account_limited", extra={"username": username})
        return _error(_RATE_LIMIT_MSG, {"Retry-After": str(await login_account_limiter.retry_after(account_key))})

    rows = await db_query(
        "SELECT id, username, password FROM users WHERE username = %s",
        [username],
    )
    user = rows[0] if rows else None

    if not user or not await asyncio.to_thread(verify_password, password, user["password"]):
        await login_account_limiter.hit(account_key)
        return _error("Invalid username or password.")

    await db_execute(
        "UPDATE users SET last_login = now() WHERE id = %s",
        [user["id"]],
    )

    token = create_session_token(user["id"], user["username"])
    response = RedirectResponse("/profile", status_code=302)
    response.set_cookie(
        COOKIE_NAME,
        token,
        httponly=True,
        samesite="lax",
        secure=SECURE_COOKIES,
        max_age=_COOKIE_MAX_AGE,
    )
    return response


# ── Logout ────────────────────────────────────────────────────────────────────

@router.get("/logout")
async def logout():
    response = RedirectResponse("/", status_code=302)
    response.delete_cookie(COOKIE_NAME)
    return response


# ── Profile ───────────────────────────────────────────────────────────────────

@router.get("/profile", response_class=HTMLResponse)
async def profile_page(request: Request, user=Depends(get_current_user), verified: str = ""):
    if not user:
        suffix = f"?verified={verified}" if verified else ""
        return RedirectResponse(f"/login{suffix}", status_code=302)
    usage = await get_usage(user["id"])
    flash_success = flash_error = None
    if verified == "1":
        flash_success = "Email confirmed — thanks! You can now generate an API key."
    elif verified == "invalid" and not user.get("email_verified"):
        flash_error = "This confirmation link is invalid or has expired. Use “Resend email” below to get a new one."
    return templates.TemplateResponse(
        "profile.html",
        {
            "request": request,
            "active_category": None,
            "user": user,
            "current_user": user,
            "usage": usage,
            "limit": FREE_TIER_MONTHLY_LIMIT,
            "rapidapi_url": RAPIDAPI_URL,
            "unverified_ttl_days": UNVERIFIED_ACCOUNT_TTL_DAYS,
            "flash_success": flash_success,
            "flash_error": flash_error,
            "csrf_token": generate_csrf_token(),
        },
    )


# ── Email verification ────────────────────────────────────────────────────────

@router.get("/verify-email/{token}")
async def verify_email(token: str, user=Depends(get_current_user)):
    """Confirm the address from the link in the verification email."""
    target = "/profile" if user else "/login"
    rows = await db_query(
        "SELECT user_id, expires_at < now() AS expired FROM email_verification_tokens WHERE token_hash = %s",
        [_hash_token(token)],
    )
    if not rows or rows[0]["expired"]:
        return RedirectResponse(f"{target}?verified=invalid", status_code=302)

    user_id = rows[0]["user_id"]
    await db_execute(
        "UPDATE users SET email_verified_at = COALESCE(email_verified_at, now()) WHERE id = %s", [user_id]
    )
    await db_execute("DELETE FROM email_verification_tokens WHERE user_id = %s", [user_id])
    logger.info("email_verified", extra={"user_id": user_id})
    return RedirectResponse(f"{target}?verified=1", status_code=302)


@router.post("/api/user/resend-verification", response_class=HTMLResponse, include_in_schema=False)
async def resend_verification(
    background_tasks: BackgroundTasks,
    user=Depends(require_user),
    _csrf=Depends(require_csrf),
):
    if user.get("email_verified"):
        return HTMLResponse(_snippet("Your email address is already confirmed.", success=True))
    if not await verify_email_limiter.allow(str(user["id"])):
        return HTMLResponse(_snippet("Too many emails requested. Please try again in an hour.", success=False))

    verify_url = await _issue_verification_link(user["id"])
    background_tasks.add_task(
        send_email, user["email"], f"{SITE_NAME} — Confirm your email address",
        _verification_email(user["username"], verify_url),
    )
    return HTMLResponse(_snippet(
        f"Sent to <strong>{escape(user['email'])}</strong>. Check your inbox (and spam folder).", success=True
    ))


# ── API Key Regeneration ──────────────────────────────────────────────────────

@router.post("/api/user/regenerate-api-key", response_class=HTMLResponse, include_in_schema=False)
async def regenerate_api_key(request: Request, user=Depends(require_user), _csrf=Depends(require_csrf)):
    """Create a new API key (replacing the old one) and show it once via HTMX.

    Only its SHA-256 hash and an 8-character prefix are stored.
    Requires a confirmed email address.
    """
    if not user.get("email_verified"):
        return templates.TemplateResponse(
            "partials/api_key_card.html",
            {"request": request, "email_verified": False, "csrf_token": generate_csrf_token()},
            status_code=403,
        )
    new_key = generate_api_key()
    await db_execute(
        "UPDATE users SET api_key_hash = %s, api_key_prefix = %s WHERE id = %s",
        [hash_api_key(new_key), api_key_prefix(new_key), user["id"]],
    )
    return templates.TemplateResponse(
        "partials/api_key_card.html",
        {
            "request": request,
            "new_key": new_key,
            "api_key_prefix": api_key_prefix(new_key),
            "email_verified": True,
            "csrf_token": generate_csrf_token(),
        },
    )


# ── Change Password ───────────────────────────────────────────────────────────

@router.post("/api/user/change-password", response_class=HTMLResponse, include_in_schema=False)
async def change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    new_password_confirm: str = Form(...),
    user=Depends(require_user),
    _csrf=Depends(require_csrf),
):
    """Change the user's password. Returns an HTML feedback snippet for HTMX."""

    def _msg(text: str, success: bool) -> str:
        if success:
            return (
                f'<div class="pw-success flex items-center gap-2 px-4 py-3 rounded-lg text-sm mb-4"'
                f' style="background:rgba(34,197,94,0.08);border:1px solid rgba(34,197,94,0.2);color:#4ade80;">'
                f'<i class="ph ph-check-circle"></i>{text}</div>'
            )
        return (
            f'<div class="flex items-center gap-2 px-4 py-3 rounded-lg text-sm mb-4"'
            f' style="background:rgba(248,113,113,0.08);border:1px solid rgba(248,113,113,0.2);color:#f87171;">'
            f'<i class="ph ph-warning-circle"></i>{text}</div>'
        )

    # Fetch current password hash from DB
    rows = await db_query("SELECT password FROM users WHERE id = %s", [user["id"]])
    if not rows:
        return HTMLResponse(_msg("User not found.", success=False))

    if not await asyncio.to_thread(verify_password, current_password, rows[0]["password"]):
        return HTMLResponse(_msg("Current password is incorrect.", success=False))

    if len(new_password) < 8:
        return HTMLResponse(_msg("New password must be at least 8 characters.", success=False))

    if new_password != new_password_confirm:
        return HTMLResponse(_msg("New passwords do not match.", success=False))

    if current_password == new_password:
        return HTMLResponse(_msg("New password must differ from the current one.", success=False))

    new_hash = await asyncio.to_thread(hash_password, new_password)
    await db_execute("UPDATE users SET password = %s WHERE id = %s", [new_hash, user["id"]])

    return HTMLResponse(_msg("Password updated successfully.", success=True))


# ── Forgot Password ───────────────────────────────────────────────────────────

@router.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_page(request: Request, user=Depends(get_current_user)):
    if user:
        return RedirectResponse("/profile", status_code=302)
    return templates.TemplateResponse(
        "forgot_password.html",
        {"request": request, "active_category": None, "csrf_token": generate_csrf_token()},
    )


@router.post("/forgot-password", response_class=HTMLResponse)
async def forgot_password_post(
    request: Request,
    email: str = Form(...),
    recaptcha_token: str = Form(""),
    _csrf=Depends(require_csrf),
):
    # Rate limit: reuse auth_limiter (5 per 5 min per IP), then CAPTCHA
    ip = client_ip(request)
    rate_limited = not await auth_limiter.allow(ip)
    if rate_limited or not await check_form_captcha(recaptcha_token, ip, "forgot_password"):
        return templates.TemplateResponse(
            "forgot_password.html",
            {
                "request": request,
                "active_category": None,
                "error": _RATE_LIMIT_MSG if rate_limited else _CAPTCHA_MSG,
                "form": {"email": email},
                "csrf_token": generate_csrf_token(),
            },
        )

    # Always show the same success message to prevent email enumeration.
    _success_msg = (
        "If an account with that email exists, we've sent a password reset link. "
        "Check your inbox (and spam folder). The link expires in 30 minutes."
    )

    if not EMAIL_CONFIGURED:
        logger.warning("password_reset_attempted_no_smtp", extra={"email": email})
        # Still show success to avoid leaking that email isn't configured
        return templates.TemplateResponse(
            "forgot_password.html",
            {
                "request": request,
                "active_category": None,
                "success": _success_msg,
                "csrf_token": generate_csrf_token(),
            },
        )

    # Look up user by email
    rows = await db_query("SELECT id, username, email FROM users WHERE email = %s", [email.strip()])
    if not rows:
        # Don't reveal whether the email exists
        return templates.TemplateResponse(
            "forgot_password.html",
            {
                "request": request,
                "active_category": None,
                "success": _success_msg,
                "csrf_token": generate_csrf_token(),
            },
        )

    user = rows[0]

    # Generate a secure token
    token = secrets.token_urlsafe(48)

    # Invalidate any existing unused tokens for this user, then store the new one
    try:
        await db_execute(
            "UPDATE password_reset_tokens SET used = TRUE WHERE user_id = %s AND NOT used",
            [user["id"]],
        )
        await db_execute(
            "INSERT INTO password_reset_tokens (user_id, token, expires_at) "
            "VALUES (%s, %s, now() + make_interval(secs => %s))",
            [user["id"], token, PASSWORD_RESET_TOKEN_EXPIRE],
        )
    except Exception as exc:
        logger.error("password_reset_token_insert_failed", extra={"error": str(exc)})
        return templates.TemplateResponse(
            "forgot_password.html",
            {
                "request": request,
                "active_category": None,
                "error": "Something went wrong. Please try again later.",
                "csrf_token": generate_csrf_token(),
            },
        )

    # Send the email
    reset_url = f"{SITE_URL}/reset-password/{token}"
    email_html = email_layout(
        "Password reset",
        [
            f"Hi <strong {_STRONG}>{escape(user['username'])}</strong>,",
            f"we received a request to reset your password on {SITE_NAME}. "
            "Click the button below to set a new password:",
        ],
        button=("Reset password", reset_url),
        note="This link expires in 30 minutes. If you didn't request this, you can safely ignore this email.",
    )

    sent = await asyncio.to_thread(
        send_email,
        to=user["email"],
        subject=f"{SITE_NAME} — Password Reset",
        body_html=email_html,
    )

    if not sent:
        logger.error("password_reset_email_failed", extra={"user_id": user["id"]})

    return templates.TemplateResponse(
        "forgot_password.html",
        {
            "request": request,
            "active_category": None,
            "success": _success_msg,
            "csrf_token": generate_csrf_token(),
        },
    )


# ── Reset Password (token link) ──────────────────────────────────────────────

@router.get("/reset-password/{token}", response_class=HTMLResponse)
async def reset_password_page(request: Request, token: str):
    # Validate token
    rows = await db_query(
        "SELECT id, user_id, used, expires_at < now() AS expired "
        "FROM password_reset_tokens WHERE token = %s",
        [token],
    )
    expired = not rows or rows[0]["used"] or rows[0]["expired"]

    return templates.TemplateResponse(
        "reset_password.html",
        {
            "request": request,
            "active_category": None,
            "token": token,
            "expired": expired,
            "csrf_token": generate_csrf_token(),
        },
    )


@router.post("/reset-password/{token}", response_class=HTMLResponse)
async def reset_password_post(
    request: Request,
    token: str,
    password: str = Form(...),
    password_confirm: str = Form(...),
    _csrf=Depends(require_csrf),
):
    # Validate token
    rows = await db_query(
        "SELECT id, user_id, used, expires_at < now() AS expired "
        "FROM password_reset_tokens WHERE token = %s",
        [token],
    )

    if not rows or rows[0]["used"] or rows[0]["expired"]:
        return templates.TemplateResponse(
            "reset_password.html",
            {
                "request": request,
                "active_category": None,
                "token": token,
                "expired": True,
                "csrf_token": generate_csrf_token(),
            },
        )

    token_row = rows[0]

    # Validate password
    if len(password) < 8:
        return templates.TemplateResponse(
            "reset_password.html",
            {
                "request": request,
                "active_category": None,
                "token": token,
                "error": "Password must be at least 8 characters.",
                "csrf_token": generate_csrf_token(),
            },
        )

    if password != password_confirm:
        return templates.TemplateResponse(
            "reset_password.html",
            {
                "request": request,
                "active_category": None,
                "token": token,
                "error": "Passwords do not match.",
                "csrf_token": generate_csrf_token(),
            },
        )

    # Update password
    new_hash = await asyncio.to_thread(hash_password, password)
    # Resetting through the emailed link also proves the address works
    await db_execute(
        "UPDATE users SET password = %s, email_verified_at = COALESCE(email_verified_at, now()) WHERE id = %s",
        [new_hash, token_row["user_id"]],
    )

    # Mark token as used
    await db_execute("UPDATE password_reset_tokens SET used = TRUE WHERE id = %s", [token_row["id"]])

    logger.info("password_reset_completed", extra={"user_id": token_row["user_id"]})

    # Redirect to login with success message
    return RedirectResponse("/login?reset=1", status_code=302)


# ── Account Deletion (GDPR) ──────────────────────────────────────────────────

@router.post("/api/user/delete-account", response_class=HTMLResponse, include_in_schema=False)
async def delete_account(
    request: Request,
    background_tasks: BackgroundTasks,
    confirm_password: str = Form(...),
    user=Depends(require_user),
    _csrf=Depends(require_csrf),
):
    """Permanently delete the user's account and all associated data, then confirm by email."""

    def _msg(text: str, success: bool) -> str:
        if success:
            return (
                f'<div class="flex items-center gap-2 px-4 py-3 rounded-lg text-sm mb-4"'
                f' style="background:rgba(34,197,94,0.08);border:1px solid rgba(34,197,94,0.2);color:#4ade80;">'
                f'<i class="ph ph-check-circle"></i>{text}</div>'
            )
        return (
            f'<div class="flex items-center gap-2 px-4 py-3 rounded-lg text-sm mb-4"'
            f' style="background:rgba(248,113,113,0.08);border:1px solid rgba(248,113,113,0.2);color:#f87171;">'
            f'<i class="ph ph-warning-circle"></i>{text}</div>'
        )

    # Verify password
    rows = await db_query("SELECT password FROM users WHERE id = %s", [user["id"]])
    if not rows:
        return HTMLResponse(_msg("User not found.", success=False))

    if not await asyncio.to_thread(verify_password, confirm_password, rows[0]["password"]):
        return HTMLResponse(_msg("Incorrect password. Account was not deleted.", success=False))

    user_id = user["id"]

    # Tokens, usage counters and AI queries are removed by ON DELETE CASCADE
    await db_execute("DELETE FROM users WHERE id = %s", [user_id])

    logger.info("account_deleted", extra={"user_id": user_id, "username": user["username"]})

    # Confirmation only to confirmed addresses (never to an address typed by someone else)
    if user.get("email_verified"):
        background_tasks.add_task(
            send_email, user["email"], f"{SITE_NAME} — Your account has been deleted",
            _account_deleted_email(user["username"]),
        )

    # Clear the session cookie and go to the home page. HTMX follows a 302 inside
    # the XHR (and would swap the whole home page into the form), so HTMX requests
    # get a 200 with HX-Redirect, which makes the browser navigate.
    if request.headers.get("HX-Request"):
        response = HTMLResponse("", headers={"HX-Redirect": "/"})
    else:
        response = RedirectResponse("/", status_code=302)
    response.delete_cookie(COOKIE_NAME)
    return response
