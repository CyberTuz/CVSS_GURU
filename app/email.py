"""
Email module — send transactional emails via SMTP.

Usage::

    from app.email import send_email, EMAIL_CONFIGURED

    if EMAIL_CONFIGURED:
        send_email(
            to="user@example.com",
            subject="Password Reset",
            body_html="<p>Click <a href='...'>here</a> to reset.</p>",
        )

Configuration is read from environment variables (see app/config.py):
  SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM, SMTP_USE_TLS
"""

import re
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid, parseaddr

from app.config import (
    SMTP_HOST,
    SMTP_PORT,
    SMTP_USER,
    SMTP_PASSWORD,
    SMTP_FROM,
    SMTP_USE_TLS,
    EMAIL_CONFIGURED,
    SITE_NAME,
)
from app.logging_config import get_logger

logger = get_logger("email")

_TIMEOUT = 15


def _connect() -> smtplib.SMTP:
    """Open an authenticated SMTP connection.

    Port 465 always means implicit TLS (SMTPS), whatever SMTP_USE_TLS says:
    speaking plain SMTP/STARTTLS to it just hangs until the timeout.
    Otherwise SMTP_USE_TLS=true means STARTTLS (587), false means plain (25).
    """
    context = ssl.create_default_context()
    if SMTP_PORT == 465:
        server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=_TIMEOUT, context=context)
    else:
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=_TIMEOUT)
        if SMTP_USE_TLS:
            server.starttls(context=context)
    if SMTP_USER and SMTP_PASSWORD:
        server.login(SMTP_USER, SMTP_PASSWORD)
    return server


def send_email(to: str, subject: str, body_html: str) -> bool:
    """Send an HTML email. Returns True on success, False on failure.

    Never raises — errors are logged and swallowed so callers don't need
    to handle SMTP failures (transactional emails are best-effort).
    Blocking: call it from async code with ``asyncio.to_thread``.
    """
    if not EMAIL_CONFIGURED:
        logger.warning("email_not_configured", extra={"to": to, "subject": subject})
        return False

    # SMTP_FROM may be "info@cvss.guru" or "CVSS Guru <info@cvss.guru>"
    from_name, from_addr = parseaddr(SMTP_FROM)

    msg = MIMEMultipart("alternative")
    msg["From"] = formataddr((from_name or SITE_NAME, from_addr))
    msg["To"] = to
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain=from_addr.split("@")[-1] or None)

    # Plain-text fallback (strip tags naively — good enough for simple emails)
    body_text = re.sub(r"<[^>]+>", "", body_html)
    body_text = re.sub(r"\s+", " ", body_text).strip()

    msg.attach(MIMEText(body_text, "plain", "utf-8"))
    msg.attach(MIMEText(body_html, "html", "utf-8"))

    try:
        with _connect() as server:
            server.sendmail(from_addr, [to], msg.as_string())
        logger.info("email_sent", extra={"to": to, "subject": subject})
        return True

    except Exception as exc:
        logger.error("email_send_failed", extra={"to": to, "error": str(exc)})
        return False


# ── Layout ────────────────────────────────────────────────────────────────────

def email_layout(heading: str, paragraphs: list[str], button: tuple[str, str] | None = None,
                 note: str = "") -> str:
    """Simple dark HTML email shared by all transactional messages.

    *paragraphs* and *note* are trusted HTML; *button* is ``(label, url)``.
    The URL is repeated as text below the button for clients that block it.
    """
    p_style = "color: #a1a1aa; font-size: 14px; line-height: 1.6;"
    body = "".join(f'<p style="{p_style}">{p}</p>' for p in paragraphs)
    if button:
        label, url = button
        body += (
            '<div style="text-align: center; margin: 28px 0;">'
            f'<a href="{url}" style="display: inline-block; background: linear-gradient(135deg, #d4940a, #b07a08); '
            'color: white; font-weight: 600; font-size: 14px; padding: 12px 32px; border-radius: 8px; '
            f'text-decoration: none;">{label}</a></div>'
            '<p style="color: #71717a; font-size: 12px; line-height: 1.6;">'
            "If the button doesn't work, copy and paste this URL into your browser:<br>"
            f'<a href="{url}" style="color: #d4940a; word-break: break-all;">{url}</a></p>'
        )
    if note:
        body += f'<p style="color: #71717a; font-size: 12px; line-height: 1.6;">{note}</p>'
    return (
        "<div style=\"font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; "
        "max-width: 480px; margin: 0 auto; padding: 32px 24px; background: #18181b; border-radius: 12px;\">"
        f'<h2 style="color: #e4e4e7; margin-bottom: 8px;">{heading}</h2>'
        f"{body}"
        '<hr style="border: none; border-top: 1px solid #27272a; margin: 24px 0;">'
        f'<p style="color: #52525b; font-size: 11px;">{SITE_NAME} &mdash; CVSS Calculator &amp; Converter</p>'
        "</div>"
    )
