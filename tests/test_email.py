"""SMTP connection mode selection (no network)."""
from unittest.mock import MagicMock, patch

import pytest

import app.email as email_mod


@pytest.mark.parametrize(
    "port, use_tls, expect_ssl, expect_starttls",
    [
        (465, True, True, False),   # implicit TLS even if SMTP_USE_TLS=true
        (465, False, True, False),
        (587, True, False, True),   # STARTTLS
        (25, False, False, False),  # plain
    ],
)
def test_connect_mode(port, use_tls, expect_ssl, expect_starttls):
    with patch.object(email_mod, "SMTP_PORT", port), \
         patch.object(email_mod, "SMTP_USE_TLS", use_tls), \
         patch.object(email_mod, "SMTP_USER", "u"), \
         patch.object(email_mod, "SMTP_PASSWORD", "p"), \
         patch.object(email_mod.smtplib, "SMTP_SSL") as smtp_ssl, \
         patch.object(email_mod.smtplib, "SMTP") as smtp:
        server = email_mod._connect()
    assert smtp_ssl.called is expect_ssl
    assert smtp.called is not expect_ssl
    assert server.starttls.called is expect_starttls
    server.login.assert_called_once_with("u", "p")


def test_send_email_sets_headers_and_envelope():
    server = MagicMock()
    with patch.object(email_mod, "EMAIL_CONFIGURED", True), \
         patch.object(email_mod, "SMTP_FROM", "info@cvss.guru"), \
         patch.object(email_mod, "_connect") as connect:
        connect.return_value.__enter__.return_value = server
        assert email_mod.send_email("a@example.invalid", "Hi", "<p>Hello</p>") is True
    from_addr, to, raw = server.sendmail.call_args[0]
    assert from_addr == "info@cvss.guru" and to == ["a@example.invalid"]
    assert "From: CVSS Guru <info@cvss.guru>" in raw
    assert "Message-ID:" in raw and "Date:" in raw


def test_send_email_never_raises():
    with patch.object(email_mod, "EMAIL_CONFIGURED", True), \
         patch.object(email_mod, "SMTP_FROM", "info@cvss.guru"), \
         patch.object(email_mod, "_connect", side_effect=TimeoutError("timed out")):
        assert email_mod.send_email("a@example.invalid", "Hi", "<p>x</p>") is False
