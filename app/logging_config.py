"""
Centralized logging configuration for CVSS Guru.
Outputs JSON-formatted log lines if python-json-logger is installed,
otherwise falls back to plain text (so the app never crashes on startup).
"""
import importlib.util
import logging
import logging.config
import os

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

_HAS_JSON_LOGGER = importlib.util.find_spec("pythonjsonlogger") is not None

_PLAIN_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "plain": {
            "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stdout",
            "formatter": "plain",
        },
    },
    "root": {"level": LOG_LEVEL, "handlers": ["console"]},
    "loggers": {
        # uvicorn.error: keep for server errors (port binding, worker crashes)
        "uvicorn": {"propagate": True},
        "uvicorn.error": {"propagate": True},
        # uvicorn.access: SILENCED — we log requests ourselves in RequestLoggingMiddleware
        "uvicorn.access": {"level": "WARNING", "propagate": False},
        "gunicorn": {"propagate": True},
        "gunicorn.error": {"propagate": True},
        # watchfiles: only show warnings (suppress "N changes detected" noise in dev)
        "watchfiles": {"level": "WARNING", "propagate": False},
        "cvss_guru": {"level": LOG_LEVEL, "propagate": True},
    },
}

_JSON_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "()": "pythonjsonlogger.json.JsonFormatter",
            "format": "%(asctime)s %(name)s %(levelname)s %(message)s",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stdout",
            "formatter": "json",
        },
    },
    "root": {"level": LOG_LEVEL, "handlers": ["console"]},
    "loggers": {
        "uvicorn": {"propagate": True},
        "uvicorn.error": {"propagate": True},
        # uvicorn.access: SILENCED — we log requests ourselves in RequestLoggingMiddleware
        "uvicorn.access": {"level": "WARNING", "propagate": False},
        "gunicorn": {"propagate": True},
        "gunicorn.error": {"propagate": True},
        # watchfiles: only show warnings (suppress "N changes detected" noise in dev)
        "watchfiles": {"level": "WARNING", "propagate": False},
        "cvss_guru": {"level": LOG_LEVEL, "propagate": True},
    },
}


def configure_logging() -> None:
    """Apply logging configuration. Call once at startup."""
    config = _JSON_CONFIG if _HAS_JSON_LOGGER else _PLAIN_CONFIG
    logging.config.dictConfig(config)
    if not _HAS_JSON_LOGGER:
        logging.getLogger("cvss_guru").warning(
            "python-json-logger not installed — using plain text logging. "
            "Install it with: pip install python-json-logger"
        )


def get_logger(name: str) -> logging.Logger:
    """Return a named logger under the cvss_guru namespace."""
    return logging.getLogger(f"cvss_guru.{name}")
