"""
CVSS Guru — FastAPI application entry point.

Wires together middleware, static files, routers, the health check and the
OpenAPI / Swagger endpoints. Business logic lives in app/routers/ and app/*.py.
"""

import asyncio
import os
import time
import uuid
from contextlib import asynccontextmanager

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import APP_VERSION, DOMAIN_ALIASES, LOCAL_MODE, SITE_URL
from app.deps import templates
from app.logging_config import configure_logging, get_logger
from app.routers import ai_scorer, api_v1, auth, convert, cve, htmx, pages
from app.security_headers import SecurityHeadersMiddleware

configure_logging()
logger = get_logger("main")

APP_START_TIME = time.time()

# ── Lifespan ──────────────────────────────────────────────────────────────────

def _run_migrations() -> None:
    """Apply pending DB migrations. Safe on every boot — applied ones are skipped."""
    try:
        from scripts.migrate import run_migrations
        applied = run_migrations(verbose=False)
        if applied:
            logger.info("db_migrations_applied", extra={"count": applied})
        else:
            logger.debug("db_migrations_up_to_date")
    except RuntimeError as exc:
        # DATABASE_URL not set — non-fatal in environments without a DB
        logger.warning("db_migrations_skipped", extra={"reason": str(exc)})
    except Exception as exc:
        # Migration failure is logged but does NOT prevent the app from starting.
        # This avoids a boot loop if the DB is temporarily unreachable.
        logger.error("db_migrations_failed", extra={"error": str(exc)})


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ───────────────────────────────────────────────────────────────
    logger.info(
        "cvss_guru_starting",
        extra={"site_url": SITE_URL, "log_level": os.getenv("LOG_LEVEL", "INFO"), "local_mode": LOCAL_MODE},
    )

    if LOCAL_MODE:
        logger.info("db_migrations_skipped", extra={"reason": "LOCAL_MODE"})
    else:
        await asyncio.to_thread(_run_migrations)

    yield  # application runs here

    # ── Shutdown ──────────────────────────────────────────────────────────────
    from app.db import close_pool
    await close_pool()
    logger.info("cvss_guru_stopping")


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="CVSS Guru API",
    description=(
        "Calculate, convert, and look up CVSS vulnerability scores programmatically.\n\n"
        "## Authentication\n\n"
        "All `/api/v1/*` endpoints require an API key. "
        "Pass it via the `Authorization: Bearer <key>` or `X-API-Key: <key>` header.\n\n"
        "Get your API key from your [profile page](https://cvss.guru/profile) after registering.\n\n"
        "## Usage limits\n\n"
        "Each API key includes 100 free calls per month. "
        "For higher volumes, use CVSS Guru on RapidAPI.\n\n"
        "Errors always have the shape `{\"success\": false, \"error\": \"...\"}`.\n\n"
        "The web interface (calculator, converter, CVE search) is always free and requires no API key."
    ),
    version=APP_VERSION,
    lifespan=lifespan,
    # Served below with self-hosted Swagger UI (the defaults load it from a CDN, blocked by the CSP)
    docs_url=None,
    redoc_url=None,
    openapi_tags=[
        {
            "name": "CVSS Guru API v1",
            "description": "Public REST API for CVSS score calculation, conversion, and CVE lookup.",
            "externalDocs": {
                "description": "API Reference",
                "url": "https://cvss.guru/api-reference",
            },
        }
    ],
)

# ── Exception handlers ────────────────────────────────────────────────────────

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    logger.warning(
        "http_exception",
        extra={"path": request.url.path, "status_code": exc.status_code, "detail": str(exc.detail)},
    )
    # Browsers get an HTML 404 page (noindex); API clients keep the JSON body.
    wants_html = "text/html" in request.headers.get("accept", "")
    if exc.status_code == 404 and wants_html and not request.url.path.startswith("/api/"):
        return templates.TemplateResponse(
            "404.html",
            {"request": request, "current_user": None, "path": request.url.path},
            status_code=404,
        )
    # A dict detail (e.g. the 429 quota body) is merged in: {"success": false, "error": ..., "limit": ...}
    body = {"success": False, **exc.detail} if isinstance(exc.detail, dict) else {"success": False, "error": exc.detail}
    return JSONResponse(content=body, status_code=exc.status_code, headers=getattr(exc, "headers", None))


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.warning(
        "validation_error",
        extra={"path": request.url.path, "errors": str(exc.errors())},
    )
    return JSONResponse(
        content={"success": False, "error": "Invalid request parameters", "details": exc.errors()},
        status_code=422,
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("unhandled_exception", extra={"path": request.url.path})
    return JSONResponse(
        content={"success": False, "error": "Internal server error"},
        status_code=500,
    )

# ── Middleware ────────────────────────────────────────────────────────────────

class DomainRedirectMiddleware(BaseHTTPMiddleware):
    """Redirect alias domains (cvss.help, cvss.info) to the primary domain."""

    async def dispatch(self, request: Request, call_next):
        host = request.headers.get("host", "").lower().split(":")[0]
        if host in DOMAIN_ALIASES:
            new_url = f"{SITE_URL}{request.url.path}"
            if request.url.query:
                new_url = f"{new_url}?{request.url.query}"
            return RedirectResponse(url=new_url, status_code=301)
        return await call_next(request)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log every HTTP request with method, path, status and duration."""

    async def dispatch(self, request: Request, call_next):
        request_id = str(uuid.uuid4())[:8]
        start = time.perf_counter()
        response = await call_next(request)
        duration_ms = round((time.perf_counter() - start) * 1000, 1)
        logger.info(
            "http_request",
            extra={
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": duration_ms,
                "request_id": request_id,
            },
        )
        return response


class HeadAsGetMiddleware:
    """Answer HEAD like GET without a body (FastAPI's @get routes return 405 to HEAD).

    Uptime monitors and some crawlers probe pages with HEAD.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] != "HEAD":
            await self.app(scope, receive, send)
            return

        async def send_without_body(message):
            if message["type"] == "http.response.body":
                if message.get("more_body", False):
                    return
                message = {"type": "http.response.body", "body": b"", "more_body": False}
            await send(message)

        await self.app({**scope, "method": "GET"}, receive, send_without_body)


app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(DomainRedirectMiddleware)
app.add_middleware(HeadAsGetMiddleware)

# ── Static files ──────────────────────────────────────────────────────────────

class CachedStaticFiles(StaticFiles):
    """StaticFiles subclass that adds a long-lived Cache-Control header.

    Safe because templates reference assets through static_url(), which appends
    a content hash (?v=...) that changes whenever the file changes.
    """

    async def get_response(self, path, scope):
        response = await super().get_response(path, scope)
        if isinstance(response, FileResponse):
            response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        return response


app.mount("/static", CachedStaticFiles(directory="app/static"), name="static")

# ── Routers ───────────────────────────────────────────────────────────────────

app.include_router(pages.router)
# Login, registration and profile need the database — not available in local mode.
if not LOCAL_MODE:
    app.include_router(auth.router)
app.include_router(htmx.router)
app.include_router(convert.router)
app.include_router(cve.router)
app.include_router(ai_scorer.router)
app.include_router(api_v1.router)

# ── Health check ──────────────────────────────────────────────────────────────

@app.get("/health", include_in_schema=False)
async def health_check():
    """Health check endpoint for container orchestration."""
    return JSONResponse(
        content={
            "status": "healthy",
            "version": app.version,
            "uptime_seconds": round(time.time() - APP_START_TIME, 1),
        }
    )


# ── OpenAPI customisation ─────────────────────────────────────────────────────

def _custom_openapi():
    """Inject securitySchemes and security requirements into the OpenAPI schema."""
    if app.openapi_schema:
        return app.openapi_schema

    from fastapi.openapi.utils import get_openapi

    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        tags=app.openapi_tags,
        routes=app.routes,
        servers=[{"url": SITE_URL, "description": "Production"}],
    )

    # Add API key security schemes
    schema.setdefault("components", {})
    schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "description": "Pass your API key as a Bearer token: `Authorization: Bearer <key>`",
        },
        "ApiKeyHeader": {
            "type": "apiKey",
            "in": "header",
            "name": "X-API-Key",
            "description": "Pass your API key in the X-API-Key header",
        },
    }

    # Apply security to all /api/v1/* paths
    for path, methods in schema.get("paths", {}).items():
        if path.startswith("/api/v1/"):
            for method_data in methods.values():
                method_data["security"] = [
                    {"BearerAuth": []},
                    {"ApiKeyHeader": []},
                ]

    app.openapi_schema = schema
    return schema


app.openapi = _custom_openapi


_RAPIDAPI_DESCRIPTION = (
    "Calculate, convert, and look up CVSS vulnerability scores (v2.0, v3.0, v3.1, v4.0) programmatically.\n\n"
    "- **Calculate** a score from individual metrics or from a vector string (version auto-detected)\n"
    "- **Convert** a vector between CVSS versions\n"
    "- **Look up** any CVE and get all its official NVD scores\n\n"
    "Authentication and quotas are handled by RapidAPI: just send your `X-RapidAPI-Key`.\n\n"
    "Errors always have the shape `{\"success\": false, \"error\": \"...\"}`.\n\n"
    "Full reference and interactive web tools: https://cvss.guru/api-reference"
)


def _to_openapi_30(node):
    """Downgrade the OpenAPI 3.1 constructs FastAPI emits to 3.0 (widest importer support).

    anyOf [X, null] -> X + nullable, schema ``examples: [..]`` -> ``example``, const -> enum.
    """
    if isinstance(node, list):
        return [_to_openapi_30(item) for item in node]
    if not isinstance(node, dict):
        return node
    node = {key: _to_openapi_30(value) for key, value in node.items()}
    variants = node.get("anyOf")
    if isinstance(variants, list) and {"type": "null"} in variants:
        rest = [v for v in variants if v != {"type": "null"}]
        del node["anyOf"]
        if len(rest) == 1:
            node = {**rest[0], **node}
        else:
            node["anyOf"] = rest
        node["nullable"] = True
    if isinstance(node.get("examples"), list):  # schema-level (media types use a dict)
        examples = node.pop("examples")
        if examples:
            node.setdefault("example", examples[0])
    if "const" in node:
        node["enum"] = [node.pop("const")]
    return node


@app.get("/openapi-rapidapi.json", include_in_schema=False)
async def openapi_rapidapi():
    """OpenAPI spec to import into RapidAPI Hub.

    Same endpoints and examples, but without the local API-key headers (the
    RapidAPI gateway authenticates) and without the free-quota wording, in
    OpenAPI 3.0.3 format.
    """
    import copy

    schema = copy.deepcopy(app.openapi())
    schema["info"]["description"] = _RAPIDAPI_DESCRIPTION
    schema.get("components", {}).pop("securitySchemes", None)
    for path in list(schema["paths"]):
        if not path.startswith("/api/v1/"):
            del schema["paths"][path]
            continue
        for operation in schema["paths"][path].values():
            operation.pop("security", None)
            responses = operation.get("responses", {})
            responses.pop("429", None)  # local API keys only: RapidAPI enforces its own plan quotas
            if "401" in responses:
                responses["401"]["description"] = "Request did not come through the RapidAPI gateway"
    schema = _to_openapi_30(schema)
    schema["openapi"] = "3.0.3"
    return JSONResponse(schema)


# ── Interactive API docs ──────────────────────────────────────────────────────

@app.get("/docs", include_in_schema=False)
async def swagger_ui():
    from fastapi.openapi.docs import get_swagger_ui_html

    from app.deps import static_url

    return get_swagger_ui_html(
        openapi_url="/openapi.json",
        title=f"{app.title} — Swagger UI",
        swagger_js_url=static_url("vendor/swagger/swagger-ui-bundle.js"),
        swagger_css_url=static_url("vendor/swagger/swagger-ui.css"),
        swagger_favicon_url=static_url("favicon.svg"),
    )


@app.get("/redoc", include_in_schema=False)
async def redoc_redirect():
    return RedirectResponse("/docs", status_code=301)


# ── OpenAPI export ────────────────────────────────────────────────────────────

@app.get("/openapi.yaml", include_in_schema=False)
async def openapi_yaml():
    """The OpenAPI schema as YAML."""
    import yaml

    return Response(
        content=yaml.dump(app.openapi(), allow_unicode=True, sort_keys=False),
        media_type="application/yaml",
    )
