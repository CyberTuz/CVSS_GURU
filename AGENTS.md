# CVSS Guru - Technical Documentation for AI Coders

## Project Overview
CVSS Guru is a web-based CVSS (Common Vulnerability Scoring System) calculator, converter, AI scorer, and CVE lookup tool supporting versions 2.0, 3.0, 3.1, and 4.0. It also exposes a public REST API.

## Architecture

### Tech Stack
- **Backend**: FastAPI (Python) + Jinja2 templates
- **Frontend**: HTMX (partial updates) + Tailwind CSS 3.4 (compiled to `app/static/css/app.css`) + vanilla JS
- **Styling**: Dark glassmorphism theme
- **Database**: PostgreSQL via async psycopg 3 pool (`app/db.py`: `await db_query(...)` / `await db_execute(...)`, `%s` placeholders) for users, hashed API keys, usage, password resets and shared rate limits; schema in `scripts/migrate.py`, applied automatically at startup. Calculations are in-memory; CVE data cached in-memory from NVD API. `LOCAL_MODE=true` runs without any database
- **Assets**: fonts, Phosphor icons, HTMX and highlight.js are self-hosted in `app/static/vendor/` (`npm run vendor`); the only third parties at runtime are Google Analytics (with consent) and reCAPTCHA
- **AI**: OpenRouter API (OpenAI-compatible) for AI Scorer feature
- **External APIs**: NVD API v2 (NIST) for CVE lookup

### Project Structure
```
CVSS_GURU/
├── main.py                 # App wiring: middleware, static files, routers, /health, OpenAPI + Swagger
├── run.py                  # Local dev server (uvicorn --reload)
├── scripts/
│   ├── migrate.py          # PostgreSQL schema migrations (applied automatically at startup)
│   ├── vendor_assets.js    # Copies fonts/icons/HTMX/highlight.js/Swagger into app/static/vendor
│   ├── build_brand_assets.py
│   └── ai_benchmark/       # AI Scorer model benchmark (dataset, runner, results)
├── tests/                  # pytest; test_reference_scores.py checks scores against the `cvss` library
└── app/
    ├── config.py           # All environment variables and constants
    ├── deps.py             # Shared calculators, Jinja templates, static_url(), client_ip()
    ├── db.py               # Async PostgreSQL pool (db_query / db_execute)
    ├── auth.py, csrf.py    # Sessions (JWT cookie), password hashing, API keys, CSRF tokens
    ├── usage.py, rate_limit.py, recaptcha.py, email.py
    ├── seo.py, docs_render.py, security_headers.py, ai_prompt.py, logging_config.py
    ├── routers/            # pages, auth, htmx (score panel), convert, cve, ai_scorer, api_v1
    ├── cvss_calculators/   # cvss2, cvss3 (v3.0, base of cvss31), cvss31, cvss4, descriptions
    ├── templates/          # Jinja pages, macros.html (metric cards), partials/
    ├── docs/cvss_guide.md  # Source of the Documentation page
    └── static/             # css/app.css (compiled Tailwind), vendor/, brand/, icons
```

## Navigation Structure

### Two-Tier Nav
- **Tier 1** (always visible): Calculator | Tools | API | Docs
- **Tier 2** (shown when Tools is active): Converter | AI Scorer | CVE Search

### Partials System
All pages use `{% include %}` for shared components:
```jinja2
{% include "partials/header.html" %}
{% set active_category = "tools" %}   {# "calculator" | "tools" | "api" | "docs" #}
{% set active_tool = "ai-scorer" %}   {# "converter" | "ai-scorer" | "cve-search" | None #}
{% include "partials/nav.html" %}
{% include "partials/footer.html" %}
```

`nav.html` handles: active state on tier-1 buttons, tools subnav visibility, and the `toggleToolsNav()` JS function.

### Color Scheme per Section
| Section | Accent color |
|---|---|
| Calculator | Cyan `#22d3ee` / `rgba(6,182,212)` |
| Tools (AI Scorer, CVE Search) | Red `#f87171` / `rgba(239,68,68)` |
| API | Indigo `#a5b4fc` / `rgba(99,102,241)` |
| Docs | Green `#4ade80` / `rgba(34,197,94)` |

Each page defines `.nav-category.active` and `.version-tab.active` with its own accent color. The `nav.html` partial picks up these CSS classes automatically.

## Key Components

### Calculators (`app/cvss_calculators/`)
Each calculator has a `calculate(metrics_dict)` method returning:
```python
{
    "base_score": float,
    "base_severity": str,          # "None" | "Low" | "Medium" | "High" | "Critical"
    "temporal_score": float|None,
    "temporal_severity": str|None,
    "environmental_score": float|None,
    "environmental_severity": str|None,
    "vector_string": str,
    "impact_subscore": float,
    "exploitability_subscore": float
}
```
**CVSS v4.0 note**: uses "Threat" instead of "Temporal"; `threat_score` is aliased to `temporal_score` for template compatibility.
Scores must match the FIRST specifications: `tests/test_reference_scores.py` compares every version with
the reference `cvss` library on random vectors (install `requirements-dev.txt`). Run it after any formula change.

### Routes (`app/routers/`)

#### Pages
| Route | Template | Notes |
|---|---|---|
| `GET /` | `index.html` | Supports `?calc=v31&vector=...` and `?tool=converter&from=...&vector=...` |
| `GET /ai-scorer` | `ai_scorer.html` | Passes `ai_configured` bool |
| `GET /cve-search` | `cve_search.html` | |
| `GET /api-reference` | `api_reference.html` | |
| `GET /documentation` | `documentation.html` | Guide rendered server-side by `app/docs_render.py` |
| `GET /privacy` | `privacy.html` | Privacy & cookie policy (noindex) |

#### HTMX Endpoints (form data, return HTML partials)
- `POST /api/cvss2/render`
- `POST /api/cvss3/render`
- `POST /api/cvss31/render`
- `POST /api/cvss4/render`
- `POST /api/convert`

Metric names are version-prefixed: `v2_AV`, `v31_AC`, `v4_VC`, etc.

#### Internal Feature Endpoints (JSON)
- `POST /api/ai-score` — calls OpenRouter, returns CVSS v3.1 score + metric reasoning
- `GET /api/cve/{cve_id}` — fetches from NVD API v2, caches result

#### Public REST API v1 (JSON)
Base: `/api/v1/`

| Method | Path | Body / Params |
|---|---|---|
| POST | `/calculate/2.0` | `V2MetricsBody` |
| POST | `/calculate/3.0` | `V30MetricsBody` |
| POST | `/calculate/3.1` | `V31MetricsBody` |
| POST | `/calculate/4.0` | `V40MetricsBody` |
| POST | `/calculate/vector` | `VectorBody { vector: str }` |
| POST | `/convert` | `ConvertBody { vector, to }` |
| GET | `/cve/{cve_id}` | — |

Calculate endpoints return `{ version, vector, scores: {base, temporal, environmental}, metrics }`
(`_fmt_score()`); convert returns `{ from, to }`. Errors: `{ "success": false, "error": ... }`.
- Logic lives in `_calculate`/`_calculate_vector`/`_convert` in `app/routers/api_v1.py`; the OpenAPI
  200 examples are generated by calling them, so keep examples and endpoints on the same code path.
- Auth: `check_usage_limit` depends on `require_api_key` (one lookup per request) and logs every call
  (`api_call`, with `channel` = `api_key` or `rapidapi`, RapidAPI user and plan).
- `/openapi-rapidapi.json` (main.py): spec for RapidAPI Hub — 3.0.3, no securitySchemes, no 429.

### AI Scorer (`/ai-scorer`)
- User describes a vulnerability in plain text
- Backend POSTs to OpenRouter with a system prompt that forces CVSS v3.1 JSON output
- Response includes: score, severity, vector, confidence, per-metric values + reasoning
- Config: `OPENROUTER_API_KEY`, `OPENROUTER_MODEL` in `.env`

### CVE Search (`/cve-search`)
- Fetches from NVD API v2: `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={id}`
- In-memory cache: `_CVE_CACHE` dict, TTL 24h (`_CVE_CACHE_TTL = 86400`), max 500 entries (FIFO eviction)
- Returns scores for all available versions (v2, v3.0, v3.1, v4.0)
- "Open in Calculator" → `/?calc=v31&vector=...`
- "Convert" → `/?tool=converter&from=V3.1&vector=...`

### Documentation Page (`/documentation`)
- `app/docs_render.py` renders `app/docs/cvss_guide.md` to HTML on the server (markdown-it-py), adding
  unique ids to h2/h3 headings; the template only builds the sidebar TOC and runs highlight.js.

### Accounts, API keys and limits
- Passwords: bcrypt, run in a thread (`asyncio.to_thread`) so they do not block the event loop.
- API keys: only `api_key_hash` (SHA-256) and `api_key_prefix` are stored; the full key is shown once
  when generated from the profile (`POST /api/user/regenerate-api-key`); `require_api_key` looks up by hash.
- Email verification: sign-up emails a link `GET /verify-email/{token}` (48 h, only the token's SHA-256 is
  stored in `email_verification_tokens`); `users.email_verified_at` → `user["email_verified"]`. Until confirmed
  the user cannot generate API keys or use the AI Scorer beyond the free analysis. Resend from the profile
  (`POST /api/user/resend-verification`). Unconfirmed accounts are purged after 7 days
  (`UNVERIFIED_ACCOUNT_TTL_DAYS`); a completed password reset also confirms the address.
- Emails (`app/email.py`, sent with `BackgroundTasks` or `asyncio.to_thread`, layout `email_layout()`):
  verification, password reset, account-deleted confirmation (only to confirmed addresses).
  Port 465 = implicit TLS, otherwise `SMTP_USE_TLS` = STARTTLS.
- reCAPTCHA v3 (`app/recaptcha.py`): AI Scorer (fails closed without keys) and the login, sign-up and
  forgot-password forms (`data-recaptcha-action` + `partials/recaptcha_form.html`; skipped without keys).
- Rate limits (`app/rate_limit.py`): login/forgot password 5 per 5 min per IP, failed logins 10 per 15 min
  per username, sign-ups 3 per 30 min (only successful ones count), verification emails 3 per hour per user,
  AI Scorer 10 per hour — stored in `rate_limit_hits`, shared by all workers.
- Footer links (GitHub repo, Ko-fi donations) come from `GITHUB_URL` / `DONATE_URL` in `app/config.py`.
- `/privacy` documents what is collected: keep it in sync with the code and bump `PRIVACY_POLICY_UPDATED`
  in `app/routers/pages.py`. AI Scorer queries are purged after 90 days.
- Tests never use the `.env` database (`tests/conftest.py`); set `TEST_DATABASE_URL` for a real one.

## Environment Variables (`.env`)
```bash
SITE_URL=https://cvss.guru
DATABASE_URL=postgresql://cvss_guru:<password>@<host>:5432/cvss_guru   # SQL uses %s placeholders
JWT_SECRET=                         # required in production (sessions + CSRF)
LOCAL_MODE=false                    # true = no DB, no login, no CAPTCHA (never on a public server)
PRIVACY_CONTROLLER=CVSS Guru                # data controller shown on /privacy
CONTACT_EMAIL=info@cvss.guru
OPENROUTER_API_KEY=sk-or-v1-...
OPENROUTER_MODEL=openai/gpt-6-luna
OPENROUTER_REASONING_EFFORT=        # optional: minimal|low|medium|high
NVD_API_KEY=                        # optional, increases NVD rate limit
GA_MEASUREMENT_ID=                  # Google Analytics 4 (G-XXXXXXXXXX), consent-gated
RECAPTCHA_SITE_KEY=                 # Google reCAPTCHA v3: AI Scorer + login/sign-up/forgot password
RECAPTCHA_SECRET_KEY=
SMTP_HOST= SMTP_PORT=465 SMTP_USER= SMTP_PASSWORD= SMTP_FROM=   # service emails
```
`load_dotenv()` is called at startup in `main.py`.

## URL Parameters

### Calculator share link
```
/?calc=v31&vector=CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

### Open converter with pre-filled vector
```
/?tool=converter&from=V3.1&vector=CVSS:3.1/AV:N/AC:L/...
```

## Field Naming Conventions

### Frontend → HTMX Backend
- v2.0: `v2_AV`, `v2_AC`, `v2_Au`, ...
- v3.0: `v3_AV`, `v3_AC`, ...
- v3.1: `v31_AV`, `v31_AC`, ...
- v4.0: `v4_AV`, `v4_VC`, `v4_SC`, ...

### Metric cards and plain-language help
- All four versions render metrics with one macro, `_metric_card` in `macros.html` (the
  `render_metric_v2/v3/v31/v4` wrappers only choose the default value).
- Texts live in `app/cvss_calculators/descriptions.py`: per metric `question` (shown under the title),
  `description` (help dialog) and per value `desc` (shown under the options for the selected value,
  kept in sync by `refreshExplanation()` in `index.html`). Write them for non-specialists.
- "Show explanations" switch (`#explain-toggle`, `body.explain-off`, localStorage `cvss_explanations`).
- `score` = formula weight, shown for v2.0/v3.x only; v4.0 values have none (lookup-table scoring).
- "Modified" metrics reuse the base descriptions; the macro adds their "Not Defined (X)" option.
- v4.0 base SC/SI/SA are N/L/H only; "S" (Safety) exists only for MSI/MSA.

### CVSS v4.0 Special Metrics
- `VC/VI/VA`: Vulnerable System Impact
- `SC/SI/SA`: Subsequent System Impact
- `AT`: Attack Requirements (replaces AC in v3.x)

## Styling Guide

### Colors
- Background: `#0a0f1a` → `#0d1525`
- Glass card: `rgba(15,23,42,0.6)` + `backdrop-filter: blur(12px)`
- Score severity: None `#64748b` | Low `#22c55e` | Medium `#eab308` | High `#f97316` | Critical `#ef4444`

### Key CSS Classes
- `.glass-card`: Glassmorphism panel
- `.nav-category`: Tier-1 nav button
- `.version-tab`: Tier-2 sub-tab or version tab
- `.cat-icon`: 28px icon inside nav button
- `.sidebar`: `position: sticky; top: 24px` with scrollbar
- `.endpoint-card`: API reference section with `scroll-margin-top: 80px`

### Grid Layout Fix
API Reference and Documentation both use `grid lg:grid-cols-[Xpx_1fr]`. The main content div **must have `min-w-0`** to prevent `pre` blocks from expanding the column beyond `1fr`.

### Tailwind CSS build
Tailwind is compiled, not loaded from a CDN. After adding or changing Tailwind classes in
templates (or in HTML strings inside Python files), rebuild and commit the CSS:
```bash
npm install          # once
npm run build:css    # or: npm run watch:css while developing
```
- Config: `tailwind.config.js` (zinc/neutral/amber/red/green mapped to the theme CSS variables),
  entry `assets/tailwind.css`, output `app/static/css/app.css` (committed, served via `static_url`).
- Write class names in full (`bg-red-500`, not `bg-${color}-500`): the build only sees literal names.
- `static_url()` appends a content hash (`?v=`), so static files can be cached for a year.

## Common Issues & Fixes

| Issue | Cause | Fix |
|---|---|---|
| AI scoring disabled | `OPENROUTER_API_KEY` empty | Set key in `.env` |
| API grid overflow | `1fr` column has `min-width: auto` | Add `min-w-0` to content div |
| v4.0 score shows `--` | Missing `impact_subscore` | Ensure calculator returns it |
| Converter pre-selected | HTML had `active` hardcoded | Active class set only by JS |

## Adding New Pages

1. Create `app/templates/yourpage.html`
2. Add `{% include "partials/header.html" %}`, set `active_category`/`active_tool`, include `partials/nav.html` and `partials/footer.html`
3. Define `.nav-category.active` and `.version-tab.active` CSS with the right accent color
4. Add the route in `app/routers/pages.py` (and the page to `app/seo.py` if it should be indexed)
5. Add link in `partials/nav.html` if it's a new top-level or tools sub-page

## SEO & Analytics

- `app/seo.py` is the registry of public pages (title, description, schema type, sitemap data).
  A page opts in with `{% set seo = seo_page("<key>") %}` before including `partials/theme_head.html`;
  pages without it (login, profile, reset, 404) get `noindex`.
- `partials/seo.html` renders title, description, canonical, Open Graph/Twitter and a JSON-LD
  `@graph` (Organization, WebSite, WebPage, WebApplication/TechArticle/WebAPI, BreadcrumbList).
- `/robots.txt`, `/sitemap.xml`, `/llms.txt` and `/llms-full.txt` are generated in `app/routers/pages.py`.
- The CVSS guide is rendered server-side (`app/docs_render.py`, markdown-it-py) so crawlers see the text.
- Canonical host is `SITE_URL` (cvss.guru); `www.cvss.guru`, `cvss.help`, `cvss.info` 301-redirect
  there (`DOMAIN_ALIASES`, `DomainRedirectMiddleware`).
- Google Analytics 4 with Consent Mode v2 (`partials/analytics.html`, banner in the footer).
  Page scripts call `track(event, params)`; events: `version_switch`, `score_calculated`,
  `share_link_generated`, `converter_used`, `metric_changed`, `explanations_toggle`, `ai_score_*`, `cve_search_*`.
