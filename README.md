<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="app/static/brand/logo-dark.svg">
    <img src="app/static/brand/logo-light.svg" alt="CVSS Guru" width="360">
  </picture>
</p>

# CVSS Guru

CVSS Guru is a free web tool for working with the Common Vulnerability Scoring System.
It runs at [cvss.guru](https://cvss.guru) and you can also host it yourself.

What it does:

- **Calculator** for CVSS v2.0, v3.0, v3.1 and v4.0. The score updates as you pick the
  metrics, and every metric comes with a short plain-English explanation, so you don't need
  to know the specification by heart.
- **Converter** between versions. Metrics don't map one-to-one, so treat the result as a
  starting point, not a final answer.
- **CVE Search**: type a CVE ID and see its official NVD scores for every version, then open
  them in the calculator.
- **AI Scorer**: describe a vulnerability in your own words and get a suggested CVSS v3.1
  vector, with a reason for each metric.
- **CVSS guide** that explains every metric with real examples.
- **REST API** to calculate, convert and look up scores from your own scripts.

Scores follow the FIRST specifications. The test suite checks all four calculators against
the reference [`cvss`](https://github.com/RedHatProductSecurity/cvss) library on thousands
of random vectors, so a formula change that breaks a score gets caught.

## Running it locally

You need Python 3.11 or newer.

```bash
pip install -r requirements.txt
echo LOCAL_MODE=true > .env
python run.py
```

Then open http://localhost:8000.

With `LOCAL_MODE=true` there is no database, no accounts and no CAPTCHA: everything works
for you alone, and the REST API needs no key. To use the AI Scorer, add an
[OpenRouter](https://openrouter.ai) key to `.env`:

```bash
OPENROUTER_API_KEY=sk-or-v1-...
```

Never turn on local mode on a public server.

## Running it in production

The public version adds user accounts (for API keys), shared rate limits and anti-bot
checks. For that you need:

- **PostgreSQL**, with a dedicated database and the `citext` extension:

  ```sql
  CREATE ROLE cvss_guru LOGIN PASSWORD '<strong-password>';
  CREATE DATABASE cvss_guru OWNER cvss_guru;
  \c cvss_guru
  CREATE EXTENSION citext;   -- needs a superuser
  ```

  The app creates and upgrades its tables by itself at startup. To see which migrations
  have been applied, run `python scripts/migrate.py --status`.
- **`JWT_SECRET`**, a random value used to sign sessions (`openssl rand -hex 32`).
- **An SMTP account** for the verification, password reset and account deletion emails.
- **Google reCAPTCHA v3 keys** for the AI Scorer and the sign-in and sign-up forms.

All settings are described in [.env.example](.env.example). The included `Dockerfile` runs
the app with gunicorn on port 5000, and `/health` answers for health checks.

## Development

```bash
pip install -r requirements-dev.txt
python -m pytest
python -m pyflakes app main.py tests
```

The tests never touch the database configured in `.env`. To run the few tests that need a
real PostgreSQL, set `TEST_DATABASE_URL`.

### Front-end

The pages are server-rendered Jinja templates, with HTMX for the live score panel and a
little plain JavaScript. The styles use Tailwind CSS. The browser loads nothing from
public CDNs: fonts, icons and libraries are served by the app itself.

The compiled CSS and the vendored files are committed, so you only need Node.js when you
change them:

```bash
npm install
npm run build:css    # after changing Tailwind classes (npm run watch:css while working)
npm run vendor       # to update fonts, icons, HTMX, highlight.js or Swagger UI
```

### Project layout

```
main.py                  app setup: middleware, routers, health check, OpenAPI
app/routers/             pages, accounts, calculator partials, converter, CVE, AI Scorer, API v1
app/cvss_calculators/    the four calculators and the metric descriptions
app/templates/           Jinja pages and partials
app/docs/cvss_guide.md   source of the guide page
scripts/migrate.py       database migrations
scripts/ai_benchmark/    AI Scorer benchmark
tests/
```

[AGENTS.md](AGENTS.md) has a more detailed technical map. It's written for AI coding
assistants but it's just as useful for people.

## REST API

Full reference: [cvss.guru/api-reference](https://cvss.guru/api-reference). There is also
interactive documentation at `/docs` and an OpenAPI spec at `/openapi.json`.

```
POST /api/v1/calculate/{2.0|3.0|3.1|4.0}   score from individual metrics
POST /api/v1/calculate/vector              score from a vector string (version auto-detected)
POST /api/v1/convert                       convert a vector to another version
GET  /api/v1/cve/{cve_id}                  CVE details and all its NVD scores
```

```bash
curl -X POST https://cvss.guru/api/v1/calculate/vector \
  -H "X-API-Key: YOUR_API_KEY" -H "Content-Type: application/json" \
  -d '{"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}'
```

You get an API key for free from your profile page, once your email address is confirmed.
It includes 100 calls a month. For more, the same API is available on RapidAPI, which
handles plans and billing. For that setup, `/openapi-rapidapi.json` is the spec to import
into RapidAPI Hub, and `RAPIDAPI_PROXY_SECRET` lets its requests through.

## AI Scorer

The prompt lives in [app/ai_prompt.py](app/ai_prompt.py). It gives the model explicit
CVSS v3.1 decision rules and asks it to reason before choosing values. When a detail is
missing, it assumes the "reasonable worst case", as NVD analysts do. The user's text is sent
as separate data, so any instructions hidden in it are ignored.

On 30 CVEs scored by NVD that were not used to write the prompt, about 81–83% of the metrics
match NVD, and the base score is off by 1.2–1.4 points on average. It's a helpful first
draft, not a replacement for an analyst.

As of September 2026 the recommended model is `openai/gpt-6-luna`. It takes about 5 seconds
and costs around $0.35 per 1000 analyses. For zero cost, for example in local mode, use
`nvidia/nemotron-3-super-120b-a12b:free` with `OPENROUTER_REASONING_EFFORT=low`. The
methodology and the full comparison are in
[scripts/ai_benchmark/README.md](scripts/ai_benchmark/README.md).

## References

- CVSS specifications: [v2.0](https://www.first.org/cvss/v2/guide),
  [v3.0](https://www.first.org/cvss/v3.0/specification-document),
  [v3.1](https://www.first.org/cvss/v3.1/specification-document),
  [v4.0](https://www.first.org/cvss/v4.0/specification-document)
- [FIRST CVSS](https://www.first.org/cvss/). CVSS is owned by FIRST.Org, Inc. and freely
  licensed for public use.

## Supporting the project

CVSS Guru is free and has no ads. If it saves you time, you can
[buy me a coffee on Ko-fi](https://ko-fi.com/cybertuz). Bug reports and pull requests are
welcome too.

## License

[MIT](LICENSE).
