"""
Generate CVSS Guru brand assets (logo, icons, social images).

The logo mark is a CVSS score gauge: five arc segments in the severity colors
(None, Low, Medium, High, Critical) with a needle pointing at Critical.

Outputs:
  app/static/favicon.svg                  browser tab (simplified 3-segment mark)
  app/static/apple-touch-icon.png         180x180, iOS home screen
  app/static/og-image.png                 1200x630, Open Graph / Twitter card
  app/static/site.webmanifest             Android / PWA install metadata
  app/static/brand/logo-dark.svg          horizontal logo for dark backgrounds
  app/static/brand/logo-light.svg         horizontal logo for light backgrounds
  app/static/brand/logo-stacked-dark.svg  stacked logo (square-ish spaces)
  app/static/brand/logo-stacked-light.svg
  app/static/brand/icon.svg               app icon, rounded tile
  app/static/brand/icon-192.png           manifest icon
  app/static/brand/icon-512.png           manifest icon, avatars (GitHub, socials)
  app/static/brand/favicon-32.png         PNG fallback favicon
  app/static/favicon.ico                  16/32/48 px ICO, served at /favicon.ico
  app/static/brand/social-preview.png     1280x640, GitHub repository social preview
  app/templates/partials/logo.html        inline header logo (theme-aware colors)

PNG files are rendered with a headless Chrome/Edge so the web fonts (Inter and
Cormorant Garamond, loaded from Google Fonts) match the site exactly.

Usage:
    python scripts/build_brand_assets.py
"""

import json
import math
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "app" / "static"
BRAND = STATIC / "brand"

SEVERITY = ["#64748b", "#22c55e", "#eab308", "#f97316", "#ef4444"]  # None → Critical
INK_DARK_BG = "#e6e7ed"
INK_LIGHT_BG = "#111117"
BRAND_DARK_BG = "#f59e0b"
BRAND_LIGHT_BG = "#d97706"
SUB_DARK_BG = "#8a8c9b"
SUB_LIGHT_BG = "#5f6170"
TILE = "#151621"
PAGE_DARK = "#0a0b10"

FONTS_CSS = (
    "https://fonts.googleapis.com/css2?family=Inter:wght@600;700;800"
    "&family=Cormorant+Garamond:ital,wght@1,600&display=swap"
)
SANS = "Inter, 'Segoe UI', system-ui, sans-serif"
SERIF = "'Cormorant Garamond', Georgia, serif"
TAGLINE = "CVSS 2.0 · 3.x · 4.0 CALCULATOR"


# ── Geometry ──────────────────────────────────────────────────────────────────

def _pt(cx: float, cy: float, r: float, deg: float) -> tuple[float, float]:
    a = math.radians(deg)
    return cx + r * math.cos(a), cy - r * math.sin(a)


def mark(cx, cy, r, sw, ink, *, gap=3.2, score=9.3, simple=False, colors=None) -> str:
    """SVG elements for the gauge mark centered on (cx, cy)."""
    colors = colors or SEVERITY
    if simple:
        # Three fatter segments read better at favicon sizes
        segs = [(180, 108, colors[1]), (108, 36, colors[3]), (36, 0, colors[4])]
    else:
        segs = [(180 - i * 36, 180 - (i + 1) * 36, colors[i]) for i in range(5)]

    out = []
    for a0, a1, col in segs:
        s0 = a0 - gap / 2 if a0 < 180 else a0
        s1 = a1 + gap / 2 if a1 > 0 else a1
        x0, y0 = _pt(cx, cy, r, s0)
        x1, y1 = _pt(cx, cy, r, s1)
        out.append(
            f'<path d="M{x0:.2f} {y0:.2f} A{r} {r} 0 0 1 {x1:.2f} {y1:.2f}" '
            f'stroke="{col}" stroke-width="{sw}" fill="none"/>'
        )

    ang = 180 - score / 10 * 180
    tip = _pt(cx, cy, r - sw * 0.15, ang)
    b1 = _pt(cx, cy, sw * 0.55, ang + 90)
    b2 = _pt(cx, cy, sw * 0.55, ang - 90)
    out.append(
        f'<path d="M{b1[0]:.2f} {b1[1]:.2f} L{tip[0]:.2f} {tip[1]:.2f} L{b2[0]:.2f} {b2[1]:.2f} Z" '
        f'fill="{ink}" stroke="{ink}" stroke-width="{sw * 0.12:.2f}" stroke-linejoin="round"/>'
    )
    out.append(f'<circle cx="{cx}" cy="{cy}" r="{sw * 0.6:.2f}" fill="{ink}"/>')
    return "\n  ".join(out)


def wordmark(x, y, size, ink, brand, anchor="start") -> str:
    return (
        f'<text x="{x}" y="{y}" text-anchor="{anchor}" font-family="{SANS}" font-size="{size}" '
        f'font-weight="800" letter-spacing="{-size / 30:.2f}" fill="{ink}">cvss'
        f'<tspan fill="{brand}" font-family="{SERIF}" font-style="italic" font-weight="600" '
        f'font-size="{size * 1.095:.1f}" letter-spacing="0">.guru</tspan></text>'
    )


# ── SVG documents ─────────────────────────────────────────────────────────────

def logo_horizontal(ink, brand, sub) -> str:
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 360 100" role="img" aria-label="CVSS Guru">
  <title>CVSS Guru</title>
  {mark(50, 68, 36, 12, ink)}
  {wordmark(106, 62, 42, ink, brand)}
  <text x="108" y="83" font-family="{SANS}" font-size="10" font-weight="700" letter-spacing="2.2" fill="{sub}">{TAGLINE}</text>
</svg>
'''


def logo_stacked(ink, brand) -> str:
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 220 130" role="img" aria-label="CVSS Guru">
  <title>CVSS Guru</title>
  {mark(110, 56, 36, 12, ink)}
  {wordmark(110, 112, 40, ink, brand, anchor="middle")}
</svg>
'''


def icon(*, rounded=True, simple=False, size=64) -> str:
    """Square app icon. Full-bleed variants (rounded=False) keep the mark inside the
    central safe zone, because iOS, Android masks and avatar circles crop the edges."""
    if rounded:
        rx, m = 14, mark(32, 44, 24, 11 if simple else 9, INK_DARK_BG, gap=5 if simple else 3.5, simple=simple)
    else:
        rx, m = 0, mark(32, 40, 18, 7, INK_DARK_BG, gap=3.5, simple=simple)
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="{size}" height="{size}">
  <rect width="64" height="64" rx="{rx}" fill="{TILE}"/>
  {m}
</svg>
'''


def social_card(width, height) -> str:
    """Open Graph / repository preview: logo, tagline and a severity scale."""
    scale = height / 630
    bar_w = width * 0.62
    bar_x = (width - bar_w) / 2
    seg_w = bar_w / 5
    bars = "".join(
        f'<rect x="{bar_x + i * seg_w + 3:.1f}" y="{height - 118 * scale:.1f}" width="{seg_w - 6:.1f}" '
        f'height="{10 * scale:.1f}" rx="{5 * scale:.1f}" fill="{c}"/>'
        for i, c in enumerate(SEVERITY)
    )
    labels = "".join(
        f'<text x="{bar_x + (i + 0.5) * seg_w:.1f}" y="{height - 84 * scale:.1f}" text-anchor="middle" '
        f'font-family="{SANS}" font-size="{17 * scale:.1f}" font-weight="600" fill="{SUB_DARK_BG}">{n}</text>'
        for i, n in enumerate(["None", "Low", "Medium", "High", "Critical"])
    )
    cx = width / 2
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}">
  <defs>
    <radialGradient id="g1" cx="50%" cy="0%" r="70%"><stop offset="0" stop-color="{BRAND_DARK_BG}" stop-opacity="0.16"/><stop offset="1" stop-color="{BRAND_DARK_BG}" stop-opacity="0"/></radialGradient>
    <radialGradient id="g2" cx="100%" cy="0%" r="60%"><stop offset="0" stop-color="#6366f1" stop-opacity="0.14"/><stop offset="1" stop-color="#6366f1" stop-opacity="0"/></radialGradient>
  </defs>
  <rect width="{width}" height="{height}" fill="{PAGE_DARK}"/>
  <rect width="{width}" height="{height}" fill="url(#g1)"/>
  <rect width="{width}" height="{height}" fill="url(#g2)"/>
  <g transform="translate({cx - 330 * scale:.1f} {150 * scale:.1f}) scale({1.85 * scale:.3f})">
    {mark(50, 68, 36, 12, INK_DARK_BG)}
    {wordmark(106, 62, 42, INK_DARK_BG, BRAND_DARK_BG)}
  </g>
  <text x="{cx}" y="{height - 250 * scale:.1f}" text-anchor="middle" font-family="{SANS}" font-size="{36 * scale:.1f}" font-weight="700" fill="{INK_DARK_BG}">Free CVSS calculator, converter &amp; CVE lookup</text>
  <text x="{cx}" y="{height - 200 * scale:.1f}" text-anchor="middle" font-family="{SANS}" font-size="{22 * scale:.1f}" font-weight="600" letter-spacing="{4 * scale:.1f}" fill="{SUB_DARK_BG}">CVSS 2.0 · 3.0 · 3.1 · 4.0</text>
  {bars}
  {labels}
</svg>
'''


def header_partial() -> str:
    """Inline logo for the site header. Colors come from the theme tokens so the
    logo follows light/dark mode; the tagline is dropped on small screens."""
    ink = "currentColor"
    brand = "rgb(var(--brand))"
    word = wordmark(106, 62, 42, ink, "BRAND")
    word = word.replace('fill="BRAND"', f'style="fill:{brand}"')
    m = mark(50, 68, 36, 12, ink)
    return f'''{{# Generated by scripts/build_brand_assets.py — edit the script, not this file. #}}
<a href="/" class="site-logo" aria-label="CVSS Guru — home">
    <svg class="hidden sm:block" width="300" height="83" viewBox="0 0 360 100" aria-hidden="true">
  {m}
  {word}
  <text x="108" y="83" font-family="{SANS}" font-size="10" font-weight="700" letter-spacing="2.2" style="fill:rgb(var(--zinc-500))">{TAGLINE}</text>
    </svg>
    <svg class="sm:hidden" width="210" height="36" viewBox="0 22 340 58" aria-hidden="true">
  {m}
  {word}
    </svg>
</a>
'''


# ── PNG rendering ─────────────────────────────────────────────────────────────

def find_browser() -> str:
    candidates = [
        os.environ.get("CHROME_PATH", ""),
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        shutil.which("google-chrome") or "",
        shutil.which("chromium") or "",
        shutil.which("chromium-browser") or "",
    ]
    for c in candidates:
        if c and Path(c).exists():
            return c
    sys.exit("Chrome/Edge not found. Set CHROME_PATH to a Chromium-based browser.")


def render_png(browser: str, svg: str, width: int, height: int, out: Path) -> None:
    html = (
        f'<!doctype html><html><head><link href="{FONTS_CSS}" rel="stylesheet">'
        f"<style>html,body{{margin:0;background:transparent}}svg{{display:block}}</style>"
        f"</head><body>{svg}</body></html>"
    )
    with tempfile.TemporaryDirectory() as tmp:
        page = Path(tmp) / "render.html"
        page.write_text(html, encoding="utf-8")
        subprocess.run(
            [
                browser, "--headless=new", "--disable-gpu", "--hide-scrollbars",
                "--force-device-scale-factor=1", "--default-background-color=00000000",
                "--virtual-time-budget=8000", f"--window-size={width},{height}",
                f"--screenshot={out}", page.as_uri(),
            ],
            check=True, capture_output=True, timeout=120,
        )


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    BRAND.mkdir(parents=True, exist_ok=True)

    svgs = {
        STATIC / "favicon.svg": icon(simple=True),
        BRAND / "logo-dark.svg": logo_horizontal(INK_DARK_BG, BRAND_DARK_BG, SUB_DARK_BG),
        BRAND / "logo-light.svg": logo_horizontal(INK_LIGHT_BG, BRAND_LIGHT_BG, SUB_LIGHT_BG),
        BRAND / "logo-stacked-dark.svg": logo_stacked(INK_DARK_BG, BRAND_DARK_BG),
        BRAND / "logo-stacked-light.svg": logo_stacked(INK_LIGHT_BG, BRAND_LIGHT_BG),
        BRAND / "icon.svg": icon(),
    }
    svgs[ROOT / "app" / "templates" / "partials" / "logo.html"] = header_partial()
    for path, content in svgs.items():
        path.write_text(content, encoding="utf-8")
        print(f"  wrote {path.relative_to(ROOT)}")

    manifest = {
        "name": "CVSS Guru",
        "short_name": "CVSS Guru",
        "description": "CVSS calculator, converter and CVE lookup for v2.0, v3.0, v3.1 and v4.0",
        "start_url": "/",
        "display": "standalone",
        "background_color": PAGE_DARK,
        "theme_color": PAGE_DARK,
        "icons": [
            {"src": "/static/brand/icon-192.png", "sizes": "192x192", "type": "image/png"},
            {"src": "/static/brand/icon-512.png", "sizes": "512x512", "type": "image/png"},
        ],
    }
    (STATIC / "site.webmanifest").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print("  wrote app/static/site.webmanifest")

    browser = find_browser()
    # Square icons are full-bleed: iOS, Android and avatar crops apply their own rounding.
    pngs = [
        (icon(rounded=False, size=180), 180, 180, STATIC / "apple-touch-icon.png"),
        (icon(rounded=False, size=192), 192, 192, BRAND / "icon-192.png"),
        (icon(rounded=False, size=512), 512, 512, BRAND / "icon-512.png"),
        (icon(simple=True, size=32), 32, 32, BRAND / "favicon-32.png"),
        (social_card(1200, 630), 1200, 630, STATIC / "og-image.png"),
        (social_card(1280, 640), 1280, 640, BRAND / "social-preview.png"),
    ]
    for svg, w, h, out in pngs:
        render_png(browser, svg, w, h, out)
        print(f"  rendered {out.relative_to(ROOT)} ({w}x{h})")

    # Multi-size ICO from a large render of the simplified mark (needs Pillow)
    from PIL import Image

    with tempfile.TemporaryDirectory() as tmp:
        big = Path(tmp) / "favicon-256.png"
        render_png(browser, icon(simple=True, size=256), 256, 256, big)
        Image.open(big).save(STATIC / "favicon.ico", sizes=[(16, 16), (32, 32), (48, 48)])
    print("  rendered app/static/favicon.ico (16, 32, 48)")


if __name__ == "__main__":
    main()
