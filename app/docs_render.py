"""
Server-side rendering of the CVSS guide (app/docs/cvss_guide.md).

Rendering on the server means search engines and AI crawlers (which often do not
run JavaScript) see the full guide. Headings h2/h3 get unique, stable ids so the
sidebar TOC and external links (#base-metrics-2) work.
"""

import os
import re
from functools import lru_cache

from markdown_it import MarkdownIt

GUIDE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "docs", "cvss_guide.md")

_md = MarkdownIt("commonmark", {"html": False}).enable(["table", "strikethrough"])


def slugify(text: str) -> str:
    slug = re.sub(r"[^\w\s-]", "", text.lower())
    slug = re.sub(r"\s+", "-", slug.strip())
    return re.sub(r"-+", "-", slug)


def read_guide() -> str:
    with open(GUIDE_PATH, encoding="utf-8") as f:
        return f.read()


@lru_cache(maxsize=4)
def _render(mtime: float) -> str:
    tokens = _md.parse(read_guide())
    seen: dict[str, int] = {}
    for i, tok in enumerate(tokens):
        if tok.type == "heading_open" and tok.tag in ("h2", "h3"):
            base = slugify(tokens[i + 1].content) or "section"
            seen[base] = seen.get(base, 0) + 1
            tok.attrSet("id", base if seen[base] == 1 else f"{base}-{seen[base]}")
    return _md.renderer.render(tokens, _md.options, {})


def guide_html() -> str:
    """Rendered guide HTML, re-rendered only when the Markdown file changes."""
    return _render(os.path.getmtime(GUIDE_PATH))
