"""
CVE lookup router.

GET /api/cve/{cve_id}   — fetches from NVD API v2 with in-memory cache
"""

import re
import time
from typing import Any, Dict

import httpx
from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.config import NVD_API_KEY, NVD_API_URL

router = APIRouter()

# ── In-memory CVE cache ───────────────────────────────────────────────────────

_CVE_CACHE: Dict[str, Any] = {}
_CVE_CACHE_TTL = 86_400   # 24 hours
_CVE_CACHE_MAX = 500       # FIFO eviction when full

_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


# ── Route ─────────────────────────────────────────────────────────────────────

@router.get("/api/cve/{cve_id}", response_class=JSONResponse, include_in_schema=False)
async def api_cve_lookup(cve_id: str):
    """Fetch CVE data from NVD with in-memory cache."""
    cve_id = cve_id.upper().strip()

    if not _CVE_ID_RE.match(cve_id):
        return JSONResponse(
            status_code=422,
            content={"success": False, "error": "Invalid CVE ID format. Expected CVE-YYYY-NNNNN."},
        )

    # Cache hit
    cached = _CVE_CACHE.get(cve_id)
    if cached and (time.time() - cached["ts"]) < _CVE_CACHE_TTL:
        return JSONResponse(content={"success": True, "cached": True, **cached["data"]})

    # Fetch from NVD
    headers: Dict[str, str] = {"Accept": "application/json"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(NVD_API_URL, params={"cveId": cve_id}, headers=headers)
            resp.raise_for_status()
    except httpx.TimeoutException:
        return JSONResponse(
            status_code=504,
            content={"success": False, "error": "NVD API timed out. Please try again."},
        )
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            return JSONResponse(
                status_code=404,
                content={"success": False, "error": f"{cve_id} not found in NVD."},
            )
        return JSONResponse(
            status_code=502,
            content={"success": False, "error": "NVD API returned an error. Please try again."},
        )

    raw = resp.json()
    vulns = raw.get("vulnerabilities", [])
    if not vulns:
        return JSONResponse(
            status_code=404,
            content={"success": False, "error": f"{cve_id} not found in NVD."},
        )

    cve = vulns[0]["cve"]
    nvd_metrics = cve.get("metrics", {})

    def _extract_metric(key: str):
        entries = nvd_metrics.get(key, [])
        if not entries:
            return None
        m = entries[0]
        d = m.get("cvssData", {})
        return {
            "version": d.get("version"),
            "vector": d.get("vectorString"),
            "score": d.get("baseScore"),
            "severity": m.get("baseSeverity") or d.get("baseSeverity"),
            "source": m.get("source", ""),
            "type": m.get("type", ""),
        }

    en_desc = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        "No description available.",
    )

    data: Dict[str, Any] = {
        "id": cve["id"],
        "published": cve.get("published", "")[:10],
        "modified": cve.get("lastModified", "")[:10],
        "description": en_desc,
        "scores": {
            "v2": _extract_metric("cvssMetricV2"),
            "v30": _extract_metric("cvssMetricV30"),
            "v31": _extract_metric("cvssMetricV31"),
            "v40": _extract_metric("cvssMetricV40"),
        },
        "references": [r["url"] for r in cve.get("references", [])[:5]],
        "weaknesses": [
            w["description"][0]["value"]
            for w in cve.get("weaknesses", [])
            if w.get("description")
        ][:3],
    }

    # Store in cache (FIFO eviction)
    if len(_CVE_CACHE) >= _CVE_CACHE_MAX:
        del _CVE_CACHE[next(iter(_CVE_CACHE))]
    _CVE_CACHE[cve_id] = {"data": data, "ts": time.time()}

    return JSONResponse(content={"success": True, "cached": False, **data})
