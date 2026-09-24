"""
HTMX partial-render endpoints.
Each endpoint receives the calculator form, runs the calculator, and returns an
HTML fragment (partials/score_result.html) that HTMX swaps into the page.

POST /api/cvss2/render
POST /api/cvss3/render
POST /api/cvss31/render
POST /api/cvss4/render
"""

from typing import Dict

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from app.deps import cvss2_calc, cvss3_calc, cvss31_calc, cvss4_calc, templates
from app.logging_config import get_logger

router = APIRouter()
logger = get_logger("routers.htmx")

# Every metric of each version with the value used when the form doesn't send it
_V3_DEFAULTS = {
    "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "N", "I": "N", "A": "N",
    "E": "X", "RL": "X", "RC": "X", "CR": "X", "IR": "X", "AR": "X",
    "MAV": "X", "MAC": "X", "MPR": "X", "MUI": "X", "MS": "X", "MC": "X", "MI": "X", "MA": "X",
}
_DEFAULTS: Dict[str, Dict[str, str]] = {
    "v2": {
        "AV": "N", "AC": "L", "Au": "N", "C": "N", "I": "N", "A": "N",
        "E": "ND", "RL": "ND", "RC": "ND", "CDP": "ND", "TD": "ND", "CR": "ND", "IR": "ND", "AR": "ND",
    },
    "v3": _V3_DEFAULTS,
    "v31": _V3_DEFAULTS,
    "v4": {
        "AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
        "VC": "N", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N",
        "E": "X", "CR": "X", "IR": "X", "AR": "X",
        "MAV": "X", "MAC": "X", "MAT": "X", "MPR": "X", "MUI": "X",
        "MVC": "X", "MVI": "X", "MVA": "X", "MSC": "X", "MSI": "X", "MSA": "X",
        "S": "X", "AU": "X", "R": "X", "V": "X", "RE": "X", "U": "X",
    },
}
_CALCS = {"v2": cvss2_calc, "v3": cvss3_calc, "v31": cvss31_calc, "v4": cvss4_calc}


async def _render(request: Request, version: str) -> HTMLResponse:
    form = await request.form()
    prefix = f"{version}_"
    # Field names are "<version>_<metric>"; match metrics case-insensitively (e.g. v2 "Au")
    sent = {key[len(prefix):].upper(): value for key, value in form.items() if key.startswith(prefix)}
    metrics = {name: sent.get(name.upper(), default) for name, default in _DEFAULTS[version].items()}
    try:
        result = _CALCS[version].calculate(metrics)
    except Exception as exc:
        logger.exception("score_render_error", extra={"version": version, "error": str(exc)})
        result = None
    return templates.TemplateResponse(
        "partials/score_result.html",
        {"request": request, "result": result, "version": version},
    )


@router.post("/api/cvss2/render", response_class=HTMLResponse, include_in_schema=False)
async def render_cvss2(request: Request):
    return await _render(request, "v2")


@router.post("/api/cvss3/render", response_class=HTMLResponse, include_in_schema=False)
async def render_cvss3(request: Request):
    return await _render(request, "v3")


@router.post("/api/cvss31/render", response_class=HTMLResponse, include_in_schema=False)
async def render_cvss31(request: Request):
    return await _render(request, "v31")


@router.post("/api/cvss4/render", response_class=HTMLResponse, include_in_schema=False)
async def render_cvss4(request: Request):
    return await _render(request, "v4")
