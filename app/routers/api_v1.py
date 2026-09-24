"""
Public REST API v1 — CVSS Guru.

All endpoints require authentication via API key.
Pass the key in one of these headers:
  - Authorization: Bearer <your_api_key>
  - X-API-Key: <your_api_key>
(Through RapidAPI, the RapidAPI gateway authenticates instead.)

Get your API key from your profile page at https://cvss.guru/profile

The OpenAPI response examples below are produced by running the same code as
the endpoints, so they match the real output (the OpenAPI generator only drops
null fields such as "temporal": null).
"""

from typing import Dict, Optional

from fastapi import APIRouter, Depends, Path
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.usage import check_usage_limit
from app.deps import cvss2_calc, cvss3_calc, cvss31_calc, cvss4_calc
from app.routers.convert import convert_metrics, parse_vector, validate_vector
from app.routers.cve import api_cve_lookup

router = APIRouter(
    prefix="/api/v1",
    tags=["CVSS Guru API v1"],
    # check_usage_limit depends on require_api_key (authentication runs once per request)
    dependencies=[Depends(check_usage_limit)],
)


# Response models

class ScoreObject(BaseModel):
    score: float = Field(..., examples=[9.8])
    severity: str = Field(..., examples=["Critical"])

class ScoresResponse(BaseModel):
    base: Optional[ScoreObject] = None
    temporal: Optional[ScoreObject] = None
    environmental: Optional[ScoreObject] = None

class ErrorResponse(BaseModel):
    success: bool = Field(False, examples=[False])
    error: str = Field(..., examples=["Invalid metric value for AV"])


# Request bodies

class V2MetricsBody(BaseModel):
    AV: str = Field(..., examples=["N"]); AC: str = Field(..., examples=["L"]); Au: str = Field(..., examples=["N"])
    C: str = Field(..., examples=["C"]); I: str = Field(..., examples=["C"]); A: str = Field(..., examples=["C"])
    E: Optional[str] = "ND"; RL: Optional[str] = "ND"; RC: Optional[str] = "ND"
    CDP: Optional[str] = "ND"; TD: Optional[str] = "ND"
    CR: Optional[str] = "ND"; IR: Optional[str] = "ND"; AR: Optional[str] = "ND"

class V30MetricsBody(BaseModel):
    AV: str = Field(..., examples=["N"]); AC: str = Field(..., examples=["L"])
    PR: str = Field(..., examples=["N"]); UI: str = Field(..., examples=["N"])
    S: str = Field(..., examples=["U"]); C: str = Field(..., examples=["H"])
    I: str = Field(..., examples=["H"]); A: str = Field(..., examples=["H"])
    E: Optional[str] = "X"; RL: Optional[str] = "X"; RC: Optional[str] = "X"
    CR: Optional[str] = "X"; IR: Optional[str] = "X"; AR: Optional[str] = "X"
    MAV: Optional[str] = "X"; MAC: Optional[str] = "X"; MPR: Optional[str] = "X"
    MUI: Optional[str] = "X"; MS: Optional[str] = "X"; MC: Optional[str] = "X"
    MI: Optional[str] = "X"; MA: Optional[str] = "X"

class V31MetricsBody(V30MetricsBody):
    """CVSS v3.1 metrics — identical schema to v3.0."""
    pass

class V40MetricsBody(BaseModel):
    AV: str = Field(..., examples=["N"]); AC: str = Field(..., examples=["L"])
    AT: str = Field(..., examples=["N"]); PR: str = Field(..., examples=["N"])
    UI: str = Field(..., examples=["N"]); VC: str = Field(..., examples=["H"])
    VI: str = Field(..., examples=["H"]); VA: str = Field(..., examples=["H"])
    SC: Optional[str] = "N"; SI: Optional[str] = "N"; SA: Optional[str] = "N"
    E: Optional[str] = "X"
    CR: Optional[str] = "X"; IR: Optional[str] = "X"; AR: Optional[str] = "X"
    MAV: Optional[str] = "X"; MAC: Optional[str] = "X"; MAT: Optional[str] = "X"
    MPR: Optional[str] = "X"; MUI: Optional[str] = "X"
    MVC: Optional[str] = "X"; MVI: Optional[str] = "X"; MVA: Optional[str] = "X"
    MSC: Optional[str] = "X"; MSI: Optional[str] = "X"; MSA: Optional[str] = "X"
    S: Optional[str] = "X"; AU: Optional[str] = "X"; R: Optional[str] = "X"
    V: Optional[str] = "X"; RE: Optional[str] = "X"; U: Optional[str] = "X"

class VectorBody(BaseModel):
    vector: str = Field(..., examples=["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"],
                        description="Full CVSS vector string. Version is auto-detected from the prefix.")

class ConvertBody(BaseModel):
    vector: str = Field(..., examples=["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"])
    to: str = Field(..., examples=["4.0"], description="Target CVSS version: 2.0, 3.0, 3.1, or 4.0")


# Core logic (shared by the endpoints and the OpenAPI examples)

_CALCS = {"2.0": cvss2_calc, "3.0": cvss3_calc, "3.1": cvss31_calc, "4.0": cvss4_calc}
_PREFIXES = {"CVSS:4.0/": "4.0", "CVSS:3.1/": "3.1", "CVSS:3.0/": "3.0"}


class _Unprocessable(ValueError):
    """Well-formed request that cannot be processed (HTTP 422)."""


def _fmt_score(result: Dict) -> Dict:
    def _obj(score, severity):
        return None if score is None else {"score": score, "severity": severity}
    return {
        "base": _obj(result.get("base_score"), result.get("base_severity")),
        "temporal": _obj(result.get("temporal_score"), result.get("temporal_severity")),
        "environmental": _obj(result.get("environmental_score"), result.get("environmental_severity")),
    }


def _prefix_version(vector: str) -> Optional[str]:
    return next((v for p, v in _PREFIXES.items() if vector.startswith(p)), None)


def _calculate(version: str, metrics: Dict) -> Dict:
    result = _CALCS[version].calculate(metrics)
    return {"version": version, "vector": result.get("vector_string"), "scores": _fmt_score(result), "metrics": metrics}


def _calculate_vector(vector: str) -> Dict:
    version = _prefix_version(vector)
    if version is None:
        if not (vector.startswith("(") or "/" in vector):
            raise _Unprocessable("Cannot detect CVSS version from vector string.")
        version = "2.0"
    metrics = parse_vector(vector)
    result = _CALCS[version].calculate(metrics)
    return {"version": version, "vector": result.get("vector_string") or vector, "scores": _fmt_score(result), "metrics": metrics}


def _convert(vector: str, to_version: str) -> Dict:
    if to_version not in _CALCS:
        raise _Unprocessable(f"Invalid target version. Must be one of: {', '.join(sorted(_CALCS))}")
    from_version = _prefix_version(vector) or "2.0"
    is_valid, err = validate_vector(vector, from_version)
    if not is_valid:
        raise _Unprocessable(f"Invalid vector: {err}")
    src_metrics = parse_vector(vector)
    src_result = _CALCS[from_version].calculate(src_metrics)
    dst_metrics = convert_metrics(src_metrics, from_version, to_version)
    dst_result = _CALCS[to_version].calculate(dst_metrics)
    return {
        "from": {"version": from_version, "vector": src_result.get("vector_string") or vector, "scores": _fmt_score(src_result)},
        "to": {"version": to_version, "vector": dst_result.get("vector_string"), "scores": _fmt_score(dst_result), "metrics": dst_metrics},
    }


def _run(fn, *args):
    """Call the core logic; errors get the same shape as the app-wide handler (401, 429, ...)."""
    try:
        return fn(*args)
    except _Unprocessable as exc:
        return JSONResponse(status_code=422, content={"success": False, "error": str(exc)})
    except Exception as exc:
        return JSONResponse(status_code=400, content={"success": False, "error": str(exc)})


# OpenAPI documentation: request examples, real response examples, error shapes

_EX_METRICS = {
    "2.0": {"AV": "N", "AC": "L", "Au": "N", "C": "C", "I": "C", "A": "C"},
    "3.0": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
    "3.1": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C", "C": "L", "I": "L", "A": "N"},
    "4.0": {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N", "VC": "H", "VI": "H", "VA": "H"},
}
_BODIES = {"2.0": V2MetricsBody, "3.0": V30MetricsBody, "3.1": V31MetricsBody, "4.0": V40MetricsBody}
_EX_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
_EX_CONVERT = {"vector": _EX_VECTOR, "to": "4.0"}

# Real NVD data for Log4Shell (description and references shortened)
_EX_CVE = {
    "success": True,
    "cached": False,
    "id": "CVE-2021-44228",
    "published": "2021-12-10",
    "modified": "2026-08-11",
    "description": "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) "
                   "JNDI features used in configuration, log messages, and parameters do not protect against …",
    "scores": {
        "v2": {"version": "2.0", "vector": "AV:N/AC:M/Au:N/C:C/I:C/A:C", "score": 9.3, "severity": "HIGH",
               "source": "nvd@nist.gov", "type": "Primary"},
        "v30": None,
        "v31": {"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "score": 10.0,
                "severity": "CRITICAL", "source": "nvd@nist.gov", "type": "Primary"},
        "v40": None,
    },
    "references": ["https://logging.apache.org/log4j/2.x/security.html"],
    "weaknesses": ["CWE-20", "CWE-917"],
}

_ERROR_DOCS = {
    400: ("Invalid metric values", {"success": False, "error": "Invalid metric value for AV"}),
    401: ("Missing or invalid API key", {"success": False, "error": "Invalid API key"}),
    404: ("CVE not found", {"success": False, "error": "CVE-2099-0001 not found in NVD."}),
    422: ("Unusable input (e.g. unknown vector format)",
          {"success": False, "error": "Cannot detect CVSS version from vector string."}),
    429: ("Monthly quota reached (local API keys only)",
          {"success": False, "error": "Monthly API limit reached", "limit": 100, "used": 100,
           "rapidapi_url": "https://rapidapi.com/..."}),
}


def _json(example) -> Dict:
    return {"application/json": {"example": example}}


def _doc(ok_example, request_example=None, errors=(400, 401, 422, 429), overrides=None) -> Dict:
    """Route decorator kwargs: 200 example, error examples and (optionally) a request example."""
    responses = {200: {"description": "Successful response", "content": _json(ok_example)}}
    docs = {**_ERROR_DOCS, **(overrides or {})}
    for code in errors:
        description, example = docs[code]
        responses[code] = {"model": ErrorResponse, "description": description, "content": _json(example)}
    kw: Dict = {"responses": responses}
    if request_example is not None:
        kw["openapi_extra"] = {"requestBody": {"content": _json(request_example)}}
    return kw


def _calc_doc(version: str) -> Dict:
    metrics = _BODIES[version](**_EX_METRICS[version]).model_dump()
    return _doc(_calculate(version, metrics), _EX_METRICS[version])


# Calculate endpoints

@router.post("/calculate/2.0", summary="Calculate CVSS v2.0 score", **_calc_doc("2.0"))
async def v1_calculate_v2(body: V2MetricsBody):
    """Calculate a CVSS v2.0 Base (and optionally Temporal/Environmental) score.
    Only the six base metrics are required; the others default to `ND` (not defined)."""
    return _run(_calculate, "2.0", body.model_dump())

@router.post("/calculate/3.0", summary="Calculate CVSS v3.0 score", **_calc_doc("3.0"))
async def v1_calculate_v30(body: V30MetricsBody):
    """Calculate a CVSS v3.0 score from individual metric values.
    Only the eight base metrics are required; temporal and environmental ones default to `X`."""
    return _run(_calculate, "3.0", body.model_dump())

@router.post("/calculate/3.1", summary="Calculate CVSS v3.1 score", **_calc_doc("3.1"))
async def v1_calculate_v31(body: V31MetricsBody):
    """Calculate a CVSS v3.1 score. Same formula as v3.0 with improved documentation.
    Use this endpoint for CVEs published after 2019."""
    return _run(_calculate, "3.1", body.model_dump())

@router.post("/calculate/4.0", summary="Calculate CVSS v4.0 score", **_calc_doc("4.0"))
async def v1_calculate_v40(body: V40MetricsBody):
    """Calculate a CVSS v4.0 score using the official FIRST.org macro-vector lookup table.
    Threat (E) and Environmental metrics are folded into the single score — no separate temporal/environmental scores."""
    return _run(_calculate, "4.0", body.model_dump())

@router.post("/calculate/vector", summary="Calculate score from vector string",
             **_doc(_calculate_vector(_EX_VECTOR), {"vector": _EX_VECTOR}))
async def v1_calculate_vector(body: VectorBody):
    """Calculate a CVSS score from a vector string. Version is auto-detected from the prefix:
    CVSS:4.0/ → v4.0, CVSS:3.1/ → v3.1, CVSS:3.0/ → v3.0, (AV:...) → v2.0"""
    return _run(_calculate_vector, body.vector.strip())


# Convert endpoint

@router.post("/convert", summary="Convert CVSS vector between versions",
             **_doc(_convert(_EX_CONVERT["vector"], _EX_CONVERT["to"]), _EX_CONVERT))
async def v1_convert(body: ConvertBody):
    """Convert a CVSS vector string from one version to another.
    Source version is auto-detected. Returns both original and converted scores.
    Supported: v2.0 <-> v3.x, v3.x <-> v4.0, v3.0 <-> v3.1.
    Conversions between versions are approximations: review the result."""
    return _run(_convert, body.vector.strip(), body.to.strip())


# CVE lookup

@router.get("/cve/{cve_id}", summary="Fetch CVE details and CVSS scores from NVD",
            **_doc(_EX_CVE, errors=(401, 404, 422, 429), overrides={
                422: ("Invalid CVE ID", {"success": False, "error": "Invalid CVE ID format. Expected CVE-YYYY-NNNNN."}),
            }))
async def v1_cve_lookup(cve_id: str = Path(..., description="CVE identifier", examples=["CVE-2021-44228"])):
    """Fetch CVE details and all available CVSS scores from the NVD.
    Results are cached for 24 hours. CVE ID format: CVE-YYYY-NNNNN."""
    return await api_cve_lookup(cve_id)
