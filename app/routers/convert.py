"""
CVSS conversion router.

Exposes:
  POST /api/convert          — HTMX/form endpoint used by the UI converter tool

Also exports the pure utility functions used by other routers:
  parse_vector(vector)
  validate_vector(vector, version)
  convert_metrics(metrics, from_ver, to_ver)
  VECTOR_VALID_VALUES
"""

from typing import Dict

from fastapi import APIRouter, Form
from fastapi.responses import JSONResponse

from app.deps import cvss2_calc, cvss3_calc, cvss31_calc, cvss4_calc
from app.logging_config import get_logger

router = APIRouter()
logger = get_logger("routers.convert")

# ── Valid metric values per CVSS version ──────────────────────────────────────

VECTOR_VALID_VALUES: Dict[str, Dict[str, list]] = {
    "2.0": {
        "AV": ["L", "A", "N"],
        "AC": ["H", "M", "L"],
        "Au": ["M", "S", "N"],
        "C": ["N", "P", "C"],
        "I": ["N", "P", "C"],
        "A": ["N", "P", "C"],
        "E": ["U", "POC", "F", "H", "ND"],
        "RL": ["OF", "TF", "W", "U", "ND"],
        "RC": ["UC", "UR", "C", "ND"],
        "CDP": ["N", "L", "LM", "MH", "H", "ND"],
        "TD": ["N", "L", "M", "H", "ND"],
        "CR": ["L", "M", "H", "ND"],
        "IR": ["L", "M", "H", "ND"],
        "AR": ["L", "M", "H", "ND"],
    },
    "3.0": {
        "AV": ["N", "A", "L", "P"],
        "AC": ["L", "H"],
        "PR": ["N", "L", "H"],
        "UI": ["N", "R"],
        "S": ["U", "C"],
        "C": ["N", "L", "H"],
        "I": ["N", "L", "H"],
        "A": ["N", "L", "H"],
        "E": ["X", "U", "P", "F", "H"],
        "RL": ["X", "O", "T", "W", "U"],
        "RC": ["X", "U", "R", "C"],
        "CR": ["X", "L", "M", "H"],
        "IR": ["X", "L", "M", "H"],
        "AR": ["X", "L", "M", "H"],
        "MAV": ["X", "N", "A", "L", "P"],
        "MAC": ["X", "L", "H"],
        "MPR": ["X", "N", "L", "H"],
        "MUI": ["X", "N", "R"],
        "MS": ["X", "U", "C"],
        "MC": ["X", "N", "L", "H"],
        "MI": ["X", "N", "L", "H"],
        "MA": ["X", "N", "L", "H"],
    },
    "3.1": {
        "AV": ["N", "A", "L", "P"],
        "AC": ["L", "H"],
        "PR": ["N", "L", "H"],
        "UI": ["N", "R"],
        "S": ["U", "C"],
        "C": ["N", "L", "H"],
        "I": ["N", "L", "H"],
        "A": ["N", "L", "H"],
        "E": ["X", "U", "P", "F", "H"],
        "RL": ["X", "O", "T", "W", "U"],
        "RC": ["X", "U", "R", "C"],
        "CR": ["X", "L", "M", "H"],
        "IR": ["X", "L", "M", "H"],
        "AR": ["X", "L", "M", "H"],
        "MAV": ["X", "N", "A", "L", "P"],
        "MAC": ["X", "L", "H"],
        "MPR": ["X", "N", "L", "H"],
        "MUI": ["X", "N", "R"],
        "MS": ["X", "U", "C"],
        "MC": ["X", "N", "L", "H"],
        "MI": ["X", "N", "L", "H"],
        "MA": ["X", "N", "L", "H"],
    },
    "4.0": {
        "AV": ["N", "A", "L", "P"],
        "AC": ["L", "H"],
        "AT": ["N", "P"],
        "PR": ["N", "L", "H"],
        "UI": ["N", "P", "A"],
        "VC": ["N", "L", "H"],
        "VI": ["N", "L", "H"],
        "VA": ["N", "L", "H"],
        "SC": ["N", "L", "H"],
        "SI": ["N", "L", "H"],
        "SA": ["N", "L", "H"],
        "E": ["X", "A", "P", "U"],
        "CR": ["X", "L", "M", "H"],
        "IR": ["X", "L", "M", "H"],
        "AR": ["X", "L", "M", "H"],
        "MAV": ["X", "N", "A", "L", "P"],
        "MAC": ["X", "L", "H"],
        "MAT": ["X", "N", "P"],
        "MPR": ["X", "N", "L", "H"],
        "MUI": ["X", "N", "P", "A"],
        "MVC": ["X", "N", "L", "H"],
        "MVI": ["X", "N", "L", "H"],
        "MVA": ["X", "N", "L", "H"],
        "MSC": ["X", "N", "L", "H"],
        "MSI": ["X", "N", "L", "H", "S"],
        "MSA": ["X", "N", "L", "H", "S"],
        "S": ["X", "N", "P"],
        "AU": ["X", "N", "Y"],
        "R": ["X", "A", "U", "I"],
        "V": ["X", "D", "C"],
        "RE": ["X", "L", "M", "H"],
        "U": ["X", "Clear", "Green", "Amber", "Red"],
    },
}


# Base metrics every vector must contain
BASE_METRICS: Dict[str, list] = {
    "2.0": ["AV", "AC", "Au", "C", "I", "A"],
    "3.0": ["AV", "AC", "PR", "UI", "S", "C", "I", "A"],
    "3.1": ["AV", "AC", "PR", "UI", "S", "C", "I", "A"],
    "4.0": ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"],
}


# ── Pure utility functions ────────────────────────────────────────────────────

def parse_vector(vector: str) -> Dict[str, str]:
    """Parse a CVSS vector string into a metrics dict."""
    metrics: Dict[str, str] = {}
    if vector.startswith(("CVSS:4.0/", "CVSS:3.1/", "CVSS:3.0/")):
        vector = vector[9:]
    elif vector.startswith("(") and vector.endswith(")"):
        vector = vector[1:-1]

    for pair in vector.split("/"):
        if ":" in pair:
            key, value = pair.split(":", 1)
            metrics[key] = value
    return metrics


def validate_vector(vector: str, version: str) -> tuple[bool, str]:
    """
    Validate a CVSS vector string for a given version.
    Returns (is_valid, error_message).
    """
    # Auto-detect version from prefix
    detected = version
    if vector.startswith("CVSS:4.0/"):
        detected = "4.0"
    elif vector.startswith("CVSS:3.1/"):
        detected = "3.1"
    elif vector.startswith("CVSS:3.0/"):
        detected = "3.0"
    elif vector.startswith("(") and vector.endswith(")"):
        detected = "2.0"

    metrics = parse_vector(vector)
    if not metrics:
        return False, "Invalid vector string: no valid metrics found"
    return validate_metrics(metrics, detected)


def validate_metrics(metrics: Dict[str, str], version: str) -> tuple[bool, str]:
    """Check that all base metrics are present and every value exists in *version*.

    Metrics the version doesn't define are ignored. Returns (is_valid, error_message).
    """
    valid_metrics = VECTOR_VALID_VALUES.get(version)
    if not valid_metrics:
        return False, f"Unknown CVSS version: {version}"

    missing = [m for m in BASE_METRICS[version] if m not in metrics]
    if missing:
        return False, f"Missing base metric(s): {', '.join(missing)}"

    errors = [
        f"Invalid value '{value}' for metric '{name}'. Expected: {', '.join(valid_metrics[name])}"
        for name, value in metrics.items()
        if name in valid_metrics and value not in valid_metrics[name]
    ]
    if errors:
        return False, "; ".join(errors)
    return True, ""


def convert_metrics(metrics: Dict[str, str], from_ver: str, to_ver: str) -> Dict[str, str]:
    """Convert a metrics dict from one CVSS version to another (an approximation: always review it)."""
    # v2.0 and v4.0 have no direct mapping: go through v3.1
    if {from_ver, to_ver} == {"2.0", "4.0"}:
        return convert_metrics(convert_metrics(metrics, from_ver, "3.1"), "3.1", to_ver)

    converted: Dict[str, str] = {}

    cia_v2_to_v3 = {"N": "N", "P": "L", "C": "H"}
    cia_v3_to_v2 = {"N": "N", "L": "P", "H": "C"}

    if from_ver == "2.0" and to_ver in ("3.0", "3.1"):
        converted["AV"] = {"L": "L", "A": "A", "N": "N"}.get(metrics.get("AV", "N"), "N")
        converted["AC"] = {"H": "H", "M": "L", "L": "L"}.get(metrics.get("AC", "L"), "L")
        converted["PR"] = {"N": "N", "S": "L", "M": "L"}.get(metrics.get("Au", "N"), "N")
        converted["UI"] = "N"
        converted["S"] = "U"
        for v2k, v3k in (("C", "C"), ("I", "I"), ("A", "A")):
            converted[v3k] = cia_v2_to_v3.get(metrics.get(v2k, "N"), "N")

    elif to_ver == "2.0" and from_ver in ("3.0", "3.1"):
        converted["AV"] = {"L": "L", "A": "A", "N": "N", "P": "L"}.get(metrics.get("AV", "N"), "L")
        converted["AC"] = {"H": "H", "L": "L"}.get(metrics.get("AC", "L"), "H")
        converted["Au"] = {"N": "N", "L": "S", "H": "M"}.get(metrics.get("PR", "N"), "N")
        for v3k, v2k in (("C", "C"), ("I", "I"), ("A", "A")):
            converted[v2k] = cia_v3_to_v2.get(metrics.get(v3k, "N"), "N")

    elif from_ver in ("3.0", "3.1") and to_ver == "4.0":
        for key in ("AV", "AC", "PR"):
            if key in metrics:
                converted[key] = metrics[key]
        converted["UI"] = {"N": "N", "R": "A"}.get(metrics.get("UI", "N"), "N")
        for v3k, v4k in (("C", "VC"), ("I", "VI"), ("A", "VA")):
            if v3k in metrics:
                converted[v4k] = metrics[v3k]
        if metrics.get("S") == "C":
            converted.update({"SC": "H", "SI": "H", "SA": "H"})
        else:
            converted.update({"SC": "N", "SI": "N", "SA": "N"})
        converted["AT"] = "N"

    elif from_ver == "4.0" and to_ver in ("3.0", "3.1"):
        for key in ("AV", "AC", "PR"):
            if key in metrics:
                converted[key] = metrics[key]
        converted["UI"] = {"N": "N", "P": "R", "A": "R"}.get(metrics.get("UI", "N"), "N")
        for v4k, v3k in (("VC", "C"), ("VI", "I"), ("VA", "A")):
            if v4k in metrics:
                converted[v3k] = metrics[v4k]
        sc, si, sa = metrics.get("SC", "N"), metrics.get("SI", "N"), metrics.get("SA", "N")
        converted["S"] = "C" if "H" in (sc, si, sa) else "U"

    elif (from_ver, to_ver) in (("3.0", "3.1"), ("3.1", "3.0")):
        converted = dict(metrics)

    # Fill in required defaults for the target version
    defaults: Dict[str, str] = {
        "2.0": {"AV": "L", "AC": "H", "Au": "N", "C": "N", "I": "N", "A": "N"},
        "3.0": {"AV": "N", "AC": "H", "PR": "N", "UI": "N", "S": "U", "C": "N", "I": "N", "A": "N"},
        "3.1": {"AV": "N", "AC": "H", "PR": "N", "UI": "N", "S": "U", "C": "N", "I": "N", "A": "N"},
        "4.0": {"AV": "N", "AC": "H", "AT": "N", "PR": "N", "UI": "N",
                "VC": "N", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N"},
    }.get(to_ver, {})

    for key, value in defaults.items():
        converted.setdefault(key, value)

    return converted


# ── Route ─────────────────────────────────────────────────────────────────────

_CALCS = {"2.0": cvss2_calc, "3.0": cvss3_calc, "3.1": cvss31_calc, "4.0": cvss4_calc}


@router.post("/api/convert", include_in_schema=False)
async def convert_cvss(
    from_version: str = Form(...),
    to_version: str = Form(...),
    vector: str = Form(...),
):
    """Convert a CVSS vector from one version to another (UI / HTMX endpoint)."""
    try:
        logger.info("convert_request", extra={"from_version": from_version, "to_version": to_version})

        is_valid, error_msg = validate_vector(vector, from_version)
        if not is_valid:
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": f"Invalid vector string: {error_msg}"},
            )

        if from_version not in _CALCS:
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": f"Unknown source version: {from_version}"},
            )
        if to_version not in _CALCS:
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": f"Unknown target version: {to_version}"},
            )

        src_metrics = parse_vector(vector)
        original = _CALCS[from_version].calculate(src_metrics)

        dst_metrics = convert_metrics(src_metrics, from_version, to_version)
        converted = _CALCS[to_version].calculate(dst_metrics)

        def _flat(r: dict) -> dict:
            return {
                "base_score": r.get("base_score"),
                "base_severity": r.get("base_severity"),
                "temporal_score": r.get("temporal_score"),
                "temporal_severity": r.get("temporal_severity"),
                "environmental_score": r.get("environmental_score"),
                "environmental_severity": r.get("environmental_severity"),
                "vector_string": r.get("vector_string"),
            }

        return JSONResponse(
            content={
                "success": True,
                "original": _flat(original),
                "converted": _flat(converted),
                "converted_metrics": dst_metrics,
            }
        )
    except Exception as exc:
        logger.exception("convert_error", extra={"error": str(exc)})
        return JSONResponse(status_code=400, content={"success": False, "error": str(exc)})
