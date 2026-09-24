"""
CVSS v4.0 Calculator — Official FIRST.org algorithm.

This is a faithful Python translation of the reference JavaScript implementation
at https://github.com/FIRSTdotorg/cvss-v4-calculator (BSD-2-Clause).

The algorithm uses a lookup table of 101 macro-vector scores and an interpolation
step to produce the final score. It does NOT use a formula.
"""

from __future__ import annotations

import math
from decimal import ROUND_HALF_UP, Decimal
from typing import Dict, Any, Optional

# ── Lookup table (MV_LOOKUP) ──────────────────────────────────────────────────
# Keys are 6-digit strings representing EQ1..EQ6 levels.
# Values are the mean score for that macro-vector.
# Source: https://github.com/FIRSTdotorg/cvss-v4-calculator/blob/main/cvss_lookup.js

MV_LOOKUP: Dict[str, float] = {
    "000000": 10.0, "000001": 9.9, "000010": 9.8, "000011": 9.5,
    "000020": 9.5,  "000021": 9.2,
    "000100": 10.0, "000101": 9.6, "000110": 9.3, "000111": 8.7,
    "000120": 9.1,  "000121": 8.1,
    "000200": 9.3,  "000201": 9.0, "000210": 8.9, "000211": 8.0,
    "000220": 8.1,  "000221": 6.8,
    "001000": 9.8,  "001001": 9.5, "001010": 9.5, "001011": 9.2,
    "001020": 9.0,  "001021": 8.4,
    "001100": 9.3,  "001101": 9.2, "001110": 8.9, "001111": 8.1,
    "001120": 8.1,  "001121": 6.5,
    "001200": 8.8,  "001201": 8.0, "001210": 7.8, "001211": 7.0,
    "001220": 6.9,  "001221": 4.8,
    "002001": 9.2,  "002011": 8.2, "002021": 7.2,
    "002101": 7.9,  "002111": 6.9, "002121": 5.0,
    "002201": 6.9,  "002211": 5.5, "002221": 2.7,
    "010000": 9.9,  "010001": 9.7, "010010": 9.5, "010011": 9.2,
    "010020": 9.2,  "010021": 8.5,
    "010100": 9.5,  "010101": 9.1, "010110": 9.0, "010111": 8.3,
    "010120": 8.4,  "010121": 7.1,
    "010200": 9.2,  "010201": 8.1, "010210": 8.2, "010211": 7.1,
    "010220": 7.2,  "010221": 5.3,
    "011000": 9.5,  "011001": 9.3, "011010": 9.2, "011011": 8.5,
    "011020": 8.5,  "011021": 7.3,
    "011100": 9.2,  "011101": 8.2, "011110": 8.0, "011111": 7.2,
    "011120": 7.0,  "011121": 5.9,
    "011200": 8.4,  "011201": 7.0, "011210": 7.1, "011211": 5.2,
    "011220": 5.0,  "011221": 3.0,
    "012001": 8.6,  "012011": 7.5, "012021": 5.2,
    "012101": 7.1,  "012111": 5.2, "012121": 2.9,
    "012201": 6.3,  "012211": 2.9, "012221": 1.7,
    "100000": 9.8,  "100001": 9.5, "100010": 9.4, "100011": 8.7,
    "100020": 9.1,  "100021": 8.1,
    "100100": 9.4,  "100101": 8.9, "100110": 8.6, "100111": 7.4,
    "100120": 7.7,  "100121": 6.4,
    "100200": 8.7,  "100201": 7.5, "100210": 7.4, "100211": 6.3,
    "100220": 6.3,  "100221": 4.9,
    "101000": 9.4,  "101001": 8.9, "101010": 8.8, "101011": 7.7,
    "101020": 7.6,  "101021": 6.7,
    "101100": 8.6,  "101101": 7.6, "101110": 7.4, "101111": 5.8,
    "101120": 5.9,  "101121": 5.0,
    "101200": 7.2,  "101201": 5.7, "101210": 5.7, "101211": 5.2,
    "101220": 5.2,  "101221": 2.5,
    "102001": 8.3,  "102011": 7.0, "102021": 5.4,
    "102101": 6.5,  "102111": 5.8, "102121": 2.6,
    "102201": 5.3,  "102211": 2.1, "102221": 1.3,
    "110000": 9.5,  "110001": 9.0, "110010": 8.8, "110011": 7.6,
    "110020": 7.6,  "110021": 7.0,
    "110100": 9.0,  "110101": 7.7, "110110": 7.5, "110111": 6.2,
    "110120": 6.1,  "110121": 5.3,
    "110200": 7.7,  "110201": 6.6, "110210": 6.8, "110211": 5.9,
    "110220": 5.2,  "110221": 3.0,
    "111000": 8.9,  "111001": 7.8, "111010": 7.6, "111011": 6.7,
    "111020": 6.2,  "111021": 5.8,
    "111100": 7.4,  "111101": 5.9, "111110": 5.7, "111111": 5.7,
    "111120": 4.7,  "111121": 2.3,
    "111200": 6.1,  "111201": 5.2, "111210": 5.7, "111211": 2.9,
    "111220": 2.4,  "111221": 1.6,
    "112001": 7.1,  "112011": 5.9, "112021": 3.0,
    "112101": 5.8,  "112111": 2.6, "112121": 1.5,
    "112201": 2.3,  "112211": 1.3, "112221": 0.6,
    "200000": 9.3,  "200001": 8.7, "200010": 8.6, "200011": 7.2,
    "200020": 7.5,  "200021": 5.8,
    "200100": 8.6,  "200101": 7.4, "200110": 7.4, "200111": 6.1,
    "200120": 5.6,  "200121": 3.4,
    "200200": 7.0,  "200201": 5.4, "200210": 5.2, "200211": 4.0,
    "200220": 4.0,  "200221": 2.2,
    "201000": 8.5,  "201001": 7.5, "201010": 7.4, "201011": 5.5,
    "201020": 6.2,  "201021": 5.1,
    "201100": 7.2,  "201101": 5.7, "201110": 5.5, "201111": 4.1,
    "201120": 4.6,  "201121": 1.9,
    "201200": 5.3,  "201201": 3.6, "201210": 3.4, "201211": 1.9,
    "201220": 1.9,  "201221": 0.8,
    "202001": 6.4,  "202011": 5.1, "202021": 2.0,
    "202101": 4.7,  "202111": 2.1, "202121": 1.1,
    "202201": 2.4,  "202211": 0.9, "202221": 0.4,
    "210000": 8.8,  "210001": 7.5, "210010": 7.3, "210011": 5.3,
    "210020": 6.0,  "210021": 5.0,
    "210100": 7.3,  "210101": 5.5, "210110": 5.9, "210111": 4.0,
    "210120": 4.1,  "210121": 2.0,
    "210200": 5.4,  "210201": 4.3, "210210": 4.5, "210211": 2.2,
    "210220": 2.0,  "210221": 1.1,
    "211000": 7.5,  "211001": 5.5, "211010": 5.8, "211011": 4.5,
    "211020": 4.0,  "211021": 2.1,
    "211100": 6.1,  "211101": 5.1, "211110": 4.8, "211111": 1.8,
    "211120": 2.0,  "211121": 0.9,
    "211200": 4.6,  "211201": 1.8, "211210": 1.7, "211211": 0.7,
    "211220": 0.8,  "211221": 0.2,
    "212001": 5.3,  "212011": 2.4, "212021": 1.4,
    "212101": 2.4,  "212111": 1.2, "212121": 0.5,
    "212201": 1.0,  "212211": 0.3, "212221": 0.1,
}

# ── Max composed vectors per EQ level ────────────────────────────────────────
# Used to find the highest-severity vector in the same macro-vector.
# Source: https://github.com/FIRSTdotorg/cvss-v4-calculator/blob/main/max_composed.js

MAX_COMPOSED: Dict[str, Any] = {
    "eq1": {
        0: ["AV:N/PR:N/UI:N/"],
        1: ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
        2: ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"],
    },
    "eq2": {
        0: ["AC:L/AT:N/"],
        1: ["AC:H/AT:N/", "AC:L/AT:P/"],
    },
    # eq3 is indexed by (eq3_level, eq6_level)
    "eq3": {
        0: {
            "0": ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],
            "1": ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"],
        },
        1: {
            "0": ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"],
            "1": [
                "VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/",
                "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
                "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/",
                "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
                "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/",
            ],
        },
        2: {
            "1": ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"],
        },
    },
    "eq4": {
        0: ["SC:H/SI:S/SA:S/"],
        1: ["SC:H/SI:H/SA:H/"],
        2: ["SC:L/SI:L/SA:L/"],
    },
    "eq5": {
        0: ["E:A/"],
        1: ["E:P/"],
        2: ["E:U/"],
    },
}

# ── Max severity distances per EQ level ──────────────────────────────────────
# Source: https://github.com/FIRSTdotorg/cvss-v4-calculator/blob/main/max_severity.js

MAX_SEVERITY: Dict[str, Any] = {
    "eq1":    {0: 1, 1: 4, 2: 5},
    "eq2":    {0: 1, 1: 2},
    "eq3eq6": {0: {0: 7, 1: 6}, 1: {0: 8, 1: 8}, 2: {1: 10}},
    "eq4":    {0: 6, 1: 5, 2: 4},
    "eq5":    {0: 1, 1: 1, 2: 1},
}

# ── Metric level mappings (for severity distance) ─────────────────────────────

AV_LEVELS = {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}
PR_LEVELS = {"N": 0.0, "L": 0.1, "H": 0.2}
UI_LEVELS = {"N": 0.0, "P": 0.1, "A": 0.2}
AC_LEVELS = {"L": 0.0, "H": 0.1}
AT_LEVELS = {"N": 0.0, "P": 0.1}
VC_LEVELS = {"H": 0.0, "L": 0.1, "N": 0.2}
VI_LEVELS = {"H": 0.0, "L": 0.1, "N": 0.2}
VA_LEVELS = {"H": 0.0, "L": 0.1, "N": 0.2}
SC_LEVELS = {"H": 0.1, "L": 0.2, "N": 0.3}
SI_LEVELS = {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3}
SA_LEVELS = {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3}
CR_LEVELS = {"H": 0.0, "M": 0.1, "L": 0.2}
IR_LEVELS = {"H": 0.0, "M": 0.1, "L": 0.2}
AR_LEVELS = {"H": 0.0, "M": 0.1, "L": 0.2}
E_LEVELS  = {"U": 0.2, "P": 0.1, "A": 0.0}


# ── Helper functions ──────────────────────────────────────────────────────────

def _m(metrics: Dict[str, str], metric: str) -> str:
    """
    Resolve the effective value of a metric, applying:
    - X defaults (E:X→A, CR/IR/AR:X→H)
    - Modified metric overrides (M{metric} overrides base when not X)
    """
    selected = metrics.get(metric, "X")

    # E:X defaults to worst case A
    if metric == "E" and selected == "X":
        return "A"
    # CR/IR/AR:X default to worst case H
    if metric in ("CR", "IR", "AR") and selected == "X":
        return "H"

    # Modified metric overrides base when defined and not X
    modified_key = "M" + metric
    if modified_key in metrics:
        modified = metrics[modified_key]
        if modified != "X":
            return modified

    return selected


def _extract_value_metric(metric: str, vector_str: str) -> str:
    """Extract a metric value from a slash-separated vector fragment like 'AV:N/PR:N/'."""
    idx = vector_str.find(metric + ":")
    if idx == -1:
        return ""
    extracted = vector_str[idx + len(metric) + 1:]
    slash = extracted.find("/")
    return extracted[:slash] if slash >= 0 else extracted


def _macro_vector(metrics: Dict[str, str]) -> str:
    """
    Compute the 6-digit macro-vector string (EQ1..EQ6).
    Direct translation of macroVector() from the FIRST reference implementation.
    """
    # EQ1: 0=AV:N+PR:N+UI:N, 1=one of them N (not all, not AV:P), 2=AV:P or none N
    if _m(metrics, "AV") == "N" and _m(metrics, "PR") == "N" and _m(metrics, "UI") == "N":
        eq1 = 0
    elif (
        (_m(metrics, "AV") == "N" or _m(metrics, "PR") == "N" or _m(metrics, "UI") == "N")
        and not (_m(metrics, "AV") == "N" and _m(metrics, "PR") == "N" and _m(metrics, "UI") == "N")
        and _m(metrics, "AV") != "P"
    ):
        eq1 = 1
    else:
        eq1 = 2

    # EQ2: 0=AC:L+AT:N, 1=otherwise
    if _m(metrics, "AC") == "L" and _m(metrics, "AT") == "N":
        eq2 = 0
    else:
        eq2 = 1

    # EQ3: 0=VC:H+VI:H, 1=one H (not both VC+VI), 2=none H
    if _m(metrics, "VC") == "H" and _m(metrics, "VI") == "H":
        eq3 = 0
    elif (
        not (_m(metrics, "VC") == "H" and _m(metrics, "VI") == "H")
        and (_m(metrics, "VC") == "H" or _m(metrics, "VI") == "H" or _m(metrics, "VA") == "H")
    ):
        eq3 = 1
    else:
        eq3 = 2

    # EQ4: 0=MSI:S or MSA:S, 1=SC/SI/SA:H (no Safety), 2=none H
    if _m(metrics, "MSI") == "S" or _m(metrics, "MSA") == "S":
        eq4 = 0
    elif (
        not (_m(metrics, "MSI") == "S" or _m(metrics, "MSA") == "S")
        and (_m(metrics, "SC") == "H" or _m(metrics, "SI") == "H" or _m(metrics, "SA") == "H")
    ):
        eq4 = 1
    else:
        eq4 = 2

    # EQ5: 0=E:A, 1=E:P, 2=E:U
    e_val = _m(metrics, "E")
    if e_val == "A":
        eq5 = 0
    elif e_val == "P":
        eq5 = 1
    else:
        eq5 = 2

    # EQ6: 0=(CR:H+VC:H) or (IR:H+VI:H) or (AR:H+VA:H), 1=otherwise
    if (
        (_m(metrics, "CR") == "H" and _m(metrics, "VC") == "H")
        or (_m(metrics, "IR") == "H" and _m(metrics, "VI") == "H")
        or (_m(metrics, "AR") == "H" and _m(metrics, "VA") == "H")
    ):
        eq6 = 0
    else:
        eq6 = 1

    return f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}"


def _get_eq_maxes(macro_vector: str, eq: int) -> list:
    """Return the list of highest-severity vector fragments for a given EQ level."""
    level = int(macro_vector[eq - 1])
    if eq == 3:
        eq6_level = macro_vector[5]
        return MAX_COMPOSED["eq3"][level][eq6_level]
    return MAX_COMPOSED[f"eq{eq}"][level]


def _distance(value: float, next_lower: Optional[float]) -> float:
    """Distance to the next lower macro vector; NaN when there is none (a 0.0 score is a real score)."""
    return float("nan") if next_lower is None else value - next_lower


def _round1(value: float) -> float:
    """Round half up to one decimal like the official calculator, which adds 1e-6 to absorb float
    error (e.g. 5.649999... must give 5.7); Python's round() would round half to even."""
    return float(Decimal(value + 1e-6).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))


def _cvss4_score(metrics: Dict[str, str]) -> float:
    """
    Compute the CVSS v4.0 score.
    Direct translation of cvss_score() from the FIRST reference implementation.
    """
    # Shortcut: no impact at all → 0.0
    if all(_m(metrics, k) == "N" for k in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return 0.0

    mv = _macro_vector(metrics)
    value = MV_LOOKUP.get(mv)
    if value is None:
        return 0.0

    eq1 = int(mv[0])
    eq2 = int(mv[1])
    eq3 = int(mv[2])
    eq4 = int(mv[3])
    eq5 = int(mv[4])
    eq6 = int(mv[5])

    # Next-lower macro vectors
    eq1_next = f"{eq1+1}{mv[1:]}"
    eq2_next = f"{mv[0]}{eq2+1}{mv[2:]}"
    eq4_next = f"{mv[:3]}{eq4+1}{mv[4:]}"
    eq5_next = f"{mv[:4]}{eq5+1}{mv[5]}"

    # EQ3+EQ6 are coupled
    if eq3 == 1 and eq6 == 1:
        eq3eq6_next = f"{mv[:2]}{eq3+1}{mv[3:]}"
    elif eq3 == 0 and eq6 == 1:
        eq3eq6_next = f"{mv[:2]}{eq3+1}{mv[3:]}"
    elif eq3 == 1 and eq6 == 0:
        eq3eq6_next = f"{mv[:5]}{eq6+1}"
    elif eq3 == 0 and eq6 == 0:
        eq3eq6_next_left  = f"{mv[:5]}{eq6+1}"
        eq3eq6_next_right = f"{mv[:2]}{eq3+1}{mv[3:]}"
    else:
        eq3eq6_next = f"{mv[:2]}{eq3+1}{mv[3:5]}{eq6+1}"

    score_eq1_next  = MV_LOOKUP.get(eq1_next)
    score_eq2_next  = MV_LOOKUP.get(eq2_next)
    score_eq4_next  = MV_LOOKUP.get(eq4_next)
    score_eq5_next  = MV_LOOKUP.get(eq5_next)

    if eq3 == 0 and eq6 == 0:
        s_left  = MV_LOOKUP.get(eq3eq6_next_left)
        s_right = MV_LOOKUP.get(eq3eq6_next_right)
        if (s_left or 0) >= (s_right or 0):
            score_eq3eq6_next = s_left
        else:
            score_eq3eq6_next = s_right
    else:
        score_eq3eq6_next = MV_LOOKUP.get(eq3eq6_next)

    # Build all combinations of highest vectors
    eq1_maxes    = _get_eq_maxes(mv, 1)
    eq2_maxes    = _get_eq_maxes(mv, 2)
    eq3eq6_maxes = _get_eq_maxes(mv, 3)
    eq4_maxes    = _get_eq_maxes(mv, 4)
    eq5_maxes    = _get_eq_maxes(mv, 5)

    max_vectors = []
    for a in eq1_maxes:
        for b in eq2_maxes:
            for c in eq3eq6_maxes:
                for d in eq4_maxes:
                    for e in eq5_maxes:
                        max_vectors.append(a + b + c + d + e)

    # Find the max vector whose severity distance is >= 0 for all metrics
    severity_distance_AV = severity_distance_PR = severity_distance_UI = 0.0
    severity_distance_AC = severity_distance_AT = 0.0
    severity_distance_VC = severity_distance_VI = severity_distance_VA = 0.0
    severity_distance_SC = severity_distance_SI = severity_distance_SA = 0.0
    severity_distance_CR = severity_distance_IR = severity_distance_AR = 0.0

    for max_vec in max_vectors:
        severity_distance_AV = AV_LEVELS.get(_m(metrics, "AV"), 0) - AV_LEVELS.get(_extract_value_metric("AV", max_vec), 0)
        severity_distance_PR = PR_LEVELS.get(_m(metrics, "PR"), 0) - PR_LEVELS.get(_extract_value_metric("PR", max_vec), 0)
        severity_distance_UI = UI_LEVELS.get(_m(metrics, "UI"), 0) - UI_LEVELS.get(_extract_value_metric("UI", max_vec), 0)
        severity_distance_AC = AC_LEVELS.get(_m(metrics, "AC"), 0) - AC_LEVELS.get(_extract_value_metric("AC", max_vec), 0)
        severity_distance_AT = AT_LEVELS.get(_m(metrics, "AT"), 0) - AT_LEVELS.get(_extract_value_metric("AT", max_vec), 0)
        severity_distance_VC = VC_LEVELS.get(_m(metrics, "VC"), 0) - VC_LEVELS.get(_extract_value_metric("VC", max_vec), 0)
        severity_distance_VI = VI_LEVELS.get(_m(metrics, "VI"), 0) - VI_LEVELS.get(_extract_value_metric("VI", max_vec), 0)
        severity_distance_VA = VA_LEVELS.get(_m(metrics, "VA"), 0) - VA_LEVELS.get(_extract_value_metric("VA", max_vec), 0)
        severity_distance_SC = SC_LEVELS.get(_m(metrics, "SC"), 0) - SC_LEVELS.get(_extract_value_metric("SC", max_vec), 0)
        severity_distance_SI = SI_LEVELS.get(_m(metrics, "SI"), 0) - SI_LEVELS.get(_extract_value_metric("SI", max_vec), 0)
        severity_distance_SA = SA_LEVELS.get(_m(metrics, "SA"), 0) - SA_LEVELS.get(_extract_value_metric("SA", max_vec), 0)
        severity_distance_CR = CR_LEVELS.get(_m(metrics, "CR"), 0) - CR_LEVELS.get(_extract_value_metric("CR", max_vec), 0)
        severity_distance_IR = IR_LEVELS.get(_m(metrics, "IR"), 0) - IR_LEVELS.get(_extract_value_metric("IR", max_vec), 0)
        severity_distance_AR = AR_LEVELS.get(_m(metrics, "AR"), 0) - AR_LEVELS.get(_extract_value_metric("AR", max_vec), 0)

        distances = [
            severity_distance_AV, severity_distance_PR, severity_distance_UI,
            severity_distance_AC, severity_distance_AT,
            severity_distance_VC, severity_distance_VI, severity_distance_VA,
            severity_distance_SC, severity_distance_SI, severity_distance_SA,
            severity_distance_CR, severity_distance_IR, severity_distance_AR,
        ]
        if all(d >= 0 for d in distances):
            break  # found the right max vector

    current_severity_distance_eq1    = severity_distance_AV + severity_distance_PR + severity_distance_UI
    current_severity_distance_eq2    = severity_distance_AC + severity_distance_AT
    current_severity_distance_eq3eq6 = (severity_distance_VC + severity_distance_VI + severity_distance_VA
                                        + severity_distance_CR + severity_distance_IR + severity_distance_AR)
    current_severity_distance_eq4    = severity_distance_SC + severity_distance_SI + severity_distance_SA

    step = 0.1

    available_distance_eq1    = _distance(value, score_eq1_next)
    available_distance_eq2    = _distance(value, score_eq2_next)
    available_distance_eq3eq6 = _distance(value, score_eq3eq6_next)
    available_distance_eq4    = _distance(value, score_eq4_next)
    available_distance_eq5    = _distance(value, score_eq5_next)

    n_existing_lower = 0
    normalized_severity_eq1 = normalized_severity_eq2 = 0.0
    normalized_severity_eq3eq6 = normalized_severity_eq4 = normalized_severity_eq5 = 0.0

    max_sev_eq1    = MAX_SEVERITY["eq1"][eq1] * step
    max_sev_eq2    = MAX_SEVERITY["eq2"][eq2] * step
    max_sev_eq3eq6 = MAX_SEVERITY["eq3eq6"][eq3][eq6] * step
    max_sev_eq4    = MAX_SEVERITY["eq4"][eq4] * step

    if not math.isnan(available_distance_eq1):
        n_existing_lower += 1
        pct = current_severity_distance_eq1 / max_sev_eq1 if max_sev_eq1 else 0
        normalized_severity_eq1 = available_distance_eq1 * pct

    if not math.isnan(available_distance_eq2):
        n_existing_lower += 1
        pct = current_severity_distance_eq2 / max_sev_eq2 if max_sev_eq2 else 0
        normalized_severity_eq2 = available_distance_eq2 * pct

    if not math.isnan(available_distance_eq3eq6):
        n_existing_lower += 1
        pct = current_severity_distance_eq3eq6 / max_sev_eq3eq6 if max_sev_eq3eq6 else 0
        normalized_severity_eq3eq6 = available_distance_eq3eq6 * pct

    if not math.isnan(available_distance_eq4):
        n_existing_lower += 1
        pct = current_severity_distance_eq4 / max_sev_eq4 if max_sev_eq4 else 0
        normalized_severity_eq4 = available_distance_eq4 * pct

    if not math.isnan(available_distance_eq5):
        n_existing_lower += 1
        # eq5 always contributes 0 percent
        normalized_severity_eq5 = 0.0

    mean_distance = (
        (normalized_severity_eq1 + normalized_severity_eq2 + normalized_severity_eq3eq6
         + normalized_severity_eq4 + normalized_severity_eq5) / n_existing_lower
        if n_existing_lower > 0 else 0.0
    )

    value -= mean_distance
    value = max(0.0, min(10.0, value))
    return _round1(value)


# ── Calculator class ──────────────────────────────────────────────────────────

class CVSS4Calculator:
    """
    CVSS v4.0 Score Calculator — official FIRST.org algorithm.

    In CVSS v4.0 there is a single score that already incorporates the
    Threat (E) metric and Environmental (CR/IR/AR + modified base) metrics.
    There are no separate temporal/environmental scores.
    """

    def calculate(self, metrics: Dict[str, str]) -> Dict[str, Any]:
        """Calculate CVSS v4.0 score from a metrics dict."""
        score = _cvss4_score(metrics)
        mv    = _macro_vector(metrics)

        return {
            # Primary score
            "base_score":    score,
            "base_severity": self._get_severity(score),

            # Macro vector (6-digit EQ string) — useful for debugging
            "severity_vector": mv,

            # Subscores — kept for template/API compatibility
            # In v4.0 there is no separate impact/exploitability subscore
            "impact_subscore":          score,
            "exploitability_subscore":  0.0,

            # Threat / Temporal — v4.0 folds E into the main score
            "threat_score":    None,
            "threat_severity": None,
            "temporal_score":  None,
            "temporal_severity": None,

            # Environmental — v4.0 folds CR/IR/AR + modified metrics into the main score
            "environmental_score":    None,
            "environmental_severity": None,

            # Supplemental metrics (informational only, do not affect score)
            "supplemental": self._get_supplemental(metrics),

            # Full vector string
            "vector_string": self._generate_vector(metrics),
        }

    # ── Private helpers ───────────────────────────────────────────────────────

    def _get_severity(self, score: Optional[float]) -> Optional[str]:
        if score is None:
            return None
        if score == 0.0:
            return "None"
        elif score < 4.0:
            return "Low"
        elif score < 7.0:
            return "Medium"
        elif score < 9.0:
            return "High"
        else:
            return "Critical"

    def _get_supplemental(self, metrics: Dict[str, str]) -> Dict[str, str]:
        """Return supplemental metrics that are set (not X)."""
        mapping = {
            "S":  "Safety",
            "AU": "Automatable",
            "R":  "Recovery",
            "V":  "ValueDensity",
            "RE": "ResponseEffort",
            "U":  "ProviderUrgency",
        }
        return {
            label: metrics[key]
            for key, label in mapping.items()
            if metrics.get(key) and metrics.get(key) != "X"
        }

    def _generate_vector(self, metrics: Dict[str, str]) -> str:
        """Generate the canonical CVSS:4.0/... vector string."""
        parts = ["CVSS:4.0"]

        # Base metrics (always included)
        for key in ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"):
            if metrics.get(key):
                parts.append(f"{key}:{metrics[key]}")

        # Threat
        if metrics.get("E") and metrics["E"] != "X":
            parts.append(f"E:{metrics['E']}")

        # Environmental
        for key in ("CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI",
                    "MVC", "MVI", "MVA", "MSC", "MSI", "MSA"):
            if metrics.get(key) and metrics[key] != "X":
                parts.append(f"{key}:{metrics[key]}")

        # Supplemental
        for key in ("S", "AU", "R", "V", "RE", "U"):
            if metrics.get(key) and metrics[key] != "X":
                parts.append(f"{key}:{metrics[key]}")

        return "/".join(parts)


# ── Quick self-test ───────────────────────────────────────────────────────────
