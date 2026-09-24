"""
Scores must match the official specifications.

Fixed vectors below have expected values from the reference `cvss` library
(Red Hat, implements the FIRST specs); the randomized test compares against the
library directly when it is installed (requirements-dev.txt).
"""
import random

import pytest

from app.cvss_calculators.cvss2 import CVSS2Calculator
from app.cvss_calculators.cvss3 import CVSS3Calculator
from app.cvss_calculators.cvss31 import CVSS31Calculator
from app.cvss_calculators.cvss4 import CVSS4Calculator
from app.routers.convert import parse_vector

CALCS = {"2.0": CVSS2Calculator(), "3.0": CVSS3Calculator(), "3.1": CVSS31Calculator(), "4.0": CVSS4Calculator()}


def _scores(version, vector):
    r = CALCS[version].calculate(parse_vector(vector))
    return r["base_score"], r["temporal_score"], r["environmental_score"]


@pytest.mark.parametrize("vector, base, temporal, env", [
    ("AV:N/AC:L/Au:N/C:C/I:C/A:C", 10.0, None, None),
    ("AV:N/AC:M/Au:N/C:P/I:N/A:N/E:F/RL:OF/RC:C", 4.3, 3.6, None),
    ("AV:L/AC:H/Au:M/C:P/I:N/A:C/E:F/RL:W/RC:UR/CDP:H/TD:M/CR:M/IR:ND/AR:H", 4.4, 3.8, 5.7),
    ("AV:N/AC:L/Au:S/C:C/I:P/A:C/E:F/RL:OF/RC:UC/CDP:LM/TD:H/CR:H/IR:ND/AR:ND", 8.7, 6.5, 7.7),
])
def test_v2_known_vectors(vector, base, temporal, env):
    assert _scores("2.0", f"({vector})") == (base, temporal, env)


@pytest.mark.parametrize("vector, base, temporal, env", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, None, None),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RL:O/RC:C", 10.0, 9.5, None),
    ("CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:N/A:H/RL:O/RC:C/IR:L/MAV:A/MAC:H/MPR:H/MUI:R/MC:H/MI:N/MA:H", 7.1, 6.8, 6.7),
    ("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:H/E:F/RL:O/CR:H/AR:H/MAV:L/MAC:H/MUI:R/MS:U/MC:L/MI:N", 8.2, 7.6, 6.0),
    # float noise: 6.5 * 0.92 must round up to 6.0, not 6.1
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N/RC:U", 6.5, 6.0, None),
])
def test_v3_known_vectors(vector, base, temporal, env):
    assert _scores(vector[5:8], vector) == (base, temporal, env)


@pytest.mark.parametrize("vector, base", [
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3),
    ("CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:A/VC:N/VI:N/VA:N/SC:N/SI:L/SA:L/E:A/AR:H/MAV:L/MAC:H/MPR:N/MUI:A"
     "/MVC:L/MVA:H/MSC:L/MSI:N/MSA:N", 5.7),
    ("CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:A/VC:L/VI:L/VA:L/SC:H/SI:H/SA:N/CR:L/IR:L/AR:L/MAC:H/MAT:N/MPR:H/MUI:N"
     "/MVC:N/MVA:L/MSC:H/MSI:S/MSA:S", 7.0),
])
def test_v4_known_vectors(vector, base):
    assert _scores("4.0", vector)[0] == base


# ── Randomized comparison with the reference implementation ──────────────────

_V2 = {"AV": ["L", "A", "N"], "AC": ["H", "M", "L"], "Au": ["M", "S", "N"], "C": ["N", "P", "C"],
       "I": ["N", "P", "C"], "A": ["N", "P", "C"], "E": ["U", "POC", "F", "H", "ND"],
       "RL": ["OF", "TF", "W", "U", "ND"], "RC": ["UC", "UR", "C", "ND"],
       "CDP": ["N", "L", "LM", "MH", "H", "ND"], "TD": ["N", "L", "M", "H", "ND"],
       "CR": ["L", "M", "H", "ND"], "IR": ["L", "M", "H", "ND"], "AR": ["L", "M", "H", "ND"]}
_V3 = {k: list(v) for k, v in {
    "AV": "NALP", "AC": "LH", "PR": "NLH", "UI": "NR", "S": "UC", "C": "NLH", "I": "NLH", "A": "NLH",
    "E": "XUPFH", "RL": "XOTWU", "RC": "XURC", "CR": "XLMH", "IR": "XLMH", "AR": "XLMH", "MAV": "XNALP",
    "MAC": "XLH", "MPR": "XNLH", "MUI": "XNR", "MS": "XUC", "MC": "XNLH", "MI": "XNLH", "MA": "XNLH"}.items()}
_V4 = {k: list(v) for k, v in {
    "AV": "NALP", "AC": "LH", "AT": "NP", "PR": "NLH", "UI": "NPA", "VC": "HLN", "VI": "HLN", "VA": "HLN",
    "SC": "HLN", "SI": "HLN", "SA": "HLN", "E": "XAPU", "CR": "XHML", "IR": "XHML", "AR": "XHML",
    "MAV": "XNALP", "MAC": "XLH", "MAT": "XNP", "MPR": "XNLH", "MUI": "XNPA", "MVC": "XHLN", "MVI": "XHLN",
    "MVA": "XHLN", "MSC": "XHLN", "MSI": "XSHLN", "MSA": "XSHLN"}.items()}


def _random_vector(space, prefix, rng):
    return prefix + "/".join(f"{k}:{rng.choice(v)}" for k, v in space.items())


@pytest.mark.parametrize("version", ["2.0", "3.0", "3.1", "4.0"])
def test_random_vectors_match_reference(version):
    ref = pytest.importorskip("cvss")
    rng = random.Random(2026)
    for _ in range(400):
        if version == "2.0":
            vector = _random_vector(_V2, "", rng)
            expected = tuple(float(s) if s is not None else None for s in ref.CVSS2(vector).scores())
            got = _scores(version, f"({vector})")
            # the library reports base/temporal/environmental even when not defined
            assert got[0] == expected[0], vector
            assert got[1] in (None, expected[1]) and got[2] in (None, expected[2]), vector
        elif version == "4.0":
            vector = _random_vector(_V4, "CVSS:4.0/", rng)
            assert _scores(version, vector)[0] == float(ref.CVSS4(vector).base_score), vector
        else:
            vector = _random_vector(_V3, f"CVSS:{version}/", rng)
            expected = tuple(float(s) for s in ref.CVSS3(vector).scores())
            got = _scores(version, vector)
            assert got[0] == expected[0], vector
            assert got[1] in (None, expected[1]) and got[2] in (None, expected[2]), vector
