"""
Unit tests for CVSS v4.0 Calculator.
Uses the official FIRST.org algorithm (lookup table + interpolation).
Reference scores verified against https://www.first.org/cvss/calculator/cvsscalc40
"""
import pytest
from app.cvss_calculators.cvss4 import CVSS4Calculator, _macro_vector


@pytest.fixture
def calc():
    return CVSS4Calculator()


BASE_MAX = {
    "AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
    "VC": "H", "VI": "H", "VA": "H", "SC": "H", "SI": "H", "SA": "H",
}
BASE_NO_SUBSEQUENT = {
    "AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
    "VC": "H", "VI": "H", "VA": "H", "SC": "N", "SI": "N", "SA": "N",
}
BASE_ZERO = {
    "AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
    "VC": "N", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N",
}


# ==================== Reference scores (FIRST.org) ====================

class TestCVSS4ReferenceScores:
    """Scores verified against the official FIRST.org calculator."""

    def test_all_high_is_10(self, calc):
        result = calc.calculate(BASE_MAX)
        assert result["base_score"] == 10.0
        assert result["base_severity"] == "Critical"

    def test_no_subsequent_impact_is_9_3(self, calc):
        result = calc.calculate(BASE_NO_SUBSEQUENT)
        assert result["base_score"] == 9.3
        assert result["base_severity"] == "Critical"

    def test_all_none_is_zero(self, calc):
        result = calc.calculate(BASE_ZERO)
        assert result["base_score"] == 0.0
        assert result["base_severity"] == "None"

    def test_score_in_valid_range(self, calc):
        result = calc.calculate({
            "AV": "A", "AC": "H", "AT": "P", "PR": "L", "UI": "P",
            "VC": "L", "VI": "N", "VA": "L", "SC": "N", "SI": "N", "SA": "N",
        })
        assert 0.0 <= result["base_score"] <= 10.0

    def test_score_rounded_to_one_decimal(self, calc):
        result = calc.calculate(BASE_MAX)
        assert result["base_score"] == round(result["base_score"], 1)


# ==================== Macro vector ====================

class TestCVSS4MacroVector:
    def test_all_high_macro_vector(self):
        mv = _macro_vector(BASE_MAX)
        assert len(mv) == 6
        # EQ1=0 (AV:N+PR:N+UI:N), EQ2=0 (AC:L+AT:N), EQ3=0 (VC:H+VI:H),
        # EQ4=1 (SC:H/SI:H/SA:H but no MSI:S/MSA:S), EQ5=0 (E:X→A), EQ6=0 (CR:H+VC:H default)
        assert mv == "000100"

    def test_all_none_macro_vector(self):
        mv = _macro_vector(BASE_ZERO)
        # EQ3=2 (no H impact), EQ4=2 (no H subsequent), EQ6=1 (no CR+VC combo)
        assert mv[2] == "2"  # EQ3
        assert mv[3] == "2"  # EQ4

    def test_macro_vector_is_6_digits(self):
        mv = _macro_vector(BASE_NO_SUBSEQUENT)
        assert len(mv) == 6
        assert mv.isdigit()

    def test_severity_vector_in_result(self, calc):
        result = calc.calculate(BASE_MAX)
        assert result["severity_vector"] == "000100"


# ==================== Score ordering ====================

class TestCVSS4ScoreOrdering:
    def test_network_higher_than_physical(self, calc):
        net = calc.calculate({
            "AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
            "VC": "H", "VI": "H", "VA": "H", "SC": "N", "SI": "N", "SA": "N",
        })
        phys = calc.calculate({
            "AV": "P", "AC": "H", "AT": "P", "PR": "H", "UI": "A",
            "VC": "H", "VI": "H", "VA": "H", "SC": "N", "SI": "N", "SA": "N",
        })
        assert net["base_score"] > phys["base_score"]

    def test_high_impact_higher_than_low(self, calc):
        high = calc.calculate({
            "AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
            "VC": "H", "VI": "H", "VA": "H", "SC": "N", "SI": "N", "SA": "N",
        })
        low = calc.calculate({
            "AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
            "VC": "L", "VI": "L", "VA": "L", "SC": "N", "SI": "N", "SA": "N",
        })
        assert high["base_score"] > low["base_score"]

    def test_subsequent_impact_increases_score(self, calc):
        no_sub = calc.calculate(BASE_NO_SUBSEQUENT)
        with_sub = calc.calculate(BASE_MAX)
        assert with_sub["base_score"] >= no_sub["base_score"]


# ==================== Threat / Temporal ====================

class TestCVSS4ThreatScore:
    def test_threat_none_when_e_is_x(self, calc):
        """In v4.0 the E metric is folded into the main score — no separate threat score."""
        result = calc.calculate({**BASE_MAX, "E": "X"})
        assert result["threat_score"] is None
        assert result["temporal_score"] is None

    def test_temporal_score_always_none(self, calc):
        """v4.0 has no separate temporal score."""
        result = calc.calculate({**BASE_MAX, "E": "A"})
        assert result["temporal_score"] is None
        assert result["threat_score"] is None

    def test_e_u_reduces_score_vs_e_a(self, calc):
        """E:U (Unreported) should give a lower score than E:A (Attacked)."""
        attacked  = calc.calculate({**BASE_NO_SUBSEQUENT, "E": "A"})
        unreported = calc.calculate({**BASE_NO_SUBSEQUENT, "E": "U"})
        assert unreported["base_score"] < attacked["base_score"]


# ==================== Environmental ====================

class TestCVSS4EnvironmentalScore:
    def test_environmental_none_without_env_metrics(self, calc):
        """v4.0 folds env into main score — no separate environmental score."""
        result = calc.calculate(BASE_MAX)
        assert result["environmental_score"] is None

    def test_environmental_always_none(self, calc):
        """Even with CR/IR/AR set, environmental_score is None (folded into base)."""
        result = calc.calculate({**BASE_MAX, "CR": "H", "IR": "H", "AR": "H"})
        assert result["environmental_score"] is None

    def test_modified_av_reduces_score(self, calc):
        """MAV:P (Physical) should reduce score vs default AV:N."""
        base = calc.calculate(BASE_NO_SUBSEQUENT)
        modified = calc.calculate({**BASE_NO_SUBSEQUENT, "MAV": "P"})
        assert modified["base_score"] < base["base_score"]


# ==================== Supplemental Metrics ====================

class TestCVSS4Supplemental:
    def test_supplemental_empty_when_all_x(self, calc):
        result = calc.calculate({
            **BASE_MAX,
            "S": "X", "AU": "X", "R": "X", "V": "X", "RE": "X", "U": "X",
        })
        assert result["supplemental"] == {}

    def test_supplemental_safety_present(self, calc):
        result = calc.calculate({**BASE_MAX, "S": "P"})
        assert result["supplemental"].get("Safety") == "P"

    def test_supplemental_automatable_present(self, calc):
        result = calc.calculate({**BASE_MAX, "AU": "Y"})
        assert result["supplemental"].get("Automatable") == "Y"

    def test_supplemental_multiple_values(self, calc):
        result = calc.calculate({**BASE_MAX, "S": "P", "AU": "Y", "R": "A"})
        assert result["supplemental"]["Safety"] == "P"
        assert result["supplemental"]["Automatable"] == "Y"
        assert result["supplemental"]["Recovery"] == "A"

    def test_supplemental_does_not_affect_score(self, calc):
        without = calc.calculate(BASE_MAX)
        with_supp = calc.calculate({**BASE_MAX, "S": "P", "AU": "Y"})
        assert without["base_score"] == with_supp["base_score"]


# ==================== Vector String ====================

class TestCVSS4VectorString:
    def test_vector_starts_with_cvss40(self, calc):
        result = calc.calculate(BASE_MAX)
        assert result["vector_string"].startswith("CVSS:4.0/")

    def test_base_metrics_in_vector(self, calc):
        result = calc.calculate(BASE_MAX)
        v = result["vector_string"]
        for m in ("AV:", "AC:", "AT:", "PR:", "UI:", "VC:", "VI:", "VA:"):
            assert m in v

    def test_x_values_excluded_from_optional(self, calc):
        result = calc.calculate({**BASE_MAX, "E": "X", "CR": "X"})
        v = result["vector_string"]
        assert "E:X" not in v
        assert "CR:X" not in v

    def test_supplemental_in_vector(self, calc):
        result = calc.calculate({**BASE_MAX, "AU": "Y"})
        assert "AU:Y" in result["vector_string"]

    def test_threat_metric_in_vector_when_set(self, calc):
        result = calc.calculate({**BASE_MAX, "E": "P"})
        assert "E:P" in result["vector_string"]
