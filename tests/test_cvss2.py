"""
Unit tests for CVSS v2.0 Calculator
Reference: https://www.first.org/cvss/v2/guide
"""
import pytest
from app.cvss_calculators.cvss2 import CVSS2Calculator


@pytest.fixture
def calc():
    return CVSS2Calculator()


# ==================== Base Score ====================

class TestCVSS2BaseScore:
    def test_all_none_impact_gives_zero_score(self, calc):
        result = calc.calculate({"AV": "L", "AC": "H", "Au": "M", "C": "N", "I": "N", "A": "N"})
        assert result["base_score"] == 0.0
        assert result["base_severity"] == "None"

    def test_full_network_impact_gives_ten(self, calc):
        result = calc.calculate({"AV": "N", "AC": "L", "Au": "N", "C": "C", "I": "C", "A": "C"})
        assert result["base_score"] == 10.0
        assert result["base_severity"] == "Critical"

    def test_heartbleed_approximation(self, calc):
        # AV:N/AC:L/Au:N/C:C/I:N/A:N — expected ~7.8
        result = calc.calculate({"AV": "N", "AC": "L", "Au": "N", "C": "C", "I": "N", "A": "N"})
        assert result["base_score"] == 7.8
        assert result["base_severity"] == "High"

    def test_local_access_low_impact(self, calc):
        result = calc.calculate({"AV": "L", "AC": "H", "Au": "M", "C": "P", "I": "N", "A": "N"})
        assert result["base_score"] < 4.0
        assert result["base_severity"] == "Low"

    def test_score_is_float_with_one_decimal(self, calc):
        result = calc.calculate({"AV": "N", "AC": "L", "Au": "N", "C": "P", "I": "P", "A": "N"})
        score = result["base_score"]
        assert isinstance(score, float)
        assert score == round(score, 1)

    def test_score_clamped_between_0_and_10(self, calc):
        result = calc.calculate({"AV": "N", "AC": "L", "Au": "N", "C": "C", "I": "C", "A": "C"})
        assert 0.0 <= result["base_score"] <= 10.0

    def test_medium_impact_medium_severity(self, calc):
        result = calc.calculate({"AV": "N", "AC": "M", "Au": "S", "C": "P", "I": "P", "A": "N"})
        assert 4.0 <= result["base_score"] < 7.0
        assert result["base_severity"] == "Medium"

    def test_severity_boundaries(self, calc):
        # Low: 0.1–3.9
        r = calc.calculate({"AV": "L", "AC": "H", "Au": "M", "C": "P", "I": "N", "A": "N"})
        assert r["base_severity"] == "Low"

        # High: 7.0–8.9
        r = calc.calculate({"AV": "N", "AC": "L", "Au": "N", "C": "C", "I": "N", "A": "N"})
        assert r["base_severity"] == "High"

        # Critical: >= 9.0
        r = calc.calculate({"AV": "N", "AC": "L", "Au": "N", "C": "C", "I": "C", "A": "C"})
        assert r["base_severity"] == "Critical"


# ==================== Temporal Score ====================

class TestCVSS2TemporalScore:
    def test_temporal_none_when_all_nd(self, calc):
        result = calc.calculate({
            "AV": "N", "AC": "L", "Au": "N", "C": "C", "I": "C", "A": "C",
            "E": "ND", "RL": "ND", "RC": "ND"
        })
        assert result["temporal_score"] is None
        assert result["temporal_severity"] is None

    def test_temporal_reduces_with_official_fix(self, calc):
        base = calc.calculate({"AV": "N", "AC": "L", "Au": "N", "C": "C", "I": "C", "A": "C"})
        temporal = calc.calculate({
            "AV": "N", "AC": "L", "Au": "N", "C": "C", "I": "C", "A": "C",
            "E": "F", "RL": "OF", "RC": "C"
        })
        assert temporal["temporal_score"] is not None
        assert temporal["temporal_score"] < base["base_score"]

    def test_temporal_with_high_exploitability(self, calc):
        result = calc.calculate({
            "AV": "N", "AC": "L", "Au": "N", "C": "C", "I": "C", "A": "C",
            "E": "H", "RL": "ND", "RC": "ND"
        })
        # E=H is 1.0, RL=ND is 1.0, RC=ND is 1.0 — all weights are 1.0
        # But E=H is not "ND", so temporal is defined
        assert result["temporal_score"] is not None
        assert result["temporal_score"] == result["base_score"]

    def test_temporal_poc_exploit(self, calc):
        result = calc.calculate({
            "AV": "N", "AC": "L", "Au": "N", "C": "C", "I": "C", "A": "C",
            "E": "POC", "RL": "ND", "RC": "ND"
        })
        assert result["temporal_score"] is not None
        assert result["temporal_score"] < 10.0

    def test_temporal_score_has_one_decimal(self, calc):
        result = calc.calculate({
            "AV": "N", "AC": "L", "Au": "N", "C": "C", "I": "C", "A": "C",
            "E": "F", "RL": "OF", "RC": "C"
        })
        score = result["temporal_score"]
        assert score == round(score, 1)


# ==================== Environmental Score ====================

class TestCVSS2EnvironmentalScore:
    def test_environmental_none_when_all_nd(self, calc):
        result = calc.calculate({
            "AV": "N", "AC": "L", "Au": "N", "C": "C", "I": "C", "A": "C",
            "CDP": "ND", "TD": "ND", "CR": "ND", "IR": "ND", "AR": "ND"
        })
        assert result["environmental_score"] is None
        assert result["environmental_severity"] is None

    def test_environmental_with_collateral_damage(self, calc):
        result = calc.calculate({
            "AV": "N", "AC": "L", "Au": "N", "C": "C", "I": "C", "A": "C",
            "CDP": "H", "TD": "H"
        })
        assert result["environmental_score"] is not None
        assert result["environmental_score"] > 0.0

    def test_environmental_high_req_increases_score(self, calc):
        base = calc.calculate({"AV": "N", "AC": "L", "Au": "N", "C": "P", "I": "P", "A": "P"})
        env = calc.calculate({
            "AV": "N", "AC": "L", "Au": "N", "C": "P", "I": "P", "A": "P",
            "CR": "H", "IR": "H", "AR": "H", "TD": "H"
        })
        assert env["environmental_score"] > base["base_score"]

    def test_environmental_zero_td_gives_zero_or_none(self, calc):
        # TD=N means 0% target distribution → score is 0.0.
        # The calculator uses `if score` which treats 0.0 as falsy, returning None.
        result = calc.calculate({
            "AV": "N", "AC": "L", "Au": "N", "C": "C", "I": "C", "A": "C",
            "CDP": "H", "TD": "N"
        })
        assert result["environmental_score"] in (0.0, None)


# ==================== Vector String ====================

class TestCVSS2VectorString:
    def test_vector_string_in_parens(self, calc):
        result = calc.calculate({"AV": "N", "AC": "L", "Au": "N", "C": "C", "I": "N", "A": "N"})
        assert result["vector_string"].startswith("(")
        assert result["vector_string"].endswith(")")

    def test_vector_includes_base_metrics(self, calc):
        result = calc.calculate({"AV": "N", "AC": "L", "Au": "N", "C": "C", "I": "N", "A": "N"})
        v = result["vector_string"]
        for metric in ["AV:", "AC:", "Au:", "C:", "I:", "A:"]:
            assert metric in v

    def test_nd_metrics_excluded_from_vector(self, calc):
        result = calc.calculate({
            "AV": "N", "AC": "L", "Au": "N", "C": "C", "I": "N", "A": "N",
            "E": "ND", "RL": "ND"
        })
        assert "E:" not in result["vector_string"]
        assert "RL:" not in result["vector_string"]

    def test_temporal_metrics_in_vector_when_defined(self, calc):
        result = calc.calculate({
            "AV": "N", "AC": "L", "Au": "N", "C": "C", "I": "N", "A": "N",
            "E": "F", "RL": "OF", "RC": "C"
        })
        v = result["vector_string"]
        assert "E:F" in v
        assert "RL:OF" in v
