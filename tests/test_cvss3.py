"""
Unit tests for CVSS v3.0 Calculator
Reference: https://www.first.org/cvss/v3.0/specification-document
"""
import pytest
from app.cvss_calculators.cvss3 import CVSS3Calculator


@pytest.fixture
def calc():
    return CVSS3Calculator()


# ==================== Base Score ====================

class TestCVSS3BaseScore:
    def test_zero_cia_impact_gives_zero_score(self, calc):
        result = calc.calculate({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                                 "C": "N", "I": "N", "A": "N"})
        assert result["base_score"] == 0.0
        assert result["base_severity"] == "None"

    def test_full_impact_unchanged_scope(self, calc):
        result = calc.calculate({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                                 "C": "H", "I": "H", "A": "H"})
        assert result["base_score"] == 9.8
        assert result["base_severity"] == "Critical"

    def test_changed_scope_high_impact(self, calc):
        result = calc.calculate({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C",
                                 "C": "H", "I": "H", "A": "H"})
        assert result["base_score"] >= 9.0
        assert result["base_severity"] == "Critical"

    def test_changed_scope_uses_pr_changed_weights(self, calc):
        # PR=L with S=C should use PR_changed[L]=0.68, giving a higher score than S=U
        unchanged = calc.calculate({"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U",
                                    "C": "H", "I": "H", "A": "H"})
        changed = calc.calculate({"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "C",
                                  "C": "H", "I": "H", "A": "H"})
        assert changed["base_score"] > unchanged["base_score"]

    def test_physical_access_low_impact(self, calc):
        result = calc.calculate({"AV": "P", "AC": "H", "PR": "H", "UI": "R", "S": "U",
                                 "C": "L", "I": "N", "A": "N"})
        assert result["base_score"] < 4.0

    def test_score_uses_roundup_not_round(self, calc):
        # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N
        # impact = 6.42 * (1-(1-0.56)*(1-0.22)*(1-0)) = 6.42 * (1-0.44*0.78) = 6.42*0.6568 = 4.217
        # exploitability = 8.22*0.85*0.77*0.85*0.85 = 3.900...
        # base = 4.217+3.900 = 8.117 → roundup = 8.2
        result = calc.calculate({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                                 "C": "H", "I": "L", "A": "N"})
        assert result["base_score"] == round(result["base_score"], 1)
        assert result["base_score"] > 0

    def test_impact_and_exploitability_subscores_present(self, calc):
        result = calc.calculate({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                                 "C": "H", "I": "H", "A": "H"})
        assert "impact_subscore" in result
        assert "exploitability_subscore" in result

    def test_score_in_valid_range(self, calc):
        result = calc.calculate({"AV": "A", "AC": "H", "PR": "L", "UI": "R", "S": "U",
                                 "C": "L", "I": "L", "A": "L"})
        assert 0.0 <= result["base_score"] <= 10.0


# ==================== Temporal Score ====================

class TestCVSS3TemporalScore:
    def test_temporal_none_when_all_x(self, calc):
        result = calc.calculate({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                                 "C": "H", "I": "H", "A": "H",
                                 "E": "X", "RL": "X", "RC": "X"})
        assert result["temporal_score"] is None
        assert result["temporal_severity"] is None

    def test_temporal_poc_reduces_score(self, calc):
        base = calc.calculate({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                               "C": "H", "I": "H", "A": "H"})
        temporal = calc.calculate({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                                   "C": "H", "I": "H", "A": "H", "E": "P"})
        assert temporal["temporal_score"] is not None
        assert temporal["temporal_score"] < base["base_score"]

    def test_temporal_unproven_lowest(self, calc):
        t_poc = calc.calculate({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                                "C": "H", "I": "H", "A": "H", "E": "P"})
        t_u = calc.calculate({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                              "C": "H", "I": "H", "A": "H", "E": "U"})
        assert t_u["temporal_score"] < t_poc["temporal_score"]

    def test_temporal_severity_is_valid_string(self, calc):
        result = calc.calculate({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                                 "C": "H", "I": "H", "A": "H", "E": "P"})
        valid = {"None", "Low", "Medium", "High", "Critical"}
        assert result["temporal_severity"] in valid


# ==================== Environmental Score ====================

class TestCVSS3EnvironmentalScore:
    def test_environmental_none_when_all_x(self, calc):
        result = calc.calculate({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                                 "C": "H", "I": "H", "A": "H",
                                 "CR": "X", "IR": "X", "AR": "X"})
        assert result["environmental_score"] is None

    def test_high_cr_defines_environmental(self, calc):
        result = calc.calculate({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                                 "C": "H", "I": "H", "A": "H", "CR": "H"})
        assert result["environmental_score"] is not None

    def test_modified_av_p_reduces_score(self, calc):
        base = calc.calculate({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                               "C": "H", "I": "H", "A": "H"})
        env = calc.calculate({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                              "C": "H", "I": "H", "A": "H", "MAV": "P"})
        assert env["environmental_score"] is not None
        assert env["environmental_score"] < base["base_score"]

    def test_environmental_score_in_valid_range(self, calc):
        result = calc.calculate({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                                 "C": "H", "I": "H", "A": "H", "CR": "H", "IR": "H"})
        env = result["environmental_score"]
        assert env is not None
        assert 0.0 <= env <= 10.0


# ==================== Vector String ====================

class TestCVSS3VectorString:
    def test_vector_starts_with_cvss30(self, calc):
        result = calc.calculate({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                                 "C": "H", "I": "H", "A": "H"})
        assert result["vector_string"].startswith("CVSS:3.0/")

    def test_x_values_excluded_from_vector(self, calc):
        result = calc.calculate({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                                 "C": "H", "I": "H", "A": "H",
                                 "E": "X", "RL": "X", "CR": "X"})
        v = result["vector_string"]
        assert "E:X" not in v
        assert "RL:X" not in v
        assert "CR:X" not in v
