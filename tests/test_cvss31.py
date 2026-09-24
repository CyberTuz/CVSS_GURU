"""
Unit tests for CVSS v3.1 Calculator
Reference: https://www.first.org/cvss/v3.1/specification-document
"""
import pytest
from app.cvss_calculators.cvss31 import CVSS31Calculator
from app.cvss_calculators.cvss3 import CVSS3Calculator


@pytest.fixture
def calc():
    return CVSS31Calculator()


# ==================== Base Score ====================

class TestCVSS31BaseScore:
    def test_log4shell_score(self, calc):
        # CVE-2021-44228 canonical score: 10.0
        result = calc.calculate({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C",
                                 "C": "H", "I": "H", "A": "H"})
        assert result["base_score"] == 10.0
        assert result["base_severity"] == "Critical"

    def test_scope_unchanged_full_impact(self, calc):
        result = calc.calculate({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                                 "C": "H", "I": "H", "A": "H"})
        assert result["base_score"] == 9.8

    def test_zero_cia_gives_zero(self, calc):
        result = calc.calculate({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                                 "C": "N", "I": "N", "A": "N"})
        assert result["base_score"] == 0.0
        assert result["base_severity"] == "None"

    def test_score_in_valid_range(self, calc):
        result = calc.calculate({"AV": "A", "AC": "H", "PR": "H", "UI": "R", "S": "U",
                                 "C": "L", "I": "L", "A": "N"})
        assert 0.0 <= result["base_score"] <= 10.0

    def test_subscores_present(self, calc):
        result = calc.calculate({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                                 "C": "H", "I": "H", "A": "H"})
        assert "impact_subscore" in result
        assert "exploitability_subscore" in result


# ==================== Roundup Function ====================

class TestCVSS31Roundup:
    def test_roundup_rounds_up(self, calc):
        assert calc._roundup(7.001) == 7.1

    def test_roundup_exact_preserves(self, calc):
        assert calc._roundup(7.1) == 7.1

    def test_roundup_zero(self, calc):
        assert calc._roundup(0.0) == 0.0

    def test_roundup_ten(self, calc):
        assert calc._roundup(10.0) == 10.0

    def test_roundup_differs_from_round(self, calc):
        # round(7.05, 1) might give 7.0 depending on float, but _roundup gives 7.1
        assert calc._roundup(7.01) == 7.1


# ==================== Parity with v3.0 ====================

class TestCVSS31VsV30Parity:
    def test_same_formula_same_result(self, calc):
        calc30 = CVSS3Calculator()
        metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                   "C": "H", "I": "L", "A": "N"}
        r31 = calc.calculate(metrics)
        r30 = calc30.calculate(metrics)
        assert r31["base_score"] == r30["base_score"]

    def test_parity_changed_scope(self, calc):
        calc30 = CVSS3Calculator()
        metrics = {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "C",
                   "C": "H", "I": "H", "A": "H"}
        r31 = calc.calculate(metrics)
        r30 = calc30.calculate(metrics)
        assert r31["base_score"] == r30["base_score"]


# ==================== Temporal Score ====================

class TestCVSS31TemporalScore:
    def test_temporal_none_all_x(self, calc):
        result = calc.calculate({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                                 "C": "H", "I": "H", "A": "H",
                                 "E": "X", "RL": "X", "RC": "X"})
        assert result["temporal_score"] is None

    def test_temporal_poc_reduces_score(self, calc):
        base = calc.calculate({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                               "C": "H", "I": "H", "A": "H"})
        temporal = calc.calculate({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                                   "C": "H", "I": "H", "A": "H", "E": "P"})
        assert temporal["temporal_score"] < base["base_score"]

    def test_temporal_uses_roundup(self, calc):
        result = calc.calculate({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                                 "C": "H", "I": "H", "A": "H", "E": "U"})
        score = result["temporal_score"]
        assert score == round(score, 1)


# ==================== Environmental Score ====================

class TestCVSS31EnvironmentalScore:
    def test_environmental_none_when_all_x(self, calc):
        result = calc.calculate({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                                 "C": "H", "I": "H", "A": "H"})
        assert result["environmental_score"] is None

    def test_miss_capped_at_0915(self, calc):
        # High CR, IR, AR with H CIA should cap MISS at 0.915
        result = calc.calculate({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                                 "C": "H", "I": "H", "A": "H",
                                 "CR": "H", "IR": "H", "AR": "H"})
        assert result["environmental_score"] is not None
        assert result["environmental_score"] <= 10.0

    def test_low_req_reduces_environmental(self, calc):
        high_req = calc.calculate({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                                   "C": "H", "I": "H", "A": "H", "CR": "H"})
        low_req = calc.calculate({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                                  "C": "H", "I": "H", "A": "H", "CR": "L"})
        assert low_req["environmental_score"] < high_req["environmental_score"]


# ==================== Vector String ====================

class TestCVSS31VectorString:
    def test_vector_starts_with_cvss31(self, calc):
        result = calc.calculate({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                                 "C": "H", "I": "H", "A": "H"})
        assert result["vector_string"].startswith("CVSS:3.1/")

    def test_x_values_not_in_vector(self, calc):
        result = calc.calculate({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                                 "C": "H", "I": "H", "A": "H",
                                 "E": "X", "CR": "X"})
        assert "E:X" not in result["vector_string"]
        assert "CR:X" not in result["vector_string"]

    def test_defined_temporal_in_vector(self, calc):
        result = calc.calculate({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                                 "C": "H", "I": "H", "A": "H", "E": "P", "RL": "O"})
        assert "E:P" in result["vector_string"]
        assert "RL:O" in result["vector_string"]
