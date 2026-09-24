"""
Unit tests for CVSS conversion logic.
Tests parse_vector, validate_vector, and convert_metrics functions.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.routers.convert import parse_vector, validate_vector, convert_metrics


# ==================== parse_vector ====================

class TestParseVector:
    def test_parse_cvss31_with_prefix(self):
        result = parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert result == {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                          "C": "H", "I": "H", "A": "H"}

    def test_parse_cvss30_with_prefix(self):
        result = parse_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert result == {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                          "C": "H", "I": "H", "A": "H"}

    def test_parse_cvss40_with_prefix(self):
        result = parse_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")
        assert result["AV"] == "N"
        assert result["VC"] == "H"
        assert result["SA"] == "H"

    def test_parse_cvss2_with_parens(self):
        result = parse_vector("(AV:N/AC:L/Au:N/C:C/I:C/A:C)")
        assert result == {"AV": "N", "AC": "L", "Au": "N", "C": "C", "I": "C", "A": "C"}

    def test_parse_invalid_returns_empty(self):
        result = parse_vector("INVALID")
        assert result == {}

    def test_parse_preserves_all_pairs(self):
        result = parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O")
        assert result["E"] == "P"
        assert result["RL"] == "O"


# ==================== validate_vector ====================

class TestValidateVector:
    def test_valid_cvss31_passes(self):
        is_valid, msg = validate_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "3.1")
        assert is_valid is True
        assert msg == ""

    def test_valid_cvss2_passes(self):
        is_valid, msg = validate_vector("(AV:N/AC:L/Au:N/C:C/I:C/A:C)", "2.0")
        assert is_valid is True

    def test_invalid_metric_value_fails(self):
        is_valid, msg = validate_vector("CVSS:3.1/AV:INVALID/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "3.1")
        assert is_valid is False
        assert "AV" in msg

    def test_empty_vector_fails(self):
        is_valid, msg = validate_vector("", "3.1")
        assert is_valid is False
        assert msg != ""

    def test_version_auto_detected_from_prefix(self):
        # Prefix says 4.0, but version arg says 3.1 — prefix wins
        is_valid, _ = validate_vector(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
            "3.1"
        )
        assert is_valid is True

    def test_valid_cvss40_passes(self):
        is_valid, msg = validate_vector(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
            "4.0"
        )
        assert is_valid is True


# ==================== convert_metrics ====================

class TestConvertMetrics:
    def test_v2_to_v31_maps_au_s_to_pr_l(self):
        metrics = {"AV": "N", "AC": "L", "Au": "S", "C": "C", "I": "C", "A": "C"}
        result = convert_metrics(metrics, "2.0", "3.1")
        assert result["PR"] == "L"

    def test_v2_to_v31_maps_au_n_to_pr_n(self):
        metrics = {"AV": "N", "AC": "L", "Au": "N", "C": "C", "I": "C", "A": "C"}
        result = convert_metrics(metrics, "2.0", "3.1")
        assert result["PR"] == "N"

    def test_v2_to_v31_maps_cia_p_to_l(self):
        metrics = {"AV": "N", "AC": "L", "Au": "N", "C": "P", "I": "N", "A": "C"}
        result = convert_metrics(metrics, "2.0", "3.1")
        assert result["C"] == "L"
        assert result["I"] == "N"
        assert result["A"] == "H"

    def test_v31_to_v2_maps_pr_h_to_au_m(self):
        metrics = {"AV": "N", "AC": "L", "PR": "H", "UI": "N", "S": "U",
                   "C": "H", "I": "H", "A": "H"}
        result = convert_metrics(metrics, "3.1", "2.0")
        assert result["Au"] == "M"

    def test_v31_to_v2_maps_cia_h_to_c(self):
        metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                   "C": "H", "I": "L", "A": "N"}
        result = convert_metrics(metrics, "3.1", "2.0")
        assert result["C"] == "C"
        assert result["I"] == "P"
        assert result["A"] == "N"

    def test_v31_to_v40_maps_ui_r_to_a(self):
        metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U",
                   "C": "H", "I": "H", "A": "H"}
        result = convert_metrics(metrics, "3.1", "4.0")
        assert result["UI"] == "A"

    def test_v31_to_v40_changed_scope_maps_to_high_subsequent(self):
        metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C",
                   "C": "H", "I": "H", "A": "H"}
        result = convert_metrics(metrics, "3.1", "4.0")
        assert result["SC"] == "H"
        assert result["SI"] == "H"
        assert result["SA"] == "H"

    def test_v40_to_v31_high_subsequent_maps_to_scope_changed(self):
        metrics = {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
                   "VC": "H", "VI": "H", "VA": "H", "SC": "H", "SI": "N", "SA": "N"}
        result = convert_metrics(metrics, "4.0", "3.1")
        assert result["S"] == "C"

    def test_v40_to_v31_no_subsequent_maps_to_scope_unchanged(self):
        metrics = {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
                   "VC": "H", "VI": "H", "VA": "H", "SC": "N", "SI": "N", "SA": "N"}
        result = convert_metrics(metrics, "4.0", "3.1")
        assert result["S"] == "U"

    def test_v30_to_v31_identical(self):
        metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                   "C": "H", "I": "H", "A": "H"}
        result = convert_metrics(metrics, "3.0", "3.1")
        assert result == metrics

    def test_defaults_added_for_missing_fields(self):
        result = convert_metrics({"AV": "N"}, "2.0", "3.1")
        for key in ["AC", "PR", "UI", "S", "C", "I", "A"]:
            assert key in result
