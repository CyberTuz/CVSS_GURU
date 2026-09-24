"""Calculator: plain-language metric help, v4.0 value sets and defaults."""
import re

import pytest
from fastapi.testclient import TestClient

from app.cvss_calculators.descriptions import CVSS_DESCRIPTIONS as D
from main import app


@pytest.fixture(scope="module")
def page():
    return TestClient(app, base_url="https://testserver").get("/").text


def _metrics():
    for version in ("v2", "v3", "v4"):
        for group, metrics in D[version].items():
            for key, meta in metrics.items():
                yield version, group, key, meta


class TestDescriptions:
    def test_every_metric_has_a_question_and_every_value_an_explanation(self):
        for version, group, key, meta in _metrics():
            assert meta.get("question", "").endswith("?"), (version, key)
            for value, info in meta["values"].items():
                assert len(info.get("desc", "")) > 10, (version, key, value)

    def test_v4_values_have_no_formula_weights(self):
        for version, group, key, meta in _metrics():
            if version == "v4":
                assert all("score" not in v for v in meta["values"].values()), key

    def test_v4_subsequent_system_values_follow_the_spec(self):
        for key in ("SC", "SI", "SA"):
            assert list(D["v4"]["base"][key]["values"]) == ["N", "L", "H"]
        assert "S" in D["v4"]["environmental"]["MSI"]["values"]  # Safety, modified only
        assert "S" not in D["v4"]["environmental"]["MSC"]["values"]


class TestRenderedCalculator:
    def test_questions_and_explanations_are_rendered(self, page):
        assert page.count('class="metric-question"') > 50
        assert 'data-explain="Exploitable remotely' in page
        # the selected value's explanation is already there without JavaScript
        assert re.search(r'<p class="metric-explain"[^>]*>Exploitable remotely', page)
        assert 'id="explain-toggle"' in page

    def test_no_weights_shown_for_v4(self, page):
        v4 = page[page.index('id="calc-v4"'):page.index('id="converter-section"')]
        v31 = page[page.index('id="calc-v31"'):page.index('id="calc-v4"')]
        assert "metric-weight" not in v4
        assert "metric-weight" in v31

    def test_modified_metrics_can_be_reset_to_not_defined(self, page):
        for name in ("v31_MAV", "v4_MAV", "v4_MSI"):
            assert re.search(rf'name="{name}" value="X"[^>]*checked', page), name

    def test_v4_defaults_are_valid_values(self, page):
        for key in ("SC", "SI", "SA"):
            assert f'name="v4_{key}" value="S"' not in page
            assert re.search(rf'name="v4_{key}" value="N"[^>]*checked', page)


class TestV4Vectors:
    def test_default_render_has_no_invalid_subsequent_values(self):
        client = TestClient(app, base_url="https://testserver")
        r = client.post("/api/cvss4/render", data={"v4_AV": "N", "v4_AC": "L", "v4_AT": "N", "v4_PR": "N",
                                                   "v4_UI": "N", "v4_VC": "H", "v4_VI": "H", "v4_VA": "H"})
        assert "SC:N/SI:N/SA:N" in r.text and "SC:S" not in r.text

    def test_validator_follows_the_spec(self):
        from app.routers.convert import validate_vector

        base = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H"
        assert validate_vector(base + "/SC:N/SI:N/SA:N/U:Red", "4.0")[0]
        assert not validate_vector(base + "/SC:S/SI:N/SA:N", "4.0")[0]
