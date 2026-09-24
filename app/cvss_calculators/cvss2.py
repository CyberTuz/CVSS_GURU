"""
CVSS v2.0 Calculator
Reference: https://www.first.org/cvss/v2/guide (section 3.2, equations)
"""

from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Dict, Optional

BASE_ORDER = ["AV", "AC", "Au", "C", "I", "A"]
TEMPORAL_ORDER = ["E", "RL", "RC"]
ENV_ORDER = ["CDP", "TD", "CR", "IR", "AR"]


def _round1(value: float) -> float:
    """round_to_1_decimal from the spec (half up; Python's round() is half-even)."""
    return float(Decimal(value + 1e-9).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))


class CVSS2Calculator:
    """CVSS v2.0 Score Calculator"""

    def __init__(self):
        # Base metric weights
        self.weights = {
            "AV": {"L": 0.395, "A": 0.646, "N": 1.0},
            "AC": {"H": 0.35, "M": 0.61, "L": 0.71},
            "Au": {"M": 0.45, "S": 0.56, "N": 0.704},
            "CIA": {"N": 0.0, "P": 0.275, "C": 0.660},
        }
        # Temporal metric weights ("ND" = Not Defined = no adjustment)
        self.temporal_weights = {
            "E": {"U": 0.85, "POC": 0.9, "F": 0.95, "H": 1.0, "ND": 1.0},
            "RL": {"OF": 0.87, "TF": 0.90, "W": 0.95, "U": 1.0, "ND": 1.0},
            "RC": {"UC": 0.90, "UR": 0.95, "C": 1.0, "ND": 1.0},
        }
        # Environmental metric weights
        self.env_weights = {
            "CDP": {"N": 0.0, "L": 0.1, "LM": 0.3, "MH": 0.4, "H": 0.5, "ND": 0.0},
            "TD": {"N": 0.0, "L": 0.25, "M": 0.75, "H": 1.0, "ND": 1.0},
            "Req": {"L": 0.5, "M": 1.0, "H": 1.51, "ND": 1.0},
        }

    def calculate(self, metrics: Dict[str, str]) -> Dict[str, Any]:
        """
        Calculate CVSS v2.0 scores from metrics.

        Required base metrics: AV, AC, Au, C, I, A
        Optional temporal: E, RL, RC
        Optional environmental: CDP, TD, CR, IR, AR
        Temporal/environmental scores are None when none of their metrics is defined.
        """
        c, i, a = (self.weights["CIA"].get(metrics.get(k, "N"), 0.0) for k in ("C", "I", "A"))
        impact = 10.41 * (1 - (1 - c) * (1 - i) * (1 - a))
        exploitability = self._exploitability(metrics)
        base_score = self._base(impact, exploitability)

        temporal_score = None
        if any(metrics.get(k, "ND") != "ND" for k in TEMPORAL_ORDER):
            temporal_score = _round1(base_score * self._temporal_multiplier(metrics))

        env_score = self._calculate_environmental(metrics, c, i, a, exploitability)
        return {
            "base_score": base_score,
            "base_severity": self._get_severity(base_score),
            "impact_subscore": round(impact, 1),
            "exploitability_subscore": round(exploitability, 1),
            "temporal_score": temporal_score,
            "temporal_severity": self._get_severity(temporal_score) if temporal_score is not None else None,
            "environmental_score": env_score,
            "environmental_severity": self._get_severity(env_score) if env_score is not None else None,
            "vector_string": self._generate_vector(metrics),
        }

    # ── Formulas ──────────────────────────────────────────────────────────────

    def _exploitability(self, metrics: Dict[str, str]) -> float:
        av = self.weights["AV"].get(metrics.get("AV", "N"), 1.0)
        ac = self.weights["AC"].get(metrics.get("AC", "L"), 0.71)
        au = self.weights["Au"].get(metrics.get("Au", "N"), 0.704)
        return 20 * av * ac * au

    def _base(self, impact: float, exploitability: float) -> float:
        f_impact = 0 if impact == 0 else 1.176
        return _round1(((0.6 * impact) + (0.4 * exploitability) - 1.5) * f_impact)

    def _temporal_multiplier(self, metrics: Dict[str, str]) -> float:
        e = self.temporal_weights["E"].get(metrics.get("E", "ND"), 1.0)
        rl = self.temporal_weights["RL"].get(metrics.get("RL", "ND"), 1.0)
        rc = self.temporal_weights["RC"].get(metrics.get("RC", "ND"), 1.0)
        return e * rl * rc

    def _calculate_environmental(self, metrics, c, i, a, exploitability) -> Optional[float]:
        if all(metrics.get(k, "ND") == "ND" for k in ENV_ORDER):
            return None
        cdp = self.env_weights["CDP"].get(metrics.get("CDP", "ND"), 0.0)
        td = self.env_weights["TD"].get(metrics.get("TD", "ND"), 1.0)
        cr, ir, ar = (self.env_weights["Req"].get(metrics.get(k, "ND"), 1.0) for k in ("CR", "IR", "AR"))

        # The base equation again with the impact weighted by the requirements, then temporal
        adjusted_impact = min(10, 10.41 * (1 - (1 - c * cr) * (1 - i * ir) * (1 - a * ar)))
        adjusted_base = self._base(adjusted_impact, exploitability)
        adjusted_temporal = _round1(adjusted_base * self._temporal_multiplier(metrics))
        return _round1((adjusted_temporal + (10 - adjusted_temporal) * cdp) * td)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _get_severity(self, score: float) -> str:
        if score == 0.0:
            return "None"
        if score < 4.0:
            return "Low"
        if score < 7.0:
            return "Medium"
        if score < 9.0:
            return "High"
        return "Critical"

    def _generate_vector(self, metrics: Dict[str, str]) -> str:
        parts = [f"{k}:{metrics[k]}" for k in BASE_ORDER if k in metrics]
        parts += [f"{k}:{metrics[k]}" for k in TEMPORAL_ORDER + ENV_ORDER if metrics.get(k, "ND") != "ND"]
        return f"({'/'.join(parts)})"
