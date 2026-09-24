"""
CVSS v3.0 Calculator
Reference: https://www.first.org/cvss/v3.0/specification-document

CVSS31Calculator (cvss31.py) subclasses this one: v3.1 only changes the
Modified Impact formula when the modified scope is Changed.
"""

import math
from typing import Any, Dict, Optional

BASE_ORDER = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
TEMPORAL_ORDER = ["E", "RL", "RC"]
ENV_ORDER = ["CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"]


class CVSS3Calculator:
    """CVSS v3.0 Score Calculator"""

    VERSION = "3.0"

    def __init__(self):
        # Base metric weights
        self.weights = {
            "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
            "AC": {"L": 0.77, "H": 0.44},
            "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
            "PR_changed": {"N": 0.85, "L": 0.68, "H": 0.5},  # when Scope is Changed
            "UI": {"N": 0.85, "R": 0.62},
            "CIA": {"N": 0.0, "L": 0.22, "H": 0.56},
        }
        # Temporal metric weights ("X" = Not Defined = no adjustment)
        self.temporal_weights = {
            "E": {"X": 1.0, "U": 0.91, "P": 0.94, "F": 0.97, "H": 1.0},
            "RL": {"X": 1.0, "O": 0.95, "T": 0.96, "W": 0.97, "U": 1.0},
            "RC": {"X": 1.0, "U": 0.92, "R": 0.96, "C": 1.0},
        }
        # Security requirements (CR/IR/AR); Not Defined counts as Medium
        self.env_req_weights = {"X": 1.0, "L": 0.5, "M": 1.0, "H": 1.5}

    def calculate(self, metrics: Dict[str, str]) -> Dict[str, Any]:
        """
        Calculate CVSS v3.x scores from metrics.

        Required base metrics: AV, AC, PR, UI, S, C, I, A
        Optional temporal: E, RL, RC
        Optional environmental: CR, IR, AR, MAV, MAC, MPR, MUI, MS, MC, MI, MA
        Temporal/environmental scores are None when none of their metrics is defined.
        """
        base_score, impact, exploitability = self._calculate_base(metrics)
        temporal_score = self._calculate_temporal(base_score, metrics)
        env_score = self._calculate_environmental(metrics)
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

    def _roundup(self, value: float) -> float:
        """Smallest one-decimal number >= value. Computed on integers, as v3.1 later made explicit,
        so float noise (5.0 * 0.92 = 4.6000000000000005) doesn't push 4.6 up to 4.7."""
        int_input = round(value * 100000)
        if int_input % 10000 == 0:
            return int_input / 100000.0
        return (math.floor(int_input / 10000) + 1) / 10.0

    def _modified_impact_changed(self, miss: float) -> float:
        """Modified Impact when the modified scope is Changed (v3.0 formula)."""
        return 7.52 * (miss - 0.029) - 3.25 * pow(miss - 0.02, 15)

    def _temporal_multiplier(self, metrics: Dict[str, str]) -> float:
        e = self.temporal_weights["E"].get(metrics.get("E", "X"), 1.0)
        rl = self.temporal_weights["RL"].get(metrics.get("RL", "X"), 1.0)
        rc = self.temporal_weights["RC"].get(metrics.get("RC", "X"), 1.0)
        return e * rl * rc

    def _score(self, impact: float, exploitability: float, changed: bool) -> float:
        """Shared by base and environmental: unrounded score from (modified) impact and exploitability."""
        if impact <= 0:
            return 0.0
        total = impact + exploitability
        return min(1.08 * total if changed else total, 10)

    def _calculate_base(self, metrics: Dict[str, str]) -> tuple:
        """Returns (base score, impact sub-score, exploitability sub-score)."""
        changed = metrics.get("S", "U") == "C"
        av = self.weights["AV"].get(metrics.get("AV", "N"), 0.85)
        ac = self.weights["AC"].get(metrics.get("AC", "L"), 0.77)
        pr = self.weights["PR_changed" if changed else "PR"].get(metrics.get("PR", "N"), 0.85)
        ui = self.weights["UI"].get(metrics.get("UI", "N"), 0.85)
        c, i, a = (self.weights["CIA"].get(metrics.get(k, "N"), 0.0) for k in ("C", "I", "A"))

        iss = 1 - ((1 - c) * (1 - i) * (1 - a))
        impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15) if changed else 6.42 * iss
        exploitability = 8.22 * av * ac * pr * ui
        return self._roundup(self._score(impact, exploitability, changed)), impact, exploitability

    def _calculate_temporal(self, base_score: float, metrics: Dict[str, str]) -> Optional[float]:
        if all(metrics.get(k, "X") == "X" for k in TEMPORAL_ORDER):
            return None
        return self._roundup(base_score * self._temporal_multiplier(metrics))

    def _calculate_environmental(self, metrics: Dict[str, str]) -> Optional[float]:
        if all(metrics.get(k, "X") == "X" for k in ENV_ORDER):
            return None

        def modified(key: str) -> str:
            # A Modified metric left as Not Defined takes the base value
            value = metrics.get("M" + key, "X")
            return metrics.get(key, "X") if value == "X" else value

        changed = modified("S") == "C"
        mav = self.weights["AV"].get(modified("AV"), 0.85)
        mac = self.weights["AC"].get(modified("AC"), 0.77)
        mpr = self.weights["PR_changed" if changed else "PR"].get(modified("PR"), 0.85)
        mui = self.weights["UI"].get(modified("UI"), 0.85)
        mc, mi, ma = (self.weights["CIA"].get(modified(k), 0.0) for k in ("C", "I", "A"))
        cr, ir, ar = (self.env_req_weights.get(metrics.get(k, "X"), 1.0) for k in ("CR", "IR", "AR"))

        miss = min(1 - ((1 - mc * cr) * (1 - mi * ir) * (1 - ma * ar)), 0.915)
        m_impact = self._modified_impact_changed(miss) if changed else 6.42 * miss
        m_exploitability = 8.22 * mav * mac * mpr * mui
        if m_impact <= 0:
            return 0.0
        env = self._roundup(self._score(m_impact, m_exploitability, changed))
        return self._roundup(env * self._temporal_multiplier(metrics))

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
        parts = [f"CVSS:{self.VERSION}"]
        parts += [f"{k}:{metrics[k]}" for k in BASE_ORDER if k in metrics]
        parts += [f"{k}:{metrics[k]}" for k in TEMPORAL_ORDER + ENV_ORDER if metrics.get(k, "X") != "X"]
        return "/".join(parts)
