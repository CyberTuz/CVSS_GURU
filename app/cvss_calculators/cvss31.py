"""
CVSS v3.1 Calculator
Reference: https://www.first.org/cvss/v3.1/specification-document

Same metrics, weights and Roundup as v3.0 (see cvss3.py); the only formula
change is the Modified Impact when the modified scope is Changed.
"""

from app.cvss_calculators.cvss3 import CVSS3Calculator


class CVSS31Calculator(CVSS3Calculator):
    """CVSS v3.1 Score Calculator"""

    VERSION = "3.1"

    def _modified_impact_changed(self, miss: float) -> float:
        return 7.52 * (miss - 0.029) - 3.25 * pow(miss * 0.9731 - 0.02, 13)
