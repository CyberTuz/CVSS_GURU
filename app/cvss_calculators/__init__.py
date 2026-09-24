"""
CVSS Calculators Package

This package contains calculators for different CVSS versions:
- CVSS2Calculator: CVSS v2.0 (2007)
- CVSS3Calculator: CVSS v3.0 (2015)
- CVSS31Calculator: CVSS v3.1 (2019)
- CVSS4Calculator: CVSS v4.0 (2023)
"""

from .cvss2 import CVSS2Calculator
from .cvss3 import CVSS3Calculator
from .cvss31 import CVSS31Calculator
from .cvss4 import CVSS4Calculator
from .descriptions import CVSS_DESCRIPTIONS

__all__ = [
    "CVSS2Calculator",
    "CVSS3Calculator", 
    "CVSS31Calculator",
    "CVSS4Calculator",
    "CVSS_DESCRIPTIONS"
]
