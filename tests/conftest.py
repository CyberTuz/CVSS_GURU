import os

# Run the suite against the full app regardless of the developer's .env
# (load_dotenv never overrides variables that are already set).
# Local-mode tests patch app.config.LOCAL_MODE explicitly.
os.environ["LOCAL_MODE"] = "false"
# Never touch the database from .env (it may be production): tests mock the DB layer,
# and app startup skips migrations when no database is configured.
# Set TEST_DATABASE_URL to run the few tests that need a real PostgreSQL.
os.environ["DATABASE_URL"] = os.getenv("TEST_DATABASE_URL", "")
# No real CAPTCHA checks or emails from the test suite (tests patch them when needed).
for _var in ("RECAPTCHA_SITE_KEY", "RECAPTCHA_SECRET_KEY", "SMTP_HOST"):
    os.environ[_var] = ""

import pytest
from app.cvss_calculators.cvss2 import CVSS2Calculator
from app.cvss_calculators.cvss3 import CVSS3Calculator
from app.cvss_calculators.cvss31 import CVSS31Calculator
from app.cvss_calculators.cvss4 import CVSS4Calculator


@pytest.fixture
def cvss2():
    return CVSS2Calculator()


@pytest.fixture
def cvss3():
    return CVSS3Calculator()


@pytest.fixture
def cvss31():
    return CVSS31Calculator()


@pytest.fixture
def cvss4():
    return CVSS4Calculator()
