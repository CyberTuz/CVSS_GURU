"""
CVSS Guru - Entry point
Run with: python run.py
"""

import asyncio
import sys

import uvicorn
from app.logging_config import configure_logging, get_logger

configure_logging()
logger = get_logger("startup")

if __name__ == "__main__":
    # psycopg's async driver cannot use Windows' default Proactor event loop.
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    logger.info(
        "cvss_guru_dev_start",
        extra={"host": "0.0.0.0", "port": 8000, "reload": True}
    )
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
