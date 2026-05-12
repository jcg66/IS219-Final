"""Runtime settings helpers for Semantic SOC Analyst.

This module is import-safe and does not require secrets to be present at
import time.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path


@dataclass(frozen=True)
class AppSettings:
    """Container for runtime configuration values."""

    groq_api_key: str | None
    hf_token: str | None
    nvd_api_key: str | None
    qdrant_path: str = "data/qdrant_db"


def load_settings() -> AppSettings:
    """Load environment-backed settings without failing on missing secrets."""

    return AppSettings(
        groq_api_key=os.getenv("GROQ_API_KEY") or None,
        hf_token=os.getenv("HF_TOKEN") or None,
        nvd_api_key=os.getenv("NVD_API_KEY") or None,
    )


def load_dotenv_if_available() -> bool:
    """Load the root .env file if python-dotenv is installed.

    Returns:
        True when the file was loaded successfully, otherwise False.
    """

    try:
        from dotenv import load_dotenv
    except ImportError:
        return False

    env_path = Path(__file__).resolve().parents[1] / ".env"
    if not env_path.exists():
        return False

    return bool(load_dotenv(env_path))