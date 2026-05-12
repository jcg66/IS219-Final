"""External log preprocessing helpers for Semantic SOC Analyst."""

from __future__ import annotations

from pathlib import Path
import re
from typing import Iterable

DEFAULT_SAMPLE_LOG_PATH = Path("data/samples/security_logs.txt")
WHITESPACE_PATTERN = re.compile(r"\s+")


def normalize_text(text: str) -> str:
    """Normalize whitespace-heavy raw text into a single clean line."""

    cleaned = text.replace("\x00", " ").replace("\r", " ").replace("\n", " ").replace("\t", " ")
    return WHITESPACE_PATTERN.sub(" ", cleaned).strip()


def normalize_log_text(text: str) -> str:
    """Normalize a raw log line before parsing or UI display."""

    return normalize_text(text)


def prepare_sample_logs(raw_logs: Iterable[str]) -> list[str]:
    """Clean and deduplicate raw sample logs."""

    cleaned_logs: list[str] = []
    seen: set[str] = set()

    for raw_log in raw_logs:
        cleaned = normalize_log_text(raw_log)
        if not cleaned or cleaned.startswith("#") or cleaned in seen:
            continue
        seen.add(cleaned)
        cleaned_logs.append(cleaned)

    return cleaned_logs


def load_sample_logs(path: str | Path | None = None) -> list[str]:
    """Load curated sample logs from disk for parser and UI testing."""

    resolved_path = Path(path) if path is not None else DEFAULT_SAMPLE_LOG_PATH
    lines = resolved_path.read_text(encoding="utf-8").splitlines()
    return prepare_sample_logs(lines)
