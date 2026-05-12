"""Sprint 01 foundation tests."""

from __future__ import annotations

from pathlib import Path
import importlib


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_env_example_documents_required_keys() -> None:
    env_example = (PROJECT_ROOT / ".env.example").read_text(encoding="utf-8")

    assert "GROQ_API_KEY" in env_example
    assert "HF_TOKEN" in env_example
    assert "NVD_API_KEY" in env_example


def test_gitignore_blocks_secrets_and_raw_data() -> None:
    gitignore = (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8")

    assert ".env" in gitignore
    assert "qdrant_storage/" in gitignore
    assert "data/*" in gitignore
    assert "!data/.gitkeep" in gitignore


def test_settings_import_is_secret_free() -> None:
    module = importlib.import_module("src.settings")

    settings = module.load_settings()

    assert settings.groq_api_key is None
    assert settings.hf_token is None
    assert settings.nvd_api_key is None


def test_requirements_are_pinned() -> None:
    requirements = (PROJECT_ROOT / "requirements.txt").read_text(encoding="utf-8")
    pinned_lines = [
        line
        for line in requirements.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]

    assert pinned_lines, "requirements.txt should list pinned dependencies"
    assert all("==" in line for line in pinned_lines)


def test_data_scaffold_placeholder_exists() -> None:
    assert (PROJECT_ROOT / "data" / ".gitkeep").exists()