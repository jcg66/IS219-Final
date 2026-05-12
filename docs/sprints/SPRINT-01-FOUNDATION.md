# Sprint 01: Foundation and Environment Setup

## Goal

Establish the project skeleton, local environment, and configuration rules before feature work begins.

## Scope

- Confirm the root folder structure
- Create `src/`, `tests/`, and `data/` scaffolding if needed
- Add `.env.example` for required secrets
- Add `.gitignore` entries for `.env` and local Qdrant storage
- Pin core Python dependencies in `requirements.txt`

## API Keys and Services

- Add API keys to the root `.env` file, not to source files
- Required keys: `GROQ_API_KEY`, `HF_TOKEN`
- Optional key: `NVD_API_KEY` if the project uses authenticated NVD requests
- Enable Groq Cloud access for Llama 3 inference
- Enable Hugging Face token access for the Inference API

## Testing

- Verify `.env.example` contains the expected variable names
- Verify `.gitignore` excludes `.env` and local Qdrant storage folders
- Verify the repository can be imported without requiring secrets at import time

## Acceptance Criteria

- The repository has a clear, reproducible local setup path
- Secrets are documented and excluded from version control
- The project can start from a clean clone without ambiguous configuration
- Core dependencies are pinned to stable versions
