# Semantic SOC Analyst

Semantic SOC Analyst is a small-scale security analysis project built as a portfolio-ready RAG application. It shows how a local machine can stay lightweight while still delivering useful threat analysis by combining local storage, retrieval, and orchestration with cloud-based model APIs.

## What It Does

The app accepts a pasted security log or uploaded text file, extracts useful signal from the entry, retrieves related CVE context from a local Qdrant store, and sends that context to Groq for a final analyst verdict.

## Project Goals

- Keep memory usage low by avoiding local LLM hosting
- Store vector data locally using Qdrant in on-disk mode
- Use Hugging Face Inference API for embeddings
- Use Groq with Llama 3 for fast analysis and response generation
- Provide a simple Streamlit interface for manual log review
- Cover the core behavior with automated tests

## Architecture

The project follows a hybrid-local design:

- Ingestion pulls a sample of NVD CVE data and stores it in local vector storage
- Parsing handles raw SSH and Syslog-style log strings
- Retrieval finds the top matching CVEs for a given log entry
- Generation uses a strict SOC analyst prompt so the response stays grounded in retrieved context
- The dashboard supports a live mode with Hugging Face and Groq credentials or a local demo mode with deterministic fallback behavior

This approach keeps the application practical for a student laptop while still demonstrating a real retrieval-augmented workflow.

## Setup

1. Create and activate a virtual environment.
2. Install dependencies with `pip install -r requirements.txt`.
3. Copy `.env.example` to `.env` in the project root.
4. Add local secrets only to the root `.env` file:
   `GROQ_API_KEY=...`
   `HF_TOKEN=...`
   `NVD_API_KEY=...`

## Run

- Launch the dashboard with `streamlit run src/app.py`.
- In live mode, ingest the target CVE dataset before analysis so the primary Qdrant collection exists.
- Without `HF_TOKEN`, the UI falls back to a demo collection for local operator-flow testing.

## Testing

- Run the full verification suite with `python -m pytest -q`.
- Automated tests mock Groq responses and cover benign-log grounding, no-match behavior, and UI error handling.

## Current Status

Sprint 05 is complete.

Completed so far:

- Sprint 01: repository foundation, environment scaffolding, and dependency setup
- Sprint 02: CVE ingestion helpers and local Qdrant storage flow
- Sprint 03: log parsing, retrieval, and grounded analyst pipeline
- Sprint 04: Streamlit dashboard, runtime wiring, and UI test coverage
- Sprint 05: verification hardening, safer failure handling, and documentation cleanup

Current focus:

- Prepare the external-data ingestion sprint
- Expand the live-data workflow beyond the local demo dataset
- Keep the project presentation-ready while feature work continues

See [docs/STATUS.md](docs/STATUS.md) for the roadmap and sprint tracker.

## Repository Structure

- `src/ingestion.py`: load and vectorize CVE data
- `src/analyst.py`: run the retrieval and analysis pipeline
- `src/app.py`: Streamlit user interface
- `tests/`: parser, integration, and grounding tests
- `data/`: local vector storage and sample CVE data
- `pytest.ini`: repo-level test discovery and local test-run configuration

## Technical Notes

The project is intentionally simple in its presentation and disciplined in its architecture. The emphasis is on reliability, explainability, and automated verification rather than flashy UI behavior or model fine-tuning.
