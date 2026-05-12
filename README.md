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
- A curated offline NVD subset and sample log set are kept in the repo for repeatable local testing
- Parsing handles raw SSH and Syslog-style log strings
- Retrieval finds the top matching CVEs for a given log entry
- Generation uses a strict SOC analyst prompt so the response stays grounded in retrieved context
- The dashboard supports a live mode with Hugging Face and Groq credentials or a local demo mode with deterministic fallback behavior

This approach keeps the application practical for a student laptop while still demonstrating a real retrieval-augmented workflow.

## Setup

1. Create and activate a virtual environment.
2. Install dependencies with `pip install -r requirements.txt`.
3. Copy `.env.example` to `.env` in the project root.
4. Add local secrets only to the root `.env` file.

Example `.env`:

```env
GROQ_API_KEY=your_groq_api_key_here
GROQ_MODEL=llama-3.1-8b-instant
HF_TOKEN=your_huggingface_token_here
NVD_API_KEY=your_nvd_api_key_here
```

API key notes:

- `GROQ_API_KEY` is used for the final analyst verdict generation.
- `GROQ_MODEL` can override the default Groq model if your account is configured for a different production model.
- `HF_TOKEN` enables live Hugging Face embeddings. Without it, the dashboard falls back to demo mode.
- `NVD_API_KEY` is reserved for NVD-backed ingestion work and should still be kept in `.env` for local development.
- Do not commit `.env`; keep real secrets only in your local root `.env` file.

## Run

1. Activate the project virtual environment.
2. Confirm `.env` is present at the project root.
3. Launch the dashboard with `streamlit run src/app.py`.

Runtime behavior:

- In live mode, ingest the target CVE dataset before analysis so the primary Qdrant collection exists.
- The repo now includes curated offline sample assets in `data/samples/` for predictable local preprocessing and test runs.
- Without `HF_TOKEN`, the UI falls back to a demo collection for local operator-flow testing.
- If `GROQ_API_KEY` is missing, the app can still run in demo mode, but it will not use the live Groq verdict path.
- CSV or JSON log exports can be uploaded directly; the dashboard normalizes structured records into analyst-ready log text.

## Docker

Build the image:

```powershell
docker build -t semantic-soc-analyst .
```

Run the container in demo mode:

```powershell
docker run --rm -p 8501:8501 -v ${PWD}\data:/app/data semantic-soc-analyst
```

Run the container with live keys:

```powershell
docker run --rm -p 8501:8501 -v ${PWD}\data:/app/data --env-file .env semantic-soc-analyst
```

Notes:

- Secrets are passed at runtime through `.env` or `docker run --env-file`; they are not baked into the image.
- The mounted `data/` directory keeps the local Qdrant store available across container runs.
- If you do not pass API keys, the app stays usable in demo mode with deterministic fallback behavior.

## DockerHub Publish

Use the release helper to build, tag, push, and pull the image against DockerHub:

```powershell
pwsh .\scripts\Publish-DockerHub.ps1 -Repository yourdockerhubuser/semantic-soc-analyst -Tag v1.0.0
```

Tagging notes:

- Use a DockerHub repository name in the form `yourusername/semantic-soc-analyst`
- Prefer a release tag such as `v1.0.0` for published images
- Omit `-Tag` to publish or test the default `latest` tag
- Pass `-SkipSmokeTest` if you only want to build, tag, push, and pull the image

The helper script performs the release flow in order:

1. Build the local image from the repository root
2. Tag the local image for DockerHub
3. Push the tagged image to DockerHub
4. Pull the image back to confirm it is available
5. Start an optional smoke-test container on port 8501

If you prefer to run the commands manually, the equivalent flow is:

```powershell
docker login
docker build -t semantic-soc-analyst .
docker tag semantic-soc-analyst yourdockerhubuser/semantic-soc-analyst:v1.0.0
docker push yourdockerhubuser/semantic-soc-analyst:v1.0.0
docker pull yourdockerhubuser/semantic-soc-analyst:v1.0.0
docker run --rm -p 8501:8501 -v ${PWD}\data:/app/data --env-file .env yourdockerhubuser/semantic-soc-analyst:v1.0.0
```

## Ingestion Workflow

Use the manual ingestion workflow to prepare and load CVE data into the live Qdrant collection.

Dry-run the curated offline sample:

```powershell
python -m src.ingest_pipeline --source sample --dry-run
```

Ingest the curated offline sample into the live collection:

```powershell
python -m src.ingest_pipeline --source sample
```

Ingest a local full NVD feed:

```powershell
python -m src.ingest_pipeline --source file --local-path data/nvdcve-2.0-2025.json --limit 75
```

If network access is available, ingest a bounded live API sample:

```powershell
python -m src.ingest_pipeline --source api --api-severity CRITICAL --limit 75
```

Notes:

- Live ingestion requires `HF_TOKEN` because embeddings must be created before records are written to Qdrant.
- API ingestion also expects `NVD_API_KEY` in the root `.env`.
- `--dry-run` lets you verify record loading and filtering without calling Hugging Face or writing to Qdrant.

## Testing

For a local test run:

1. Activate the project virtual environment.
2. Run `python -m pytest -q` from the repository root.

What the suite covers:

- Parser extraction behavior
- Ingestion normalization and vector-storage safeguards
- Analyst grounding behavior for benign and matched logs
- UI helper and dashboard rendering behavior
- Timeout and empty-data failure paths

If you want to test the app manually after the suite passes:

1. Start the UI with `streamlit run src/app.py`.
2. Paste a sample SSH or syslog-style log entry.
3. Verify that the parsed fields, retrieved evidence, and verdict render without crashing.

## Current Status

Sprint 08 is complete.

Completed so far:

- Sprint 01: repository foundation, environment scaffolding, and dependency setup
- Sprint 02: CVE ingestion helpers and local Qdrant storage flow
- Sprint 03: log parsing, retrieval, and grounded analyst pipeline
- Sprint 04: Streamlit dashboard, runtime wiring, and UI test coverage
- Sprint 05: verification hardening, safer failure handling, and documentation cleanup
- Sprint 06: external sample data ingestion and preprocessing
- Sprint 07: Docker image and local container run
- Sprint 08: DockerHub publish workflow

Current focus:

- Keep the project presentation-ready while feature work continues
- Explore optional CI/CD or multi-architecture release automation
- Expand the live-data workflow beyond the curated offline subset

See [docs/STATUS.md](docs/STATUS.md) for the roadmap and sprint tracker.

## Repository Structure

- `src/ingestion.py`: load and vectorize CVE data
- `src/preprocessing.py`: clean external sample logs and normalize raw text
- `src/analyst.py`: run the retrieval and analysis pipeline
- `src/app.py`: Streamlit user interface
- `tests/`: parser, integration, and grounding tests
- `data/samples/`: curated offline CVE and log samples for Sprint 06
- `data/`: local vector storage and additional local data files
- `pytest.ini`: repo-level test discovery and local test-run configuration

## Technical Notes

The project is intentionally simple in its presentation and disciplined in its architecture. The emphasis is on reliability, explainability, and automated verification rather than flashy UI behavior or model fine-tuning.
