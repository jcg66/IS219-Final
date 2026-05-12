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

## Implementation Strategy

The project follows a hybrid-local design:

- Ingestion pulls a sample of NVD CVE data and stores it in local vector storage
- Parsing handles raw SSH and Syslog-style log strings
- Retrieval finds the top matching CVEs for a given log entry
- Generation uses a strict SOC analyst prompt so the response stays grounded in retrieved context

This approach keeps the application practical for a student laptop while still demonstrating a real retrieval-augmented workflow.

## Current Status

Planning phase only. See [docs/STATUS.md](docs/STATUS.md) for the roadmap and sprint tracker.

## Planned Structure

- `src/ingestion.py`: load and vectorize CVE data
- `src/analyst.py`: run the retrieval and analysis pipeline
- `src/app.py`: Streamlit user interface
- `tests/`: parser, integration, and grounding tests
- `data/`: local vector storage and sample CVE data

## Technical Notes

The project is intentionally simple in its presentation and disciplined in its architecture. The emphasis is on reliability, explainability, and automated verification rather than flashy UI behavior or model fine-tuning.