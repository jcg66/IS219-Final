# Sprint 07: Docker Image and Local Container Run

## Goal

Package the application into a reproducible Docker image so the app can be run locally without manual Python environment setup.

## Scope

- Add a production-oriented `Dockerfile` for the Streamlit app
- Ensure the image can install Python dependencies and run `src/app.py`
- Support mounting or preserving the local `data/` directory for Qdrant on-disk storage
- Document how to pass `.env` configuration into the container at runtime
- Add a short local container run workflow to the README or release docs

## Non-Goals

- No Kubernetes, ECS, or cloud deployment work in this sprint
- No reverse proxy or TLS setup
- No multi-container orchestration unless Qdrant is moved out of embedded local mode in a future sprint

## API Keys and Services

- The container runtime must accept `GROQ_API_KEY`, `HF_TOKEN`, and `NVD_API_KEY`
- Secrets must still be injected at runtime, not baked into the image
- The image should run in demo mode when live API keys are not provided

## Testing

- Build the Docker image locally
- Start the container and confirm Streamlit boots successfully
- Confirm the app can read runtime environment variables from an `.env` file or `docker run --env`
- Confirm the mounted `data/` path remains usable for local Qdrant storage

## Acceptance Criteria

- A developer can build the image with one documented `docker build` command
- A developer can run the app locally with one documented `docker run` command
- Secrets are provided at runtime rather than copied into the image
- The containerized app behavior matches the local app behavior closely enough for demos and evaluation
