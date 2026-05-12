# Sprint 04: Streamlit Dashboard and Operator Flow

## Goal

Provide a simple operator interface for pasting logs, reviewing context, and reading the final verdict.

## Scope

- Build the Streamlit app shell
- Add a log input area and optional file upload path
- Show retrieved CVE context and the analyst verdict
- Keep the UI clean and minimal
- Display useful status messages during analysis

## API Keys and Services

- The UI should read credentials from the root `.env` file
- Groq and Hugging Face services must already be enabled for the backend pipeline
- Streamlit runs locally and does not require a separate cloud service

## Testing

- Verify the UI can submit a sample log to the backend pipeline
- Mock backend calls so UI tests do not depend on live APIs
- Verify missing input is handled with a clear message
- Verify the verdict and evidence sections render correctly

## Acceptance Criteria

- A user can paste or upload a log and receive an analyst verdict
- The UI surfaces relevant context without clutter
- Backend errors are shown cleanly instead of crashing the app
- The interface stays aligned with the project’s utility-first design
