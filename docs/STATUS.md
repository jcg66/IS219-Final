# Project Status

## Current Snapshot

Project: Semantic SOC Analyst
Status: Planning phase
Sprint: No sprint started yet

## Technical Direction

The project will follow a hybrid-local architecture designed for a low-RAM machine:

- Local storage and retrieval with Qdrant in on-disk mode
- Cloud-hosted embeddings through the Hugging Face Inference API
- Cloud-hosted analysis through Groq with Llama 3
- Streamlit for a simple operator-facing dashboard
- Pytest for automated verification, including grounding checks

This approach keeps the heavy model work off the local machine while preserving local control over data flow, retrieval, and application logic.

## Roadmap

### Phase 1: Foundation

- Confirm repository structure and Python dependencies
- Add environment templates and ignore rules for local secrets and Qdrant storage
- Define the shared data model for CVEs and parsed logs

### Phase 2: Ingestion Layer

- Build the NVD sample loader with local JSON fallback
- Normalize CVE records for vector storage
- Store embeddings and metadata in Qdrant only if the collection does not already exist

### Phase 3: Analyst Pipeline

- Implement the log parser for SSH and syslog-style strings
- Embed the pasted log through Hugging Face
- Retrieve the top 3 matching CVEs from Qdrant
- Send the retrieved context plus log to Groq with a strict SOC analyst prompt

### Phase 4: Operator UI

- Build a Streamlit interface for manual log paste or file upload
- Display the analyst verdict and supporting CVE context
- Keep the interface functional and minimal rather than visually elaborate

### Phase 5: Verification

- Add unit tests for log parsing
- Add integration tests that mock Groq responses
- Add a grounding test to reduce false positives on benign logs
- Validate that the pipeline returns a safe, contextual response when no known vulnerability matches

## Current Sprint

No sprint has been started yet.

Planned sprint focus:

- Lock the project skeleton
- Implement ingestion and parsing
- Establish the first test suite

## Open Decisions

- Confirm whether the NVD source will be live API only or API plus a checked-in sample JSON
- Decide the minimum fields to keep in the local CVE schema
- Finalize the wording for the analyst prompt and the verdict output format

## Success Criteria

- The tool runs locally without loading a large model into RAM
- Retrieval returns relevant CVE context for security logs
- The analyst response stays grounded in the retrieved evidence
- Tests cover parsing, integration behavior, and benign-log handling