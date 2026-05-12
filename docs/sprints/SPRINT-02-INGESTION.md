# Sprint 02: CVE Ingestion and Qdrant Storage

## Goal

Load sample NVD CVE data and store it locally in Qdrant using on-disk mode.

## Scope

- Build the ingestion module for NVD sample loading
- Add local JSON fallback if the API is slow or unavailable
- Normalize CVE records into a consistent schema
- Create or reuse the Qdrant collection only when needed
- Store embeddings, metadata, and identifiers for retrieval

## API Keys and Services

- Use the Hugging Face token stored in the root `.env` file for embeddings
- Keep Qdrant local with `QdrantClient(path="data/qdrant_db")`
- No external database service is required

## Testing

- Mock the NVD fetch path to confirm local fallback behavior
- Mock the embedding client to confirm records are prepared for storage
- Verify ingestion skips re-creating an existing collection
- Verify invalid or empty NVD records are handled safely

## Acceptance Criteria

- Sample CVE data can be ingested locally
- Qdrant persists data on disk instead of using large in-memory storage
- Re-running ingestion does not duplicate the collection
- The ingestion path fails gracefully when source data is unavailable
