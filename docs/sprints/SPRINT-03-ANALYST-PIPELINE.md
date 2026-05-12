# Sprint 03: Log Parsing and Analyst Pipeline

## Goal

Turn raw security logs into a retrieval-augmented analyst workflow that returns a grounded verdict.

## Scope

- Implement the SSH and syslog-style log parser
- Extract useful fields such as timestamp and IP address when present
- Embed the input log through Hugging Face
- Query Qdrant for the top 3 similar CVEs
- Send retrieved context and the log to Groq with the SOC analyst prompt

## API Keys and Services

- Root `.env` must contain `GROQ_API_KEY` and `HF_TOKEN`
- Groq Cloud must be enabled for the Llama 3 model used by the app
- Hugging Face Inference API access must be active for embeddings

## Testing

- Unit test the parser against representative log strings
- Mock Qdrant retrieval to confirm the top-3 lookup path
- Mock the Groq response to confirm the pipeline returns an analyst verdict
- Add a benign-log case to check that the system stays grounded

## Acceptance Criteria

- The parser handles common SSH and syslog formats
- The pipeline retrieves relevant CVE context before generation
- The verdict is based on retrieved evidence, not free-form guessing
- Benign logs do not get incorrectly labeled as threats
