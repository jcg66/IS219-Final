# Sprint 06: External Data Ingestion and Preprocessing

## Goal

Collect and prepare external sample data so the app has realistic input for testing and retrieval.

## Scope

- Pull sample CVE data from the NVD API or a downloaded JSON feed
- Filter the dataset to a manageable subset such as Critical CVEs or SSH/RDP-related records
- Extract only the fields needed for retrieval: `cve_id`, `description`, and `cvss_score`
- Prepare sample security logs from an external source for parser and UI testing
- Normalize and clean raw text before it reaches the ingestion or analyst pipeline

## API Keys and Services

- Add `NVD_API_KEY` to the root `.env` file if using the live NVD API
- Add `GROQ_API_KEY` and `HF_TOKEN` to the root `.env` file for the downstream app pipeline
- Enable NVD API access or download the 2024/2025 JSON feed into `data/`
- Enable Hugging Face Inference API access for vectorization of selected CVE text

## Testing

- Verify the NVD fetch path can work with both live API and local JSON feed inputs
- Verify sample log files are parsed into the expected cleaned format
- Verify filtering reduces the dataset to the intended small test subset
- Mock external fetches so tests do not depend on network availability

## Acceptance Criteria

- The project has realistic external sample data for testing
- The external data set is small enough to keep ingestion practical on a student laptop
- Preprocessing produces consistent records for the rest of the pipeline
- The workflow supports offline fallback when the external source is unavailable
