"""Tests for the manual ingestion workflow."""

from __future__ import annotations

from src.ingest_pipeline import build_parser, run_ingestion_workflow
from src.ingestion import CVERecord
from src.settings import AppSettings


def test_run_ingestion_workflow_supports_dry_run_without_hf_token() -> None:
    settings = AppSettings(groq_api_key=None, hf_token=None, nvd_api_key=None)

    result = run_ingestion_workflow(
        source="sample",
        limit=10,
        dry_run=True,
        settings=settings,
    )

    assert result.source == "sample"
    assert result.source_records >= 1
    assert result.prepared_records >= 1
    assert result.upserted_records == 0
    assert result.dry_run is True


def test_run_ingestion_workflow_requires_hf_token_for_live_ingestion() -> None:
    settings = AppSettings(groq_api_key=None, hf_token=None, nvd_api_key=None)

    try:
        run_ingestion_workflow(source="sample", limit=10, dry_run=False, settings=settings)
    except RuntimeError as error:
        assert "HF_TOKEN is required" in str(error)
    else:  # pragma: no cover - defensive assertion
        raise AssertionError("Expected a RuntimeError when HF_TOKEN is missing")


def test_run_ingestion_workflow_ingests_prepared_records_with_injected_dependencies() -> None:
    class FakeClient:
        pass

    def fake_embedder(texts: list[str]) -> list[list[float]]:
        return [[1.0, 0.0, 0.0] for _ in texts]

    fake_client = FakeClient()
    settings = AppSettings(groq_api_key=None, hf_token="token", nvd_api_key=None)
    sample_records = [CVERecord(cve_id="CVE-1", description="Critical SSH issue", cvss_score=9.8)]
    captured: dict[str, object] = {}

    def fake_load_source_records(*args, **kwargs):
        return sample_records

    def fake_ingest_records(records, client, embedder, *, collection_name):
        captured["records"] = records
        captured["client"] = client
        captured["collection_name"] = collection_name
        return len(records)

    def fake_count_points(client, collection_name):
        return 1

    from unittest.mock import patch

    with (
        patch("src.ingest_pipeline._load_source_records", fake_load_source_records),
        patch("src.ingest_pipeline.ingest_records", fake_ingest_records),
        patch("src.ingest_pipeline.count_points", fake_count_points),
    ):
        result = run_ingestion_workflow(
            source="sample",
            collection_name="semantic_soc_cves",
            limit=10,
            settings=settings,
            client=fake_client,
            embedder=fake_embedder,
        )

    assert result.upserted_records == 1
    assert result.point_count == 1
    assert captured["client"] is fake_client
    assert captured["collection_name"] == "semantic_soc_cves"


def test_build_parser_accepts_expected_manual_workflow_flags() -> None:
    parser = build_parser()

    args = parser.parse_args(["--source", "file", "--local-path", "data/nvdcve-2.0-2025.json", "--dry-run"])

    assert args.source == "file"
    assert args.local_path.endswith("nvdcve-2.0-2025.json")
    assert args.dry_run is True
