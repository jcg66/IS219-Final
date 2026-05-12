"""Tests for the Sprint 02 ingestion workflow."""

from __future__ import annotations

from pathlib import Path

from qdrant_client import QdrantClient

from src.ingestion import (
    CVERecord,
    DEFAULT_SAMPLE_JSON,
    _fetch_json,
    count_points,
    filter_records,
    ingest_records,
    load_nvd_api_records,
    load_nvd_records,
    prepare_cve_records,
)


def test_load_nvd_records_from_local_json(monkeypatch) -> None:
    sample_payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2025-0001",
                    "descriptions": [
                        {"lang": "en", "value": "Critical SSH authentication bypass in example service."}
                    ],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
                }
            },
            {
                "cve": {
                    "id": "CVE-2025-0002",
                    "descriptions": [
                        {"lang": "en", "value": "Informational desktop issue not relevant to the demo."}
                    ],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.0}}]},
                }
            },
        ]
    }
    monkeypatch.setattr("src.ingestion._read_json", lambda path: sample_payload)
    monkeypatch.setattr(Path, "exists", lambda self: True)

    records = load_nvd_records(local_path="sample_nvd.json")

    assert len(records) == 2
    assert records[0].cve_id == "CVE-2025-0001"
    assert records[0].cvss_score == 9.8
    assert "SSH authentication bypass" in records[0].description


def test_load_nvd_records_uses_curated_sample_by_default() -> None:
    records = load_nvd_records()

    assert DEFAULT_SAMPLE_JSON.exists()
    assert records
    assert any(record.cve_id == "CVE-2025-1001" for record in records)


def test_filter_records_prefers_high_signal_items() -> None:
    records = [
        CVERecord(cve_id="CVE-1", description="Critical SSH issue", cvss_score=9.8),
        CVERecord(cve_id="CVE-2", description="Low severity desktop issue", cvss_score=4.0),
    ]

    selected = filter_records(records, min_cvss=9.0, keywords=("ssh",), limit=10)

    assert len(selected) == 1
    assert selected[0].cve_id == "CVE-1"


def test_prepare_cve_records_filters_normalizes_and_deduplicates() -> None:
    prepared = prepare_cve_records(
        [
            CVERecord(cve_id="CVE-1", description=" Critical   SSH issue ", cvss_score=9.8),
            CVERecord(cve_id="CVE-1", description="Critical SSH issue", cvss_score=9.8),
            CVERecord(cve_id="CVE-2", description="Low severity desktop issue", cvss_score=4.0),
            CVERecord(cve_id="CVE-3", description="RDP escalation path", cvss_score=8.0),
        ],
        min_cvss=9.0,
        keywords=("ssh", "rdp"),
        limit=10,
    )

    assert [record.cve_id for record in prepared] == ["CVE-1", "CVE-3"]
    assert prepared[0].description == "Critical SSH issue"


def test_ingest_records_is_idempotent() -> None:
    client = QdrantClient(location=":memory:")
    records = [
        CVERecord(cve_id="CVE-2025-0100", description="SSH brute force vector", cvss_score=9.5),
        CVERecord(cve_id="CVE-2025-0101", description="RDP privilege escalation path", cvss_score=9.2),
    ]

    def embedder(texts: list[str]) -> list[list[float]]:
        return [[float(len(text)), 1.0, 0.0] for text in texts]

    first_ingest = ingest_records(records, client, embedder)
    second_ingest = ingest_records(records, client, embedder)
    total_points = count_points(client)
    if hasattr(client, "close"):
        client.close()

    assert first_ingest == 2
    assert second_ingest == 2
    assert total_points == 2


def test_ingest_records_rejects_empty_embedding_output() -> None:
    client = QdrantClient(location=":memory:")

    def empty_embedder(texts: list[str]) -> list[list[float]]:
        return []

    try:
        ingest_records(
            [CVERecord(cve_id="CVE-2025-0100", description="SSH brute force vector", cvss_score=9.5)],
            client,
            empty_embedder,
        )
    except RuntimeError as error:
        assert "returned no vector" in str(error)
    else:  # pragma: no cover - defensive assertion
        raise AssertionError("Expected a RuntimeError for empty embedding output")
    finally:
        if hasattr(client, "close"):
            client.close()


def test_fetch_json_timeout_raises_clear_error(monkeypatch) -> None:
    class FakeRequests:
        class Timeout(Exception):
            pass

        class RequestException(Exception):
            pass

        @staticmethod
        def get(url: str, headers=None, params=None, timeout: float = 0.0):
            raise FakeRequests.Timeout("timeout")

    monkeypatch.setitem(__import__("sys").modules, "requests", FakeRequests)

    try:
        _fetch_json("https://example.com/nvd.json", 2.0)
    except TimeoutError as error:
        assert "timed out" in str(error)
    else:  # pragma: no cover - defensive assertion
        raise AssertionError("Expected TimeoutError for NVD timeout handling")


def test_load_nvd_api_records_uses_mocked_fetch(monkeypatch) -> None:
    payload = {
        "totalResults": 2,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2025-1111",
                    "descriptions": [{"lang": "en", "value": "Critical SSH issue from API."}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.7}}]},
                }
            },
            {
                "cve": {
                    "id": "CVE-2025-2222",
                    "descriptions": [{"lang": "en", "value": "RDP authentication weakness from API."}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.1}}]},
                }
            },
        ],
    }

    monkeypatch.setattr("src.ingestion._fetch_json", lambda *args, **kwargs: payload)

    records = load_nvd_api_records("test-key", max_records=2, keyword_search="ssh")

    assert len(records) == 2
    assert records[0].cve_id == "CVE-2025-1111"
