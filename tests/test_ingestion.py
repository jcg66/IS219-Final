"""Tests for the Sprint 02 ingestion workflow."""

from __future__ import annotations

from pathlib import Path

from qdrant_client import QdrantClient

from src.ingestion import CVERecord, count_points, filter_records, ingest_records, load_nvd_records


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


def test_filter_records_prefers_high_signal_items() -> None:
    records = [
        CVERecord(cve_id="CVE-1", description="Critical SSH issue", cvss_score=9.8),
        CVERecord(cve_id="CVE-2", description="Low severity desktop issue", cvss_score=4.0),
    ]

    selected = filter_records(records, min_cvss=9.0, keywords=("ssh",), limit=10)

    assert len(selected) == 1
    assert selected[0].cve_id == "CVE-1"


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
