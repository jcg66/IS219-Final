"""Ingestion helpers for Semantic SOC Analyst.

This module focuses on pulling a small CVE sample, normalizing it, and
storing it in a local Qdrant collection without duplicating records across
re-ingestion runs.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import logging
import uuid
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

from src.preprocessing import normalize_text

logger = logging.getLogger(__name__)

DEFAULT_COLLECTION_NAME = "semantic_soc_cves"
DEFAULT_SAMPLE_JSON = Path("data/samples/nvd-sample-2025.json")
DEFAULT_FULL_FEED_JSON = Path("data/nvdcve-2.0-2025.json")
DEFAULT_NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass(frozen=True)
class CVERecord:
    """Normalized CVE data used for vector storage."""

    cve_id: str
    description: str
    cvss_score: float


def load_nvd_records(
    local_path: str | Path | None = None,
    source_url: str | None = None,
    timeout_seconds: float = 20.0,
) -> list[CVERecord]:
    """Load NVD data from a local JSON file or an HTTP endpoint.

    The local file is preferred when available so the project can work fully
    offline for demo and testing purposes.
    """

    candidate_paths = [Path(local_path)] if local_path is not None else [DEFAULT_SAMPLE_JSON, DEFAULT_FULL_FEED_JSON]
    for resolved_path in candidate_paths:
        if resolved_path.exists():
            logger.info("Loading NVD sample from %s", resolved_path)
            return _parse_nvd_payload(_read_json(resolved_path))

    if source_url:
        logger.info("Fetching NVD sample from %s", source_url)
        payload = _fetch_json(source_url, timeout_seconds)
        return _parse_nvd_payload(payload)

    logger.warning("No NVD source was available")
    return []


def load_nvd_api_records(
    api_key: str | None,
    *,
    base_url: str = DEFAULT_NVD_API_URL,
    timeout_seconds: float = 20.0,
    results_per_page: int = 200,
    max_records: int = 500,
    keyword_search: str | None = None,
    severity: str | None = None,
) -> list[CVERecord]:
    """Load a bounded NVD sample directly from the live NVD API."""

    headers = {"apiKey": api_key} if api_key else None
    collected: list[CVERecord] = []
    start_index = 0

    while len(collected) < max_records:
        batch_size = min(results_per_page, max_records - len(collected))
        params: dict[str, object] = {
            "resultsPerPage": batch_size,
            "startIndex": start_index,
        }
        if keyword_search:
            params["keywordSearch"] = keyword_search
        if severity:
            params["cvssV3Severity"] = severity

        payload = _fetch_json(base_url, timeout_seconds, headers=headers, params=params)
        batch = _parse_nvd_payload(payload)
        if not batch:
            break

        collected.extend(batch)
        total_results = int(payload.get("totalResults", len(collected))) if isinstance(payload, dict) else len(collected)
        start_index += len(batch)
        if start_index >= total_results:
            break

    return collected[:max_records]


def filter_records(
    records: Iterable[CVERecord],
    *,
    min_cvss: float = 9.0,
    keywords: Sequence[str] = ("ssh", "rdp"),
    limit: int = 500,
) -> list[CVERecord]:
    """Reduce the dataset to a manageable, high-signal subset."""

    selected: list[CVERecord] = []
    keyword_set = tuple(keyword.lower() for keyword in keywords)

    for record in records:
        description = record.description.lower()
        if record.cvss_score >= min_cvss or any(keyword in description for keyword in keyword_set):
            selected.append(record)
        if len(selected) >= limit:
            break

    return selected


def prepare_cve_records(
    records: Iterable[CVERecord],
    *,
    min_cvss: float = 9.0,
    keywords: Sequence[str] = ("ssh", "rdp"),
    limit: int = 500,
) -> list[CVERecord]:
    """Filter, normalize, and deduplicate CVE records for ingestion."""

    filtered = sorted(
        filter_records(records, min_cvss=min_cvss, keywords=keywords, limit=limit),
        key=lambda record: (-record.cvss_score, record.cve_id),
    )
    prepared: list[CVERecord] = []
    seen_ids: set[str] = set()

    for record in filtered:
        if record.cve_id in seen_ids:
            continue
        seen_ids.add(record.cve_id)
        normalized_description = normalize_text(record.description)
        if not normalized_description:
            continue
        prepared.append(
            CVERecord(
                cve_id=record.cve_id,
                description=normalized_description,
                cvss_score=record.cvss_score,
            )
        )

    return prepared[:limit]


def ingest_records(
    records: Sequence[CVERecord],
    client: Any,
    embedder: Callable[[Sequence[str]], Sequence[Sequence[float]]],
    *,
    collection_name: str = DEFAULT_COLLECTION_NAME,
) -> int:
    """Store records in Qdrant using stable point IDs.

    Re-running this function with the same records upserts the same point IDs,
    so the collection remains deduplicated.
    """

    if not records:
        logger.info("No CVE records supplied for ingestion")
        return 0

    from qdrant_client.http import models

    sample_vectors = list(embedder([records[0].description]))
    if not sample_vectors or not sample_vectors[0]:
        raise RuntimeError("Embedder returned no vector for CVE ingestion.")

    _ensure_collection(client, collection_name, len(sample_vectors[0]))

    descriptions = [record.description for record in records]
    vectors = list(embedder(descriptions))
    if len(vectors) != len(records):
        raise ValueError("Embedder returned a mismatched number of vectors")
    if any(not vector for vector in vectors):
        raise RuntimeError("Embedder returned an empty vector during CVE ingestion.")

    points = []
    for record, vector in zip(records, vectors, strict=True):
        points.append(
            models.PointStruct(
                id=str(uuid.uuid5(uuid.NAMESPACE_URL, record.cve_id)),
                vector=list(vector),
                payload={
                    "cve_id": record.cve_id,
                    "description": record.description,
                    "cvss_score": record.cvss_score,
                },
            )
        )

    logger.info("Upserting %d CVE records into Qdrant collection %s", len(points), collection_name)
    client.upsert(collection_name=collection_name, points=points)
    return len(points)


def count_points(client: Any, collection_name: str = DEFAULT_COLLECTION_NAME) -> int:
    """Count points in a Qdrant collection using a scroll query."""

    points, _ = client.scroll(
        collection_name=collection_name,
        limit=10_000,
        with_payload=False,
        with_vectors=False,
    )
    return len(points)


def _ensure_collection(client: Any, collection_name: str, vector_size: int) -> None:
    """Create the target collection if it does not already exist."""

    from qdrant_client.http import models

    if client.collection_exists(collection_name):
        logger.info("Qdrant collection %s already exists", collection_name)
        return

    logger.info("Creating Qdrant collection %s", collection_name)
    client.create_collection(
        collection_name=collection_name,
        vectors_config=models.VectorParams(size=vector_size, distance=models.Distance.COSINE),
    )


def _read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as file_handle:
        return json.load(file_handle)


def _fetch_json(
    url: str,
    timeout_seconds: float,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, object] | None = None,
) -> Any:
    try:
        import requests
    except ImportError as error:  # pragma: no cover - only relevant in minimal installs
        raise RuntimeError("requests is required to fetch remote NVD data") from error

    try:
        response = requests.get(url, headers=headers, params=params, timeout=timeout_seconds)
        response.raise_for_status()
        return response.json()
    except requests.Timeout as error:
        raise TimeoutError("NVD request timed out") from error
    except requests.RequestException as error:
        raise RuntimeError(f"NVD request failed: {error}") from error


def _parse_nvd_payload(payload: Any) -> list[CVERecord]:
    if isinstance(payload, list):
        return [record for record in (_normalize_record(item) for item in payload) if record is not None]

    vulnerabilities = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
    return [record for record in (_normalize_record(item) for item in vulnerabilities) if record is not None]


def _normalize_record(item: Any) -> CVERecord | None:
    if not isinstance(item, dict):
        return None

    if {"cve_id", "description", "cvss_score"}.issubset(item):
        try:
            return CVERecord(
                cve_id=str(item["cve_id"]),
                description=str(item["description"]),
                cvss_score=float(item["cvss_score"]),
            )
        except (TypeError, ValueError):
            return None

    cve = item.get("cve")
    if not isinstance(cve, dict):
        return None

    cve_id = cve.get("id")
    description = normalize_text(_extract_description(cve))
    cvss_score = _extract_cvss_score(cve)

    if not cve_id or not description:
        return None

    return CVERecord(cve_id=str(cve_id), description=description, cvss_score=cvss_score)


def _extract_description(cve: dict[str, Any]) -> str:
    descriptions = cve.get("descriptions", [])
    for entry in descriptions:
        if isinstance(entry, dict) and entry.get("lang") == "en" and entry.get("value"):
            return str(entry["value"])
    return ""


def _extract_cvss_score(cve: dict[str, Any]) -> float:
    metrics = cve.get("metrics", {})
    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_entries = metrics.get(metric_key, [])
        if not metric_entries:
            continue
        first_entry = metric_entries[0]
        if not isinstance(first_entry, dict):
            continue
        cvss_data = first_entry.get("cvssData", {})
        score = cvss_data.get("baseScore")
        try:
            return float(score)
        except (TypeError, ValueError):
            continue
    return 0.0
