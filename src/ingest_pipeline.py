"""User-facing ingestion workflow for Semantic SOC Analyst."""

from __future__ import annotations

from dataclasses import dataclass
import argparse
import logging
from pathlib import Path
from typing import Any, Callable, Sequence

from src.ingestion import (
    DEFAULT_COLLECTION_NAME,
    DEFAULT_SAMPLE_JSON,
    CVERecord,
    count_points,
    ingest_records,
    load_nvd_api_records,
    load_nvd_records,
    prepare_cve_records,
)
from src.settings import AppSettings, load_dotenv_if_available, load_settings

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class IngestionWorkflowResult:
    """Summary returned by the manual ingestion workflow."""

    source: str
    source_records: int
    prepared_records: int
    upserted_records: int
    point_count: int
    collection_name: str
    dry_run: bool


def run_ingestion_workflow(
    *,
    source: str = "sample",
    local_path: str | Path | None = None,
    collection_name: str = DEFAULT_COLLECTION_NAME,
    limit: int = 75,
    min_cvss: float = 9.0,
    keywords: Sequence[str] = ("ssh", "rdp"),
    api_severity: str | None = "CRITICAL",
    api_keyword_search: str | None = None,
    timeout_seconds: float = 20.0,
    dry_run: bool = False,
    settings: AppSettings | None = None,
    client: Any | None = None,
    embedder: Callable[[Sequence[str]], Sequence[Sequence[float]]] | None = None,
) -> IngestionWorkflowResult:
    """Load, prepare, and optionally ingest CVE records into Qdrant."""

    load_dotenv_if_available()
    settings = settings or load_settings()
    source_records = _load_source_records(
        source,
        settings,
        local_path=local_path,
        timeout_seconds=timeout_seconds,
        api_severity=api_severity,
        api_keyword_search=api_keyword_search,
        limit=limit,
    )
    prepared_records = prepare_cve_records(source_records, min_cvss=min_cvss, keywords=keywords, limit=limit)

    if dry_run:
        return IngestionWorkflowResult(
            source=source,
            source_records=len(source_records),
            prepared_records=len(prepared_records),
            upserted_records=0,
            point_count=0,
            collection_name=collection_name,
            dry_run=True,
        )

    if not settings.hf_token:
        raise RuntimeError("HF_TOKEN is required to run live ingestion. Add it to the root .env file first.")

    client = client or _create_qdrant_client(settings)
    embedder = embedder or _create_embedder(settings)
    upserted_records = ingest_records(prepared_records, client, embedder, collection_name=collection_name)
    point_count = count_points(client, collection_name)
    return IngestionWorkflowResult(
        source=source,
        source_records=len(source_records),
        prepared_records=len(prepared_records),
        upserted_records=upserted_records,
        point_count=point_count,
        collection_name=collection_name,
        dry_run=False,
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser for the manual ingestion workflow."""

    parser = argparse.ArgumentParser(description="Prepare and ingest CVE data into the local Qdrant collection.")
    parser.add_argument("--source", choices=("sample", "file", "api"), default="sample")
    parser.add_argument("--local-path", help="Path to a local NVD JSON file when using --source file.")
    parser.add_argument("--collection", default=DEFAULT_COLLECTION_NAME)
    parser.add_argument("--limit", type=int, default=75)
    parser.add_argument("--min-cvss", type=float, default=9.0)
    parser.add_argument("--keywords", default="ssh,rdp", help="Comma-separated keywords used during record filtering.")
    parser.add_argument("--api-severity", default="CRITICAL")
    parser.add_argument("--api-keyword-search", default=None)
    parser.add_argument("--timeout-seconds", type=float, default=20.0)
    parser.add_argument("--dry-run", action="store_true", help="Load and prepare records without embedding or writing.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint for manual ingestion."""

    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
    parser = build_parser()
    args = parser.parse_args(argv)
    keywords = tuple(keyword.strip().lower() for keyword in args.keywords.split(",") if keyword.strip())
    result = run_ingestion_workflow(
        source=args.source,
        local_path=args.local_path,
        collection_name=args.collection,
        limit=args.limit,
        min_cvss=args.min_cvss,
        keywords=keywords or ("ssh", "rdp"),
        api_severity=args.api_severity,
        api_keyword_search=args.api_keyword_search,
        timeout_seconds=args.timeout_seconds,
        dry_run=args.dry_run,
    )
    print(_format_result(result))
    return 0


def _load_source_records(
    source: str,
    settings: AppSettings,
    *,
    local_path: str | Path | None,
    timeout_seconds: float,
    api_severity: str | None,
    api_keyword_search: str | None,
    limit: int,
) -> list[CVERecord]:
    if source == "sample":
        return load_nvd_records(local_path=DEFAULT_SAMPLE_JSON, timeout_seconds=timeout_seconds)
    if source == "file":
        if local_path is None:
            raise RuntimeError("--local-path is required when using --source file.")
        return load_nvd_records(local_path=local_path, timeout_seconds=timeout_seconds)
    if source == "api":
        return load_nvd_api_records(
            settings.nvd_api_key,
            timeout_seconds=timeout_seconds,
            max_records=limit,
            severity=api_severity,
            keyword_search=api_keyword_search,
        )
    raise RuntimeError(f"Unsupported ingestion source: {source}")


def _create_qdrant_client(settings: AppSettings) -> Any:
    from src.app import create_qdrant_client

    return create_qdrant_client(settings)


def _create_embedder(settings: AppSettings) -> Callable[[Sequence[str]], Sequence[Sequence[float]]]:
    from src.app import create_embedder

    return create_embedder(settings)


def _format_result(result: IngestionWorkflowResult) -> str:
    return (
        f"source={result.source} "
        f"source_records={result.source_records} "
        f"prepared_records={result.prepared_records} "
        f"upserted_records={result.upserted_records} "
        f"point_count={result.point_count} "
        f"collection={result.collection_name} "
        f"dry_run={result.dry_run}"
    )


if __name__ == "__main__":
    raise SystemExit(main())
