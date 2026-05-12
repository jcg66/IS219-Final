"""Analyst pipeline for Semantic SOC Analyst.

This module parses raw logs, retrieves related CVEs from Qdrant, and builds a
grounded verdict using retrieved context and a strict SOC analyst prompt.
"""

from __future__ import annotations

from dataclasses import dataclass
import logging
import re
from typing import Any, Callable, Sequence

from src.ingestion import DEFAULT_COLLECTION_NAME
from src.settings import AppSettings, load_dotenv_if_available, load_settings

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "You are a Senior SOC Analyst. Use only the provided context to analyze the log. "
    "If no match is found, state that no known vulnerability was identified."
)


@dataclass(frozen=True)
class ParsedLog:
    """Structured log data extracted from a raw security event."""

    raw_text: str
    timestamp: str | None
    ip_address: str | None
    service: str | None
    message: str


@dataclass(frozen=True)
class RetrievedCVE:
    """Relevant CVE context returned from the vector store."""

    cve_id: str
    description: str
    cvss_score: float
    score: float


@dataclass(frozen=True)
class AnalystReport:
    """Final result returned by the analyst pipeline."""

    parsed_log: ParsedLog
    retrieved_cves: list[RetrievedCVE]
    verdict: str


TIMESTAMP_PATTERNS = (
    re.compile(r"\b(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\b"),
    re.compile(r"\b(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b"),
)
IP_PATTERN = re.compile(r"\b(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\b")
SYSLOG_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<service>[A-Za-z0-9._/-]+)(?:\[\d+\])?:\s+(?P<message>.+)$"
)
ISO_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+"
    r"(?P<service>[A-Za-z0-9._/-]+)(?:\[\d+\])?:\s+(?P<message>.+)$"
)


def parse_log(raw_text: str) -> ParsedLog:
    """Parse common SSH and syslog-style log strings."""

    text = raw_text.strip()
    timestamp = _extract_timestamp(text)
    ip_address = _extract_ip(text)

    service = None
    message = text

    syslog_match = SYSLOG_PATTERN.match(text)
    if syslog_match:
        service = syslog_match.group("service")
        message = syslog_match.group("message")
    else:
        iso_match = ISO_PATTERN.match(text)
        if iso_match:
            service = iso_match.group("service")
            message = iso_match.group("message")
        else:
            service = _infer_service(text)
            message = _extract_message(text)

    return ParsedLog(
        raw_text=text,
        timestamp=timestamp,
        ip_address=ip_address,
        service=service,
        message=message,
    )


def retrieve_similar_cves(
    log_text: str,
    client: Any,
    embedder: Callable[[Sequence[str]], Sequence[Sequence[float]]],
    *,
    collection_name: str = DEFAULT_COLLECTION_NAME,
    top_k: int = 3,
    min_score: float = 0.25,
) -> list[RetrievedCVE]:
    """Retrieve the top matching CVEs for a log entry."""

    logger.info("Querying Qdrant...")
    query_vector = list(embedder([log_text])[0])
    search_results = client.search(
        collection_name=collection_name,
        query_vector=query_vector,
        limit=top_k,
        with_payload=True,
        with_vectors=False,
    )

    retrieved: list[RetrievedCVE] = []
    for item in search_results:
        payload = item.payload or {}
        if item.score < min_score:
            continue
        cve_id = str(payload.get("cve_id", "unknown"))
        description = str(payload.get("description", ""))
        cvss_score = float(payload.get("cvss_score", 0.0))
        retrieved.append(
            RetrievedCVE(
                cve_id=cve_id,
                description=description,
                cvss_score=cvss_score,
                score=float(item.score),
            )
        )

    return retrieved


def build_prompt(parsed_log: ParsedLog, retrieved_cves: Sequence[RetrievedCVE]) -> str:
    """Build the user prompt for the analyst model."""

    context_lines = [
        f"Log: {parsed_log.raw_text}",
        f"Parsed service: {parsed_log.service or 'unknown'}",
        f"Parsed timestamp: {parsed_log.timestamp or 'unknown'}",
        f"Parsed IP: {parsed_log.ip_address or 'unknown'}",
        "Retrieved CVE context:",
    ]

    if retrieved_cves:
        for index, cve in enumerate(retrieved_cves, start=1):
            context_lines.append(
                f"{index}. {cve.cve_id} | CVSS {cve.cvss_score:.1f} | similarity {cve.score:.3f} | {cve.description}"
            )
    else:
        context_lines.append("No known vulnerability matched the log.")

    return "\n".join(context_lines)


def generate_verdict(
    parsed_log: ParsedLog,
    retrieved_cves: Sequence[RetrievedCVE],
    groq_client: Any | None = None,
    *,
    settings: AppSettings | None = None,
) -> str:
    """Generate a grounded verdict.

    When no retrieval context is available, the function returns a safe
    deterministic verdict instead of invoking the model.
    """

    if not retrieved_cves:
        logger.info("No matching CVEs found; returning safe verdict")
        return "Analyst Verdict: No known vulnerability was identified."

    prompt = build_prompt(parsed_log, retrieved_cves)
    logger.info("Generating Verdict...")

    if groq_client is None:
        settings = settings or load_settings()
        groq_client = GroqChatClient(api_key=settings.groq_api_key)

    verdict = groq_client.generate(SYSTEM_PROMPT, prompt)
    return verdict.strip()


def analyze_log(
    raw_text: str,
    client: Any,
    embedder: Callable[[Sequence[str]], Sequence[Sequence[float]]],
    groq_client: Any | None = None,
    *,
    collection_name: str = DEFAULT_COLLECTION_NAME,
) -> AnalystReport:
    """Run the full analyst pipeline for a raw log entry."""

    load_dotenv_if_available()
    parsed_log = parse_log(raw_text)
    retrieved_cves = retrieve_similar_cves(
        parsed_log.message or parsed_log.raw_text,
        client,
        embedder,
        collection_name=collection_name,
    )
    verdict = generate_verdict(parsed_log, retrieved_cves, groq_client=groq_client)
    return AnalystReport(parsed_log=parsed_log, retrieved_cves=list(retrieved_cves), verdict=verdict)


class GroqChatClient:
    """Minimal Groq chat client used by the analyst pipeline."""

    def __init__(self, api_key: str | None, model: str = "llama3-8b-8192") -> None:
        self.api_key = api_key
        self.model = model

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        if not self.api_key:
            return "Analyst Verdict: No known vulnerability was identified."

        import requests

        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": 0,
            },
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()
        return str(data["choices"][0]["message"]["content"])


def _extract_timestamp(text: str) -> str | None:
    for pattern in TIMESTAMP_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group("timestamp")
    return None


def _extract_ip(text: str) -> str | None:
    match = IP_PATTERN.search(text)
    return match.group("ip") if match else None


def _infer_service(text: str) -> str | None:
    lowered = text.lower()
    if "sshd" in lowered:
        return "sshd"
    if "ssh" in lowered:
        return "ssh"
    if "syslog" in lowered:
        return "syslog"
    return None


def _extract_message(text: str) -> str:
    if ": " in text:
        return text.split(": ", 1)[1]
    return text