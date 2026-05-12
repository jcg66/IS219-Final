"""Tests for the Sprint 03 analyst pipeline."""

from __future__ import annotations

from dataclasses import dataclass

from src.analyst import SAFE_NO_MATCH_VERDICT, SAFE_TIMEOUT_VERDICT, analyze_log, generate_verdict, parse_log


@dataclass(frozen=True)
class FakeScoredPoint:
    payload: dict[str, object] | None
    score: float


class FakeQdrantClient:
    def __init__(self, search_results: list[FakeScoredPoint]) -> None:
        self.search_results = search_results
        self.search_calls: list[dict[str, object]] = []

    def search(self, **kwargs):
        self.search_calls.append(kwargs)
        return self.search_results


class FakeGroqClient:
    def __init__(self, response: str) -> None:
        self.response = response
        self.calls: list[tuple[str, str]] = []

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        self.calls.append((system_prompt, user_prompt))
        return self.response


class TimeoutGroqClient:
    def generate(self, system_prompt: str, user_prompt: str) -> str:
        raise TimeoutError("timed out")


def _fake_embedder(texts: list[str]) -> list[list[float]]:
    return [[float(len(text)), 1.0, 0.0] for text in texts]


def test_parse_syslog_log_extracts_timestamp_service_and_ip() -> None:
    parsed = parse_log("May 12 10:11:12 host sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2")

    assert parsed.timestamp == "May 12 10:11:12"
    assert parsed.service == "sshd"
    assert parsed.ip_address == "10.0.0.5"
    assert "Failed password" in parsed.message


def test_parse_iso_log_extracts_service_and_message() -> None:
    parsed = parse_log("2026-05-12T10:11:12Z sshd[55]: Accepted password for admin from 192.168.1.15 port 22")

    assert parsed.timestamp == "2026-05-12T10:11:12Z"
    assert parsed.service == "sshd"
    assert parsed.ip_address == "192.168.1.15"
    assert parsed.message.startswith("Accepted password")


def test_parse_log_normalizes_external_whitespace_before_parsing() -> None:
    parsed = parse_log("  May 12 10:11:12\thost sshd[1234]: Failed password for root \nfrom 10.0.0.5 port 22 ssh2  ")

    assert parsed.timestamp == "May 12 10:11:12"
    assert parsed.service == "sshd"
    assert parsed.ip_address == "10.0.0.5"
    assert parsed.message.startswith("Failed password")


def test_analyze_log_returns_grounded_verdict_when_matches_exist() -> None:
    qdrant_client = FakeQdrantClient(
        [
            FakeScoredPoint(
                payload={
                    "cve_id": "CVE-2025-0100",
                    "description": "SSH brute force authentication weakness.",
                    "cvss_score": 9.8,
                },
                score=0.91,
            )
        ]
    )
    groq_client = FakeGroqClient("Analyst Verdict: High Risk. SSH brute force pattern matched the retrieved CVE.")

    report = analyze_log(
        "May 12 10:11:12 host sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2",
        qdrant_client,
        _fake_embedder,
        groq_client,
    )

    assert report.parsed_log.service == "sshd"
    assert report.retrieved_cves[0].cve_id == "CVE-2025-0100"
    assert report.verdict.startswith("Analyst Verdict: High Risk")
    assert groq_client.calls
    assert "CVE-2025-0100" in groq_client.calls[0][1]


def test_benign_log_returns_safe_verdict_without_groq_call() -> None:
    qdrant_client = FakeQdrantClient([])
    groq_client = FakeGroqClient("Analyst Verdict: Threat detected.")

    report = analyze_log(
        "May 12 12:00:00 host cron[1000]: session opened for user backup",
        qdrant_client,
        _fake_embedder,
        groq_client,
    )

    assert report.retrieved_cves == []
    assert report.verdict == SAFE_NO_MATCH_VERDICT
    assert groq_client.calls == []


def test_generate_verdict_returns_safe_no_match_without_calling_groq() -> None:
    parsed = parse_log("May 12 12:00:00 host cron[1000]: session opened for user backup")

    verdict = generate_verdict(parsed, [], groq_client=TimeoutGroqClient())

    assert verdict == SAFE_NO_MATCH_VERDICT


def test_analyze_log_uses_safe_timeout_verdict_when_groq_times_out() -> None:
    qdrant_client = FakeQdrantClient(
        [
            FakeScoredPoint(
                payload={
                    "cve_id": "CVE-2025-0100",
                    "description": "SSH brute force authentication weakness.",
                    "cvss_score": 9.8,
                },
                score=0.91,
            )
        ]
    )

    report = analyze_log(
        "May 12 10:11:12 host sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2",
        qdrant_client,
        _fake_embedder,
        TimeoutGroqClient(),
    )

    assert report.verdict == SAFE_TIMEOUT_VERDICT


def test_analyze_log_raises_clear_error_when_embedder_returns_no_vector() -> None:
    qdrant_client = FakeQdrantClient([])

    def empty_embedder(texts: list[str]) -> list[list[float]]:
        return []

    try:
        analyze_log(
            "May 12 10:11:12 host sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2",
            qdrant_client,
            empty_embedder,
            FakeGroqClient("unused"),
        )
    except RuntimeError as error:
        assert "returned no vector" in str(error)
    else:  # pragma: no cover - defensive assertion
        raise AssertionError("Expected a RuntimeError when the embedder returns no vectors")
