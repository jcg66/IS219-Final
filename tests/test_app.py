"""Tests for the Sprint 04 Streamlit dashboard helpers."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass

import sys

from qdrant_client import QdrantClient

from src.analyst import AnalystReport, ParsedLog, RetrievedCVE
from src.app import (
    ANALYSIS_STATUS_MESSAGE,
    DEMO_COLLECTION_NAME,
    DashboardRuntime,
    PROJECT_ROOT,
    UIAnalysisResult,
    build_demo_embedder,
    build_display_sections,
    normalize_embedding_payload,
    render_dashboard,
    resolve_log_input,
    submit_log_for_analysis,
)


@dataclass(frozen=True)
class FakeUploadedFile:
    content: bytes
    name: str = "log.txt"

    def getvalue(self) -> bytes:
        return self.content


class FakeGroqClient:
    def __init__(self, response: str) -> None:
        self.response = response
        self.calls: list[tuple[str, str]] = []

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        self.calls.append((system_prompt, user_prompt))
        return self.response


class BrokenQdrantClient:
    def collection_exists(self, collection_name: str) -> bool:
        return True

    def search(self, **kwargs):
        raise RuntimeError("vector store offline")


class FakeStreamlit:
    def __init__(self, *, pasted_log: str = "", uploaded_file: FakeUploadedFile | None = None, run_clicked: bool = False) -> None:
        self.pasted_log = pasted_log
        self.uploaded_file = uploaded_file
        self.run_clicked = run_clicked
        self.messages: list[tuple[str, str]] = []

    def set_page_config(self, **kwargs) -> None:
        self.messages.append(("config", kwargs["page_title"]))

    def title(self, text: str) -> None:
        self.messages.append(("title", text))

    def caption(self, text: str) -> None:
        self.messages.append(("caption", text))

    def info(self, text: str) -> None:
        self.messages.append(("info", text))

    def text_area(self, label: str, **kwargs) -> str:
        self.messages.append(("text_area", label))
        return self.pasted_log

    def file_uploader(self, label: str, **kwargs) -> FakeUploadedFile | None:
        self.messages.append(("file_uploader", label))
        return self.uploaded_file

    def button(self, label: str, **kwargs) -> bool:
        self.messages.append(("button", label))
        return self.run_clicked

    @contextmanager
    def spinner(self, text: str):
        self.messages.append(("spinner", text))
        yield

    def error(self, text: str) -> None:
        self.messages.append(("error", text))

    def success(self, text: str) -> None:
        self.messages.append(("success", text))

    def subheader(self, text: str) -> None:
        self.messages.append(("subheader", text))

    def write(self, text: str) -> None:
        self.messages.append(("write", text))


def test_resolve_log_input_prefers_pasted_text() -> None:
    result = resolve_log_input("  pasted log  ", FakeUploadedFile(b"ignored"))

    assert result == "pasted log"


def test_app_bootstraps_project_root_for_streamlit_script_execution() -> None:
    assert str(PROJECT_ROOT) in sys.path


def test_resolve_log_input_reads_uploaded_file_when_no_paste() -> None:
    result = resolve_log_input("", FakeUploadedFile(b"May 12 10:11:12 host sshd[1]: Failed password"))

    assert "Failed password" in result


def test_resolve_log_input_normalizes_csv_log_rows() -> None:
    csv_text = (
        "timestamp,service,message\n"
        "2026-05-12T10:11:12Z,sshd,Failed password for root from 10.0.0.5 port 22 ssh2\n"
    )

    result = resolve_log_input(
        "",
        FakeUploadedFile(csv_text.encode("utf-8"), name="ssh-illegal-login-attempts.csv"),
    )

    assert "Failed password" in result
    assert "sshd" in result


def test_resolve_log_input_normalizes_json_log_rows() -> None:
    json_text = (
        "[{\"timestamp\": \"2026-05-12T10:11:12Z\", \"service\": \"sshd\", "
        "\"message\": \"Failed password for root from 10.0.0.5 port 22 ssh2\"}]"
    )

    result = resolve_log_input("", FakeUploadedFile(json_text.encode("utf-8"), name="ssh-illegal-login-attempts.json"))

    assert "Failed password" in result
    assert "service=sshd" in result


def test_normalize_embedding_payload_averages_token_vectors() -> None:
    payload = [[1.0, 3.0, 5.0], [3.0, 5.0, 7.0]]

    assert normalize_embedding_payload(payload) == [2.0, 4.0, 6.0]


def test_normalize_embedding_payload_rejects_invalid_payload() -> None:
    try:
        normalize_embedding_payload([])
    except ValueError as error:
        assert "empty or invalid" in str(error)
    else:  # pragma: no cover - defensive assertion
        raise AssertionError("Expected ValueError for an empty embedding payload")


def test_huggingface_embedder_uses_inference_client(monkeypatch) -> None:
    from src.app import HuggingFaceEmbedder

    class FakeInferenceClient:
        def __init__(self, api_key: str) -> None:
            assert api_key == "hf-test-token"

        def feature_extraction(self, text: str, *, model: str):
            assert model == "sentence-transformers/all-MiniLM-L6-v2"
            return [[1.0, 2.0, 3.0], [3.0, 4.0, 5.0]]

    monkeypatch.setattr("huggingface_hub.InferenceClient", FakeInferenceClient)

    embedder = HuggingFaceEmbedder("hf-test-token")
    vectors = embedder(["failed password for root"])

    assert vectors == [[2.0, 3.0, 4.0]]


def test_submit_log_for_analysis_bootstraps_demo_collection() -> None:
    client = QdrantClient(location=":memory:")
    fake_groq = FakeGroqClient("Analyst Verdict: High Risk. Retrieved SSH context supports the finding.")

    result = submit_log_for_analysis(
        "May 12 10:11:12 host sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2",
        qdrant_client=client,
        embedder=build_demo_embedder(),
        groq_client=fake_groq,
        collection_name=DEMO_COLLECTION_NAME,
        bootstrap_demo=True,
    )
    if hasattr(client, "close"):
        client.close()

    assert result.error_message is None
    assert result.report is not None
    assert result.report.retrieved_cves
    assert result.report.verdict.startswith("Analyst Verdict: High Risk")
    sections = build_display_sections(result)
    assert sections["verdict"] == result.report.verdict
    assert any("CVE-DEMO-SSH-001" in line for line in sections["evidence_lines"])


def test_submit_log_for_analysis_reports_missing_live_collection() -> None:
    client = QdrantClient(location=":memory:")
    result = submit_log_for_analysis(
        "May 12 10:11:12 host sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2",
        qdrant_client=client,
        embedder=build_demo_embedder(),
        groq_client=FakeGroqClient("unused"),
        bootstrap_demo=False,
    )
    if hasattr(client, "close"):
        client.close()

    assert result.report is None
    assert result.error_message is not None
    assert "Run the ingestion workflow" in result.error_message


def test_submit_log_for_analysis_handles_backend_error() -> None:
    result = submit_log_for_analysis(
        "May 12 12:00:00 host cron[1000]: session opened for user backup",
        qdrant_client=BrokenQdrantClient(),
        embedder=build_demo_embedder(),
        groq_client=FakeGroqClient("unused"),
        collection_name=DEMO_COLLECTION_NAME,
        bootstrap_demo=False,
    )

    assert result.report is None
    assert result.error_message is not None
    assert "Analysis failed" in result.error_message


def test_build_display_sections_for_empty_submission() -> None:
    result = submit_log_for_analysis("", qdrant_client=BrokenQdrantClient(), embedder=build_demo_embedder())
    sections = build_display_sections(result)

    assert sections["verdict"] is None
    assert sections["message"] == "Paste a log or upload a file before submitting."

def test_build_display_sections_truncates_large_parsed_message() -> None:
    long_message = "Failed password for root from 10.0.0.5 port 22 ssh2 " * 80
    result = UIAnalysisResult(
        raw_text=long_message,
        report=AnalystReport(
            parsed_log=ParsedLog(
                raw_text=long_message,
                timestamp="May 12 10:11:12",
                ip_address="10.0.0.5",
                service="sshd",
                message=long_message,
            ),
            retrieved_cves=[],
            verdict="Analyst Verdict: No known vulnerability was identified.",
        ),
    )

    sections = build_display_sections(result)

    message_line = next(line for line in sections["parsed_lines"] if line.startswith("Message: "))
    assert len(message_line) < len("Message: ") + len(long_message)
    assert "[truncated for display]" in message_line


def test_render_dashboard_shows_runtime_status_and_verdict(monkeypatch) -> None:
    fake_st = FakeStreamlit(
        pasted_log="May 12 10:11:12 host sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2",
        run_clicked=True,
    )
    fake_runtime = DashboardRuntime(
        qdrant_client=object(),
        embedder=build_demo_embedder(),
        groq_client=FakeGroqClient("unused"),
        collection_name=DEMO_COLLECTION_NAME,
        bootstrap_demo=True,
        status_message="Demo mode: using local sample data.",
    )

    def fake_submit(log_text: str, **kwargs):
        return UIAnalysisResult(
            raw_text=log_text,
            report=AnalystReport(
                parsed_log=ParsedLog(
                    raw_text=log_text,
                    timestamp="May 12 10:11:12",
                    ip_address="10.0.0.5",
                    service="sshd",
                    message="Failed password for root from 10.0.0.5 port 22 ssh2",
                ),
                retrieved_cves=[
                    RetrievedCVE(
                        cve_id="CVE-DEMO-SSH-001",
                        description="SSH brute-force authentication weakness affecting login handling.",
                        cvss_score=9.8,
                        score=0.991,
                    )
                ],
                verdict="Analyst Verdict: High Risk. Retrieved SSH context supports the finding.",
            ),
        )

    monkeypatch.setattr("src.app.build_dashboard_runtime", lambda settings=None: fake_runtime)
    monkeypatch.setattr("src.app.submit_log_for_analysis", fake_submit)

    render_dashboard(fake_st)

    assert ("info", "Demo mode: using local sample data.") in fake_st.messages
    assert ("spinner", ANALYSIS_STATUS_MESSAGE) in fake_st.messages
    assert ("success", "Analyst verdict ready.") in fake_st.messages
    assert any(item == ("subheader", "Retrieved Context") for item in fake_st.messages)
    assert any(message[0] == "write" and "Analyst Verdict:" in message[1] for message in fake_st.messages)
