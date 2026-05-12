"""Streamlit dashboard for Semantic SOC Analyst.

The UI stays thin and delegates the actual analysis to testable helper
functions so the operator flow can be verified without starting a browser.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import logging
from typing import Any, Callable, Iterator, Sequence

try:  # pragma: no cover - exercised indirectly in runtime environments
    import streamlit as st
except ImportError:  # pragma: no cover - enables import-safe tests
    st = None

from qdrant_client import QdrantClient

from src.analyst import AnalystReport, GroqChatClient, analyze_log
from src.ingestion import CVERecord, DEFAULT_COLLECTION_NAME, count_points, ingest_records
from src.settings import AppSettings, load_dotenv_if_available, load_settings

logger = logging.getLogger(__name__)

DEMO_COLLECTION_NAME = f"{DEFAULT_COLLECTION_NAME}_demo"
DEFAULT_HF_EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
ANALYSIS_STATUS_MESSAGE = "Analyzing log, retrieving CVE context, and generating a verdict..."


@dataclass(frozen=True)
class UIAnalysisResult:
    """Result returned by the UI layer after a submission attempt."""

    raw_text: str
    report: AnalystReport | None
    error_message: str | None = None


@dataclass(frozen=True)
class DashboardRuntime:
    """Runtime dependencies selected for the dashboard."""

    qdrant_client: Any
    embedder: Callable[[Sequence[str]], Sequence[Sequence[float]]]
    groq_client: Any
    collection_name: str
    bootstrap_demo: bool
    status_message: str


def resolve_log_input(pasted_log: str, uploaded_file: Any | None) -> str:
    """Choose the pasted log or the uploaded file contents."""

    pasted_text = pasted_log.strip()
    if pasted_text:
        return pasted_text

    if uploaded_file is None:
        return ""

    if hasattr(uploaded_file, "getvalue"):
        raw_bytes = uploaded_file.getvalue()
    elif hasattr(uploaded_file, "read"):
        raw_bytes = uploaded_file.read()
    else:
        raw_bytes = uploaded_file

    if isinstance(raw_bytes, bytes):
        return raw_bytes.decode("utf-8", errors="replace").strip()
    return str(raw_bytes).strip()


def build_demo_cve_records() -> list[CVERecord]:
    """Return a tiny on-device CVE sample for local UI demos."""

    return [
        CVERecord(
            cve_id="CVE-DEMO-SSH-001",
            description="SSH brute-force authentication weakness affecting login handling.",
            cvss_score=9.8,
        ),
        CVERecord(
            cve_id="CVE-DEMO-RDP-001",
            description="Remote desktop authentication bypass affecting RDP services.",
            cvss_score=9.4,
        ),
    ]


def build_demo_embedder() -> Callable[[Sequence[str]], Sequence[Sequence[float]]]:
    """Create a deterministic local embedder for demo and testing flows."""

    def embedder(texts: Sequence[str]) -> list[list[float]]:
        vectors: list[list[float]] = []
        for text in texts:
            lowered = text.lower()
            ssh_score = sum(lowered.count(keyword) for keyword in ("ssh", "sshd", "password", "login", "brute"))
            rdp_score = sum(lowered.count(keyword) for keyword in ("rdp", "remote desktop", "terminal services"))
            brute_score = sum(lowered.count(keyword) for keyword in ("failed", "bypass", "exploit", "attack"))
            vector = [float(ssh_score), float(rdp_score), float(brute_score)]
            if vector == [0.0, 0.0, 0.0]:
                vector = [0.01, 0.01, 0.01]
            vectors.append(vector)
        return vectors

    return embedder


def normalize_embedding_payload(payload: Any) -> list[float]:
    """Convert Hugging Face feature-extraction output to a single vector."""

    if not isinstance(payload, list) or not payload:
        raise ValueError("Embedding response was empty or invalid")

    if all(isinstance(value, (int, float)) for value in payload):
        return [float(value) for value in payload]

    rows: list[list[float]] = []
    for item in payload:
        if not isinstance(item, list) or not item:
            continue
        if not all(isinstance(value, (int, float)) for value in item):
            raise ValueError("Embedding response contained non-numeric values")
        rows.append([float(value) for value in item])

    if not rows:
        raise ValueError("Embedding response did not contain usable vectors")

    width = len(rows[0])
    if any(len(row) != width for row in rows):
        raise ValueError("Embedding response rows had inconsistent dimensions")

    return [sum(row[index] for row in rows) / len(rows) for index in range(width)]


class HuggingFaceEmbedder:
    """Minimal Hugging Face Inference API embedder."""

    def __init__(self, api_token: str, model: str = DEFAULT_HF_EMBEDDING_MODEL) -> None:
        self.api_token = api_token
        self.model = model
        self.url = f"https://api-inference.huggingface.co/pipeline/feature-extraction/{model}"

    def __call__(self, texts: Sequence[str]) -> list[list[float]]:
        import requests

        vectors: list[list[float]] = []
        headers = {"Authorization": f"Bearer {self.api_token}"}
        for text in texts:
            try:
                response = requests.post(
                    self.url,
                    headers=headers,
                    json={"inputs": text, "options": {"wait_for_model": True}},
                    timeout=60,
                )
                response.raise_for_status()
                vectors.append(normalize_embedding_payload(response.json()))
            except requests.Timeout as error:
                raise TimeoutError("Hugging Face embedding request timed out") from error
            except requests.RequestException as error:
                raise RuntimeError(f"Hugging Face embedding request failed: {error}") from error
        return vectors


class DemoGroqClient:
    """Local fallback that keeps the UI usable without a Groq key."""

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        prompt = user_prompt.lower()
        if "no known vulnerability" in prompt:
            return "Analyst Verdict: No known vulnerability was identified."
        if any(keyword in prompt for keyword in ("ssh", "password", "brute", "bypass")):
            return "Analyst Verdict: High Risk. The log aligns with the retrieved SSH context."
        if any(keyword in prompt for keyword in ("rdp", "remote desktop")):
            return "Analyst Verdict: High Risk. The log aligns with the retrieved RDP context."
        return "Analyst Verdict: Low Risk. The retrieved context is not conclusive."


def create_qdrant_client(settings: AppSettings | None = None) -> QdrantClient:
    """Create the local on-disk Qdrant client."""

    settings = settings or load_settings()
    return QdrantClient(path=settings.qdrant_path)


def create_embedder(settings: AppSettings | None = None) -> Callable[[Sequence[str]], Sequence[Sequence[float]]]:
    """Create the Hugging Face embedder or fall back to a deterministic demo embedder."""

    settings = settings or load_settings()
    if settings.hf_token:
        return HuggingFaceEmbedder(api_token=settings.hf_token)
    return build_demo_embedder()


def create_groq_client(settings: AppSettings | None = None) -> Any:
    """Create the Groq client or fall back to a local demo client."""

    settings = settings or load_settings()
    if settings.groq_api_key:
        return GroqChatClient(api_key=settings.groq_api_key)
    return DemoGroqClient()


def build_dashboard_runtime(settings: AppSettings | None = None) -> DashboardRuntime:
    """Select runtime dependencies for live or local demo mode."""

    load_dotenv_if_available()
    settings = settings or load_settings()

    live_mode = bool(settings.hf_token)
    collection_name = DEFAULT_COLLECTION_NAME if live_mode else DEMO_COLLECTION_NAME
    status_message = (
        "Live mode: using Hugging Face embeddings and the configured Groq/Qdrant pipeline."
        if live_mode
        else "Demo mode: HF token not configured, using a local sample collection and deterministic embeddings."
    )

    return DashboardRuntime(
        qdrant_client=create_qdrant_client(settings),
        embedder=create_embedder(settings),
        groq_client=create_groq_client(settings),
        collection_name=collection_name,
        bootstrap_demo=not live_mode,
        status_message=status_message,
    )


def ensure_collection_ready(
    client: Any,
    embedder: Callable[[Sequence[str]], Sequence[Sequence[float]]],
    *,
    collection_name: str,
    bootstrap_demo: bool,
) -> None:
    """Ensure the target collection is ready for analysis."""

    try:
        collection_exists = client.collection_exists(collection_name)
    except Exception as error:
        raise RuntimeError(f"Could not inspect Qdrant collection '{collection_name}': {error}") from error

    if collection_exists and count_points(client, collection_name) > 0:
        return

    if bootstrap_demo:
        logger.info("Bootstrapping demo collection for the dashboard")
        ingest_records(build_demo_cve_records(), client, embedder, collection_name=collection_name)
        return

    raise RuntimeError(
        f"Qdrant collection '{collection_name}' is empty or missing. Run the ingestion workflow before using live mode."
    )


def submit_log_for_analysis(
    log_text: str,
    *,
    qdrant_client: Any | None = None,
    embedder: Callable[[Sequence[str]], Sequence[Sequence[float]]] | None = None,
    groq_client: Any | None = None,
    collection_name: str = DEFAULT_COLLECTION_NAME,
    bootstrap_demo: bool = False,
) -> UIAnalysisResult:
    """Run the backend analysis flow and capture clean UI-friendly errors."""

    load_dotenv_if_available()
    cleaned_text = log_text.strip()
    if not cleaned_text:
        return UIAnalysisResult(raw_text=cleaned_text, report=None, error_message="Paste a log or upload a file before submitting.")

    qdrant_client = qdrant_client or create_qdrant_client()
    embedder = embedder or create_embedder()
    groq_client = groq_client or create_groq_client()

    try:
        ensure_collection_ready(
            qdrant_client,
            embedder,
            collection_name=collection_name,
            bootstrap_demo=bootstrap_demo,
        )
        report = analyze_log(
            cleaned_text,
            qdrant_client,
            embedder,
            groq_client=groq_client,
            collection_name=collection_name,
        )
        return UIAnalysisResult(raw_text=cleaned_text, report=report)
    except Exception as error:  # pragma: no cover - exercised through UI tests
        logger.exception("Dashboard analysis failed")
        return UIAnalysisResult(raw_text=cleaned_text, report=None, error_message=f"Analysis failed: {error}")


def build_display_sections(result: UIAnalysisResult) -> dict[str, object]:
    """Return text blocks that the dashboard renders."""

    if result.error_message:
        return {
            "headline": "Analysis could not be completed.",
            "message": result.error_message,
            "evidence_lines": [],
            "parsed_lines": [],
            "verdict": None,
        }

    if result.report is None:
        return {
            "headline": "No report available.",
            "message": "Submit a log to generate an analyst verdict.",
            "evidence_lines": [],
            "parsed_lines": [],
            "verdict": None,
        }

    report = result.report
    evidence_lines = [
        f"{cve.cve_id} | CVSS {cve.cvss_score:.1f} | similarity {cve.score:.3f} | {cve.description}"
        for cve in report.retrieved_cves
    ]
    if not evidence_lines:
        evidence_lines = ["No known vulnerability matched the submitted log."]

    parsed_lines = [
        f"Timestamp: {report.parsed_log.timestamp or 'unknown'}",
        f"Service: {report.parsed_log.service or 'unknown'}",
        f"IP Address: {report.parsed_log.ip_address or 'unknown'}",
        f"Message: {report.parsed_log.message}",
    ]

    return {
        "headline": "Analyst verdict ready.",
        "message": "Retrieved context is shown below.",
        "evidence_lines": evidence_lines,
        "parsed_lines": parsed_lines,
        "verdict": report.verdict,
    }


@contextmanager
def analysis_status(st_module: Any) -> Iterator[None]:
    """Show a Streamlit spinner when the API is available."""

    spinner = getattr(st_module, "spinner", None)
    if callable(spinner):
        with spinner(ANALYSIS_STATUS_MESSAGE):
            yield
        return

    yield


def render_dashboard(st_module: Any | None = None) -> None:
    """Render the Streamlit dashboard."""

    st_module = st_module or st
    if st_module is None:
        raise RuntimeError("streamlit is required to render the dashboard")

    runtime = build_dashboard_runtime()
    st_module.set_page_config(page_title="Semantic SOC Analyst", page_icon="🛡️", layout="wide")
    st_module.title("Semantic SOC Analyst")
    st_module.caption("Paste a log or upload a file, then review the grounded verdict.")
    st_module.info(runtime.status_message)

    pasted_log = st_module.text_area(
        "Security log",
        height=180,
        placeholder="May 12 10:11:12 host sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2",
    )
    uploaded_file = st_module.file_uploader("Optional log file", type=["txt", "log"])

    if st_module.button("Run analysis", type="primary"):
        raw_log = resolve_log_input(pasted_log, uploaded_file)
        with analysis_status(st_module):
            result = submit_log_for_analysis(
                raw_log,
                qdrant_client=runtime.qdrant_client,
                embedder=runtime.embedder,
                groq_client=runtime.groq_client,
                collection_name=runtime.collection_name,
                bootstrap_demo=runtime.bootstrap_demo,
            )
        sections = build_display_sections(result)

        if result.error_message:
            st_module.error(sections["message"])
            return

        st_module.success(sections["headline"])
        st_module.write(sections["message"])
        st_module.subheader("Parsed Log")
        st_module.write("\n".join(sections["parsed_lines"]))
        st_module.subheader("Retrieved Context")
        st_module.write("\n".join(sections["evidence_lines"]))
        st_module.subheader("Analyst Verdict")
        st_module.write(sections["verdict"])


def main() -> None:
    """Entry point for `streamlit run src/app.py`."""

    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
    render_dashboard()


if __name__ == "__main__":
    main()
