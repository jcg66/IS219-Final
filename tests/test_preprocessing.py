"""Tests for Sprint 06 external log preprocessing helpers."""

from __future__ import annotations

from src.preprocessing import load_sample_logs, normalize_log_text, prepare_sample_logs


def test_normalize_log_text_collapses_whitespace_and_control_chars() -> None:
    cleaned = normalize_log_text(" May 12 10:11:12\thost sshd[1]: Failed password \nfor root \x00 ")

    assert cleaned == "May 12 10:11:12 host sshd[1]: Failed password for root"


def test_prepare_sample_logs_skips_comments_and_duplicates() -> None:
    prepared = prepare_sample_logs(
        [
            "# comment",
            "May 12 10:11:12 host sshd[1]: Failed password",
            "  May 12 10:11:12 host sshd[1]: Failed password  ",
            "",
            "May 12 12:00:00 host cron[1000]: session opened for user backup",
        ]
    )

    assert prepared == [
        "May 12 10:11:12 host sshd[1]: Failed password",
        "May 12 12:00:00 host cron[1000]: session opened for user backup",
    ]


def test_load_sample_logs_reads_curated_external_logs() -> None:
    logs = load_sample_logs()

    assert len(logs) == 4
    assert any("sshd" in log for log in logs)
    assert any("cron" in log for log in logs)
