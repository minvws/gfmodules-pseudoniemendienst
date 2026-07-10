"""Verifies per-field stream routing (APP == stroom 2, SIEM == stroom 3) for the PRS events."""

import io
import json
import logging
from typing import Any, Iterator

import pytest

from app.logging.events import (
    HEALTH_UNHEALTHY,
    OPRF_EVAL_OK,
    SYS_APP_STARTED,
    log_event,
)
from app.logging.filters import AppFilter, LoggingStreams, SiemFilter
from app.logging.formatter import JsonFormatter


@pytest.fixture
def streams() -> Iterator[tuple[logging.Logger, io.StringIO, io.StringIO]]:
    app_buf, siem_buf = io.StringIO(), io.StringIO()

    app_handler = logging.StreamHandler(app_buf)
    app_handler.addFilter(AppFilter())
    app_handler.setFormatter(
        JsonFormatter(include_traces=False, stream=LoggingStreams.APP)
    )

    siem_handler = logging.StreamHandler(siem_buf)
    siem_handler.addFilter(SiemFilter())
    siem_handler.setFormatter(
        JsonFormatter(include_traces=False, stream=LoggingStreams.SIEM)
    )

    logger = logging.getLogger("app.test_stream_routing")
    logger.setLevel(logging.DEBUG)
    logger.handlers = [app_handler, siem_handler]
    logger.propagate = False

    try:
        yield logger, app_buf, siem_buf
    finally:
        logger.handlers = []


def _messages(buf: io.StringIO) -> list[dict[str, Any]]:
    return [json.loads(line)["message"] for line in buf.getvalue().splitlines()]


def test_health_unhealthy_withholds_error_detail_from_siem(
    streams: tuple[logging.Logger, io.StringIO, io.StringIO],
) -> None:
    logger, app_buf, siem_buf = streams
    log_event(
        logger,
        HEALTH_UNHEALTHY,
        "unhealthy",
        component="database",
        status="error",
        error_detail="connection refused on 10.0.0.1:5432",
    )

    app_msg = _messages(app_buf)[0]
    siem_msg = _messages(siem_buf)[0]

    assert app_msg["error_detail"] == "connection refused on 10.0.0.1:5432"
    assert "error_detail" not in siem_msg  # not in SIEM allow-list for PRS-HEALTH-001
    for msg in (app_msg, siem_msg):
        assert msg["component"] == "database"
        assert msg["status"] == "error"


def test_app_started_goes_to_app_stream_only(
    streams: tuple[logging.Logger, io.StringIO, io.StringIO],
) -> None:
    logger, app_buf, siem_buf = streams
    log_event(
        logger,
        SYS_APP_STARTED,
        "started",
        component="pseudoniemendienst",
        version="v1.2.3",
    )

    assert _messages(app_buf)[0]["component"] == "pseudoniemendienst"
    assert _messages(siem_buf) == []  # PRS-SYS-001 has no SIEM stream per spec


def test_oprf_eval_ok_withholds_key_versions_from_siem(
    streams: tuple[logging.Logger, io.StringIO, io.StringIO],
) -> None:
    logger, app_buf, siem_buf = streams
    log_event(
        logger,
        OPRF_EVAL_OK,
        "evaluated",
        handelende_oin="00000099000000001000",
        doel_oin="oin:00000099000000002000",
        oprf_secret_versie=3,
        ontvanger_pubkey_id="key-1",
    )

    app_msg = _messages(app_buf)[0]
    siem_msg = _messages(siem_buf)[0]

    assert app_msg["oprf_secret_versie"] == 3
    assert app_msg["ontvanger_pubkey_id"] == "key-1"
    assert (
        "oprf_secret_versie" not in siem_msg
    )  # not in SIEM allow-list for PRS-OPRF-001
    assert "ontvanger_pubkey_id" not in siem_msg
    for msg in (app_msg, siem_msg):
        assert msg["handelende_oin"] == "00000099000000001000"
        assert msg["doel_oin"] == "oin:00000099000000002000"
