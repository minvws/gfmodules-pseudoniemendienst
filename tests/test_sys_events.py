"""Asserts the PRS-HEALTH / PRS-SYS events (issue 1041) are emitted correctly."""

import logging
from typing import Callable, List
from unittest.mock import MagicMock, patch

import pytest
import requests
from fastapi import FastAPI
from fastapi.testclient import TestClient
from jwcrypto import jwk
from sqlalchemy.exc import DatabaseError, OperationalError

from app import container
from app.config import ConfigOprf, get_config
from app.db.db import Database
from app.models.oin import RecipientOrganizationOin
from app.models.requests import BlindRequest
from app.services.oprf.oprf_service import OprfEvaluationError, OprfService

RecordLogs = Callable[[str], List[logging.LogRecord]]


def _blind_request() -> BlindRequest:
    return BlindRequest(
        encryptedPersonalId="Zm9vYmFy",
        recipientOrganization=RecipientOrganizationOin("oin:00000099000000001000"),
        recipientScope="nvi",
    )


def _events(records: List[logging.LogRecord], event_id: str) -> List[logging.LogRecord]:
    return [r for r in records if getattr(r, "event_id", None) == event_id]


def test_startup_emits_sys_app_started(
    capsys: pytest.CaptureFixture[str], app: FastAPI
) -> None:
    # dictConfig (run inside create_fastapi_app) clears handlers on all app.*
    # loggers, so a recording handler cannot observe the startup event. Instead,
    # read it from the JSON console handler output — end-to-end through the
    # actual logging config.
    import json

    out = capsys.readouterr().out
    events = [json.loads(line) for line in out.splitlines() if '"270401"' in line]
    assert len(events) == 1
    event = events[0]
    assert event["level"] == "INFO"
    message = event["message"]
    assert message["component"] == "pseudoniemendienst"
    assert message["version"]
    assert message["environment"]
    assert message["pseudoniem_api_enabled"] is True


def test_lifespan_shutdown_emits_sys_app_stopped(
    record_logs: RecordLogs, app: FastAPI
) -> None:
    records = record_logs("app.application")

    # TestClient runs the lifespan; leaving the context triggers shutdown.
    with TestClient(app):
        pass

    events = _events(records, "270402")
    assert len(events) == 1
    record = events[0]
    assert record.levelno == logging.INFO
    assert record.component == "pseudoniemendienst"  # type: ignore[attr-defined]
    assert record.shutdown_reason == "graceful"  # type: ignore[attr-defined]


def test_unhandled_exception_emits_sys_event_and_returns_500(
    record_logs: RecordLogs, app: FastAPI
) -> None:
    records = record_logs("app.application")

    class ExplodingOrgService:
        def get_by_oin(self, oin: object) -> None:
            raise RuntimeError("boom")

    app.dependency_overrides[container.get_org_service] = lambda: ExplodingOrgService()
    client = TestClient(app, raise_server_exceptions=False)
    try:
        response = client.post(
            "/oprf/eval",
            json={
                "encryptedPersonalId": "Zm9v",
                "recipientOrganization": "oin:00000099000000001000",
                "recipientScope": "nvi",
            },
            headers={
                "x-gf-oin": "00000099000000001000",
                "x-gf-audience": "prs.service",
            },
        )
    finally:
        app.dependency_overrides.pop(container.get_org_service, None)

    assert response.status_code == 500
    assert response.json() == {"error": "Internal server error"}
    events = _events(records, "270404")
    assert len(events) == 1
    record = events[0]
    assert record.levelno == logging.ERROR
    assert record.exception_type == "RuntimeError"  # type: ignore[attr-defined]
    assert record.endpoint == "/oprf/eval"  # type: ignore[attr-defined]
    assert record.method == "POST"  # type: ignore[attr-defined]


def test_db_retry_emits_connection_events(
    record_logs: RecordLogs, database: Database
) -> None:
    records = record_logs("app.db.session")
    config = get_config()
    original_backoff = config.database.retry_backoff
    config.database.retry_backoff = [0.0]

    def failing_operation() -> None:
        raise OperationalError("stmt", {}, Exception("connection lost"))

    try:
        with database.get_db_session() as session:
            with pytest.raises(DatabaseError):
                session._retry(failing_operation)
    finally:
        config.database.retry_backoff = original_backoff

    events = _events(records, "270403")
    assert len(events) == 2

    retrying = events[0]
    assert retrying.levelno == logging.ERROR
    assert retrying.datastore == "prs-database"  # type: ignore[attr-defined]
    assert retrying.error_type == "OperationalError"  # type: ignore[attr-defined]
    assert retrying.retry_attempt == 1  # type: ignore[attr-defined]
    assert retrying.backoff_seconds == 0.0  # type: ignore[attr-defined]

    gave_up = events[1]
    assert gave_up.error_type == "OperationalError"  # type: ignore[attr-defined]
    assert gave_up.retry_attempt == 2  # type: ignore[attr-defined]


def test_hsm_unreachable_emits_sys_event(record_logs: RecordLogs) -> None:
    records = record_logs("app.services.oprf.oprf_service")
    hsm_key_version_service = MagicMock()
    hsm_key_version_service.get_active_versions.return_value = [MagicMock(version=1)]
    service = OprfService(
        server_key=None,
        hsm_config=ConfigOprf(hsm_url="https://hsm.local"),
        hsm_key_version_service=hsm_key_version_service,
    )
    key = jwk.JWK.generate(kty="RSA", size=2048)
    pub = jwk.JWK.from_json(key.export_public())

    with (
        patch(
            "app.services.oprf.oprf_service.requests.post",
            side_effect=requests.exceptions.ConnectionError("connection refused"),
        ),
        pytest.raises(OprfEvaluationError) as exc,
    ):
        service.eval_blind(_blind_request(), pub, None)

    assert exc.value.error_type == "crypto_evaluation_failure"
    events = _events(records, "270406")
    assert len(events) == 1
    record = events[0]
    assert record.levelno == logging.CRITICAL
    assert "connection refused" in record.error_reason  # type: ignore[attr-defined]
