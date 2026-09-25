"""Asserts the PRS-HEALTH / PRS-SYS events (issue 1041) are emitted correctly."""

import logging
from collections.abc import Callable
from unittest.mock import MagicMock, patch

import pytest
import requests
from fastapi import FastAPI
from fastapi.testclient import TestClient
from gfmodules.logging.testing import capture_records
from jwcrypto import jwk
from sqlalchemy.exc import DatabaseError, OperationalError

from app import container
from app.config import ConfigOprf, get_config
from app.db.db import Database
from app.db.models import OrganizationEntity
from app.logging.events import Log
from app.models.auth.data import AuthorizationScope
from app.models.oin import RecipientOrganizationOin
from app.models.requests import BlindRequest
from app.services.oprf.evaluators import HsmOprfEvaluator
from app.services.oprf.oprf_service import OprfEvaluationError, OprfService

RecordLogs = Callable[[str], list[logging.LogRecord]]


def _blind_request() -> BlindRequest:
    return BlindRequest(
        encryptedPersonalId="Zm9vYmFy",
        recipientOrganization=RecipientOrganizationOin("oin:00000099000000001000"),
        recipientScope="nvi",
    )


def _events(records: list[logging.LogRecord], event_id: str) -> list[logging.LogRecord]:
    return [r for r in records if getattr(r, "event_id", None) == event_id]


def test_startup_emits_sys_app_started(record_logs: RecordLogs, app: FastAPI) -> None:
    records = record_logs("app.application")

    # The started event is emitted on lifespan entry, which TestClient runs.
    with TestClient(app):
        pass

    events = _events(records, "270401")
    assert len(events) == 1
    record = events[0]
    assert record.levelno == logging.INFO
    assert record.version  # type: ignore[attr-defined]
    assert record.pseudoniem_api_enabled is True  # type: ignore[attr-defined]


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
    assert record.shutdown_reason == "graceful"  # type: ignore[attr-defined]


def test_unhandled_exception_emits_sys_event_and_returns_500(
    app: FastAPI,
    persisted_organization: OrganizationEntity,
) -> None:
    class ExplodingOrgService:
        def get_by_org_and_domain(self, oin: object, domain: object) -> None:
            raise RuntimeError("boom")

    app.dependency_overrides[container.get_organization_public_key_service] = lambda: (
        ExplodingOrgService()
    )
    client = TestClient(app, raise_server_exceptions=False)
    try:
        with capture_records("app.application") as captured:
            response = client.post(
                "/oprf/eval",
                json={
                    "encryptedPersonalId": "Zm9v",
                    "recipientOrganization": "oin:"
                    + persisted_organization.external_id.value,
                    "recipientScope": "nvi",
                },
                headers={
                    "x-gf-sub": persisted_organization.external_id.value,
                    "x-gf-act-sub": persisted_organization.external_id.value,
                    "x-gf-act-cn": persisted_organization.external_id.value,
                    "x-gf-audience": "prs.service",
                    "x-gf-scope": AuthorizationScope.OPRF_PSEUDONYM.value,
                },
            )
    finally:
        app.dependency_overrides.pop(
            container.get_organization_public_key_service, None
        )

    assert response.status_code == 500
    assert response.json() == {"detail": "Internal server error"}
    events = captured.for_event(Log.SYS_UNHANDLED_EXCEPTION)
    assert len(events) == 1
    entry = events[0]
    assert entry.record.levelno == logging.ERROR
    assert entry.message["exception_type"] == "RuntimeError"
    assert entry.message["endpoint"] == "/oprf/eval"
    assert entry.message["method"] == "POST"


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
        with database.get_db_session() as session, pytest.raises(DatabaseError):
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


def test_hsm_unreachable_emits_sys_event(
    record_logs: RecordLogs,
) -> None:
    records = record_logs("app.services.hsm.client")
    hsm_key_version_service = MagicMock()
    hsm_key_version_service.get_active_version_numbers_by_organization_oin.return_value = [
        1
    ]

    service = OprfService(
        evaluator=HsmOprfEvaluator(
            hsm_config=ConfigOprf(hsm_url="https://hsm.local"),
            hsm_key_version_service=hsm_key_version_service,
        )
    )
    key = jwk.JWK.generate(kty="RSA", size=2048)
    pub = jwk.JWK.from_json(key.export_public())

    with (
        patch(
            "app.services.hsm.client.requests.post",
            side_effect=requests.exceptions.ConnectionError("connection refused"),
        ),
        pytest.raises(OprfEvaluationError) as exc,
    ):
        service.eval_blind(_blind_request(), pub)

    assert exc.value.error_type == "hsm_unreachable"
    events = _events(records, "270406")
    assert len(events) == 1
    record = events[0]
    assert record.levelno == logging.CRITICAL
    assert "connection refused" in record.error_reason  # type: ignore[attr-defined]
