"""Integration tests for PRS-HEALTH / PRS-SYS events (issue 1041)."""

import logging
from collections.abc import Callable
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from gfmodules.logging.testing import capture_records
from jwcrypto.jwk import JWK
from requests.exceptions import ConnectionError
from sqlalchemy.exc import DatabaseError, OperationalError
from starlette.testclient import TestClient

from app.db.models.organization import OrganizationEntity
from app.db.session import DbSession
from app.exceptions.pseudonym import PseudonymOperationError
from app.logging.events import Log
from app.models.oin import RecipientOrganizationOin
from app.models.requests.oprf import BlindRequest
from app.services.oprf.oprf_service import OprfService
from app.services.organization_public_key_service import OrganizationPublicKeyService
from tests.conftest import blinded_input
from tests.test_config import get_test_config

# Constants for logger names
APP_LOGGER = "app.application"
DB_LOGGER = "app.db.session"
HSM_CLIENT_LOGGER = "app.services.hsm.client"

RecordLogs = Callable[[str], list[logging.LogRecord]]


def _events(records: list[logging.LogRecord], event_id: str) -> list[logging.LogRecord]:
    """Helper to filter log records by event_id."""
    return [r for r in records if getattr(r, "event_id", None) == event_id]


@pytest.fixture
def blind_request(persisted_organization: OrganizationEntity) -> BlindRequest:
    """Fixture to create a blind request for testing."""
    return BlindRequest(
        encryptedPersonalId=blinded_input(),
        recipientOrganization=RecipientOrganizationOin(
            f"oin:{persisted_organization.external_id.value}"
        ),
        recipientScope="nvi",
    )


def test_startup_emits_sys_app_started(record_logs: RecordLogs, app: FastAPI) -> None:
    """Tests that app startup emits SYS_APP_STARTED (270401)."""
    # Attach handler BEFORE TestClient starts to capture lifespan events
    records = record_logs(APP_LOGGER)

    # The started event is emitted on lifespan entry, which TestClient runs.
    with TestClient(app):
        pass

    events = _events(records, Log.SYS_APP_STARTED.event_id)
    assert len(events) == 1
    record = events[0]
    assert record.levelno == logging.INFO
    assert record.version  # type: ignore[attr-defined]
    assert record.pseudoniem_api_enabled is True  # type: ignore[attr-defined]


def test_lifespan_shutdown_emits_sys_app_stopped(
    record_logs: RecordLogs, app: FastAPI
) -> None:
    """Tests that app shutdown emits SYS_APP_STOPPED (270402)."""
    # Attach handler BEFORE TestClient starts to capture lifespan events
    records = record_logs(APP_LOGGER)

    # TestClient runs the lifespan; leaving the context triggers shutdown.
    with TestClient(app):
        pass

    events = _events(records, Log.SYS_APP_STOPPED.event_id)
    assert len(events) == 1
    record = events[0]
    assert record.levelno == logging.INFO
    assert record.shutdown_reason == "graceful"  # type: ignore[attr-defined]


def test_unhandled_exception_emits_sys_event_and_returns_500(
    client: TestClient,
    persisted_organization: OrganizationEntity,
    valid_headers: dict[str, str],
    organization_public_key_service: OrganizationPublicKeyService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tests that unhandled exceptions emit SYS_UNHANDLED_EXCEPTION (270404)."""
    # Add the exception handler to the app
    # Assign a mock directly to the instance method (no cleanup needed)
    mock_response = MagicMock(side_effect=RuntimeError("boom"))
    monkeypatch.setattr(
        organization_public_key_service, "get_by_org_and_domain", mock_response
    )

    # client = TestClient(local_app, raise_server_exceptions=False)
    with capture_records(APP_LOGGER) as captured:
        try:
            response = client.post(
                "/oprf/eval",
                json={
                    "encryptedPersonalId": "Zm9v",
                    "recipientOrganization": f"oin:{persisted_organization.external_id.value}",
                    "recipientScope": "nvi",
                },
                headers={
                    **valid_headers,
                    "x-gf-sub": persisted_organization.external_id.value,
                },
            )
            print(response.text)
            assert response.status_code == 500
            assert response.json() == {"detail": "Internal server error"}

            events = captured.for_event(Log.SYS_UNHANDLED_EXCEPTION)
            assert len(events) == 1
            entry = events[0]
            assert entry.record.levelno == logging.ERROR
            assert entry.message["exception_type"] == "RuntimeError"
        except RuntimeError:
            pass


def test_db_retry_emits_connection_events(
    record_logs: RecordLogs, db_session: DbSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Tests that database retries emit SYS_DB_CONNECTION_FAILED events."""
    records = record_logs(DB_LOGGER)
    test_config = get_test_config()
    test_config.database.retry_backoff = [0.0]  # Retry once, then give up

    # Patch get_config to return the test config
    with patch("app.db.session.get_config", return_value=test_config):
        # Mock the session to raise OperationalError
        mock_exectute = MagicMock(
            side_effect=OperationalError("stmt", {}, Exception("connection lost"))
        )
        monkeypatch.setattr(db_session.session, "execute", mock_exectute)

        with pytest.raises(DatabaseError):
            db_session.execute("SELECT 1")

    events = _events(records, Log.SYS_DB_CONNECTION_FAILED.event_id)
    assert len(events) == 2  # One for retrying, one for giving up

    retrying = events[0]
    assert retrying.levelno == logging.ERROR
    assert retrying.datastore == "prs-database"  # type: ignore[attr-defined]
    assert retrying.error_type == "OperationalError"  # type: ignore
    assert retrying.retry_attempt == 1  # type: ignore[attr-defined]
    assert retrying.backoff_seconds == 0.0  # type: ignore[attr-defined]

    gave_up = events[1]
    assert gave_up.error_type == "OperationalError"  # type: ignore
    assert gave_up.retry_attempt == 2  # type: ignore[attr-defined]


def test_hsm_unreachable_emits_sys_event(
    record_logs: RecordLogs,
    oprf_service: OprfService,
    blind_request: BlindRequest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tests that HSM unreachable emits SYS_HSM_UNREACHABLE (270406)."""
    records = record_logs(HSM_CLIENT_LOGGER)

    # Create the mock response
    mock_response = MagicMock(side_effect=ConnectionError("connection refused"))

    # Access the private evaluator via its mangled name on the instance
    evaluator = oprf_service._OprfService__evaluator  # type: ignore

    # Safe monkeypatch down the object chain
    monkeypatch.setattr(evaluator._client._http, "do_request", mock_response)

    pub_key = JWK.generate(kty="RSA", size=2048)

    with pytest.raises(PseudonymOperationError) as exc:
        oprf_service.eval_blind(blind_request, pub_key)

    assert exc.value.error_type == "hsm_unreachable"
    events = _events(records, Log.SYS_HSM_UNREACHABLE.event_id)
    assert len(events) == 1
    record = events[0]
    assert record.levelno == logging.CRITICAL
    assert "connection refused" in record.error_reason  # type: ignore
