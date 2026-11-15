"""Integration tests for OPRF operations that require real cryptographic operations or audit logging."""

import base64
import json
import logging
from dataclasses import dataclass
from unittest.mock import MagicMock

import pyoprf
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import FastAPI
from gfmodules.logging import LoggingStreams
from gfmodules.logging.testing import capture_records
from jwcrypto import jwe, jwk
from starlette.testclient import TestClient

from app import container
from app.db.models import OrganizationEntity
from app.enums.personal_id_type import PersonalIdType
from app.exceptions.access import NotAllowedToRequestError, RecipientNotFoundError
from app.exceptions.pseudonym import (
    HsmUnreachableError,
    InvalidBlindedInputError,
)
from app.exceptions.registration import DomainNotRegisteredError
from app.logging.events import Log
from app.models.oin import Oin
from app.services.authorization_service import AuthorizationService
from app.services.oprf.evaluators import LocalOprfEvaluator
from app.services.oprf.oprf_service import OprfEvalResult, OprfService
from app.services.organization_public_key_service import OrganizationPublicKeyService
from tests.conftest import setup_org_and_key


@dataclass(frozen=True)
class OprfIntegrationContext:
    personal_identifier: dict[str, str]
    recipient_organization: str
    recipient_scope: str
    private_key_pem: str


def run_oprf_eval_and_unblind(
    client: TestClient,
    private_key_pem: str,
    personal_identifier: dict[str, str],
    recipient_organization: str,
    recipient_scope: str,
    headers: dict[str, str],
) -> str:
    blind_factor_raw, blinded_input_raw = derive_blind_factor_and_input(
        personal_identifier=personal_identifier,
        recipient_organization=recipient_organization,
        recipient_scope=recipient_scope,
    )
    blind_factor = base64.urlsafe_b64encode(blind_factor_raw).decode("ascii")
    blinded_input = base64.urlsafe_b64encode(blinded_input_raw).decode("ascii")

    eval_response = client.post(
        "/oprf/eval",
        json={
            "encryptedPersonalId": blinded_input,
            "recipientOrganization": recipient_organization,
            "recipientScope": recipient_scope,
        },
        headers=headers,
    )
    assert eval_response.status_code == 200
    token = jwe.JWE()
    token.deserialize(eval_response.json()["jwe"])
    token.decrypt(jwk.JWK.from_pem(private_key_pem.encode("ascii")))

    body = json.loads(token.payload.decode("utf-8"))
    assert body["aud"] == recipient_organization
    assert body["scope"] == recipient_scope
    assert body["subject"].startswith("pseudonym:eval:")

    eval_subject = body["subject"].split(":")[-1]
    final = pyoprf.unblind(
        base64.urlsafe_b64decode(blind_factor),
        base64.urlsafe_b64decode(eval_subject),
    )
    final_pseudonym = base64.urlsafe_b64encode(final).decode("ascii")
    assert final_pseudonym

    return final_pseudonym


def derive_blind_factor_and_input(
    personal_identifier: dict[str, str],
    recipient_organization: str,
    recipient_scope: str,
) -> tuple[bytes, bytes]:
    info = f"{recipient_organization}|{recipient_scope}|v1".encode()
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info)
    personal_id = json.dumps(personal_identifier, separators=(",", ":"))
    derived_personal_id = hkdf.derive(personal_id.encode("utf-8"))
    blind_factor_raw, blinded_input_raw = pyoprf.blind(derived_personal_id)
    return bytes(blind_factor_raw), bytes(blinded_input_raw)


@pytest.fixture
def oprf_context(
    persisted_organization: OrganizationEntity,
    organization_public_key_service: OrganizationPublicKeyService,
) -> OprfIntegrationContext:
    recipient_organization = f"oin:{persisted_organization.external_id.value}"
    recipient_scope = "nvi"
    personal_identifier = {
        "landCode": "NL",
        "type": "bsn",
        "value": "950000012",
    }
    private_key_pem = setup_org_and_key(
        organization_public_key_service,
        persisted_organization,
        domains=[recipient_scope],
    )
    return OprfIntegrationContext(
        personal_identifier=personal_identifier,
        recipient_organization=recipient_organization,
        recipient_scope=recipient_scope,
        private_key_pem=private_key_pem,
    )


def test_oprf_integration_roundtrip_is_stable_for_same_input(
    client: TestClient,
    oprf_context: OprfIntegrationContext,
    valid_headers: dict[str, str],
    app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tests that the OPRF roundtrip returns a stable pseudonym for the same input.
    Uses LocalOprfEvaluator to avoid requiring a real HSM service.
    """
    # Generate a local OPRF server key
    server_key = pyoprf.keygen()

    # Create a LocalOprfEvaluator with the server key
    local_evaluator = LocalOprfEvaluator(server_key)

    # Create an OPRF service with the local evaluator
    oprf_service = OprfService(local_evaluator)

    #  SAFE OVERRIDE: Use monkeypatch.setitem
    # This automatically tracks the dictionary mutation and clears it on teardown.
    monkeypatch.setitem(
        app.dependency_overrides, container.get_oprf_service, lambda: oprf_service
    )

    # Run the integration test logic (No try/finally boilerplate required!)
    pseudonym_1 = run_oprf_eval_and_unblind(
        client=client,
        private_key_pem=oprf_context.private_key_pem,
        personal_identifier=oprf_context.personal_identifier,
        recipient_organization=oprf_context.recipient_organization,
        recipient_scope=oprf_context.recipient_scope,
        headers=valid_headers,
    )
    pseudonym_2 = run_oprf_eval_and_unblind(
        client=client,
        private_key_pem=oprf_context.private_key_pem,
        personal_identifier=oprf_context.personal_identifier,
        recipient_organization=oprf_context.recipient_organization,
        recipient_scope=oprf_context.recipient_scope,
        headers=valid_headers,
    )

    assert pseudonym_1 == pseudonym_2


def test_oprf_eval_success_emits_audit_event(
    client: TestClient,
    oprf_context: OprfIntegrationContext,
    valid_headers: dict[str, str],
    valid_organization_id: Oin,
    valid_client_organization_id: Oin,
    app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tests that a successful OPRF evaluation emits the correct audit event."""

    server_key = pyoprf.keygen()

    local_evaluator = LocalOprfEvaluator(server_key)

    oprf_service = OprfService(local_evaluator)

    monkeypatch.setitem(
        app.dependency_overrides,
        container.get_oprf_service,
        lambda: oprf_service,
    )

    class RecordingHandler(logging.Handler):
        def __init__(self) -> None:
            super().__init__()
            self.records: list[logging.LogRecord] = []

        def emit(self, record: logging.LogRecord) -> None:
            self.records.append(record)

    handler = RecordingHandler()
    target_logger = logging.getLogger("app.routers.oprf")

    new_handlers = target_logger.handlers + [handler]
    monkeypatch.setattr(target_logger, "handlers", new_handlers)

    pseudonym = run_oprf_eval_and_unblind(
        client=client,
        private_key_pem=oprf_context.private_key_pem,
        personal_identifier=oprf_context.personal_identifier,
        recipient_organization=oprf_context.recipient_organization,
        recipient_scope=oprf_context.recipient_scope,
        headers=valid_headers,
    )
    assert pseudonym  # Ensure we got a result

    # Check audit events
    events = [r for r in handler.records if getattr(r, "event_id", None) == "210400"]
    assert len(events) == 1
    record = events[0]
    assert record.levelno == logging.INFO
    assert (
        record.acting_organization_identifier == valid_client_organization_id.value  # type: ignore
    )
    assert (
        record.represented_organization_identifier  # type: ignore
        == valid_organization_id.value
    )
    assert (
        record.recipient_organization_identifier  # type: ignore
        == oprf_context.recipient_organization
    )
    assert record.oprf_secret_version == 1  # type: ignore[attr-defined]
    assert not hasattr(record, "previous_oprf_secret_version")
    assert record.recipient_pubkey_id  # type: ignore[attr-defined]
    assert LoggingStreams.SIEM in record.stream  # type: ignore

    # Ensure no failure events were emitted
    failure_events = [
        r for r in handler.records if getattr(r, "event_id", None) == "210402"
    ]
    assert len(failure_events) == 0
    no_active_key_events = [
        r for r in handler.records if getattr(r, "event_id", None) == "210403"
    ]
    assert len(no_active_key_events) == 0


def test_oprf_eval_during_grace_logs_the_previous_secret_version(
    app: FastAPI,
    client: TestClient,
    oprf_context: OprfIntegrationContext,
    valid_headers: dict[str, str],
    valid_client_organization_id: Oin,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class GraceOprfService:
        def eval_blind(self, req: object, pub_key_jwk: object) -> OprfEvalResult:
            return OprfEvalResult(jwe="jwe", key_versions=(1, 2))

    monkeypatch.setitem(
        app.dependency_overrides,
        container.get_oprf_service,
        lambda: GraceOprfService(),
    )

    with capture_records("app.routers.oprf") as captured:
        response = client.post(
            "/oprf/eval",
            json={
                "encryptedPersonalId": "Zm9v",
                "recipientOrganization": oprf_context.recipient_organization,
                "recipientScope": oprf_context.recipient_scope,
            },
            headers=valid_headers,
        )

    assert response.status_code == 200
    events = captured.for_event(Log.OPRF_EVAL_OK)
    assert len(events) == 1
    entry = events[0]
    assert entry.record.levelno == logging.INFO
    assert entry.message["previous_oprf_secret_version"] == 1
    assert entry.message["oprf_secret_version"] == 2
    assert entry.message["recipient_pubkey_id"]
    assert (
        entry.message["acting_organization_identifier"]
        == valid_client_organization_id.value
    )
    assert (
        entry.message["recipient_organization_identifier"]
        == oprf_context.recipient_organization
    )


def test_oprf_eval_unknown_scope_emits_refused_event(
    client: TestClient,
    oprf_context: OprfIntegrationContext,
    valid_headers: dict[str, str],
    valid_client_organization_id: Oin,
    app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tests that an unknown scope emits the correct refused audit event."""
    mock_pubkey_service = MagicMock(spec=OrganizationPublicKeyService)
    mock_pubkey_service.get_by_org_and_domain.side_effect = DomainNotRegisteredError()

    monkeypatch.setitem(
        app.dependency_overrides,
        container.get_organization_public_key_service,
        lambda: mock_pubkey_service,
    )

    with capture_records("app.routers.oprf") as captured:
        response = client.post(
            "/oprf/eval",
            json={
                "encryptedPersonalId": "Zm9v",  # Fake blinded input
                "recipientOrganization": oprf_context.recipient_organization,
                "recipientScope": "invalid-scope",  # Unknown scope
            },
            headers=valid_headers,
        )

    assert response.status_code == 404
    events = captured.for_event(Log.OPRF_REFUSED_NO_ACTIVE_PUBKEY)
    assert len(events) == 1
    entry = events[0]
    assert entry.record.levelno == logging.WARNING
    assert (
        entry.message["acting_organization_identifier"]
        == valid_client_organization_id.value
    )
    assert (
        entry.message["recipient_organization_identifier"]
        == oprf_context.recipient_organization
    )
    assert not captured.for_event(Log.OPRF_EVAL_OK)


def test_oprf_eval_unknown_recipient_emits_refused_event(
    client: TestClient,
    valid_headers: dict[str, str],
    persisted_organization: OrganizationEntity,
    app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tests that an unknown recipient emits the correct refused audit event."""
    # Mock the organization public key service to raise RecipientNotFoundError
    mock_pubkey_service = MagicMock(spec=OrganizationPublicKeyService)
    mock_pubkey_service.get_by_org_and_domain.side_effect = RecipientNotFoundError()

    monkeypatch.setitem(
        app.dependency_overrides,
        container.get_organization_public_key_service,
        lambda: mock_pubkey_service,
    )

    class RecordingHandler(logging.Handler):
        def __init__(self) -> None:
            super().__init__()
            self.records: list[logging.LogRecord] = []

        def emit(self, record: logging.LogRecord) -> None:
            self.records.append(record)

    handler = RecordingHandler()
    target_logger = logging.getLogger("app.routers.oprf")

    new_handlers = target_logger.handlers + [handler]
    monkeypatch.setattr(target_logger, "handlers", new_handlers)

    response = client.post(
        "/oprf/eval",
        json={
            "encryptedPersonalId": "Zm9v",  # Fake blinded input
            "recipientOrganization": f"oin:{persisted_organization.external_id.value}",
            "recipientScope": "nvi",
        },
        headers=valid_headers,
    )

    # Assert
    assert response.status_code == 404
    events = [r for r in handler.records if getattr(r, "event_id", None) == "210403"]
    assert len(events) == 1
    assert (
        events[0].recipient_organization_identifier  # type: ignore
        == f"oin:{persisted_organization.external_id.value}"
    )
    assert not [r for r in handler.records if getattr(r, "event_id", None) == "210400"]


def test_oprf_eval_sender_not_allowed_to_request_is_refused_and_audited(
    client: TestClient,
    oprf_context: OprfIntegrationContext,
    valid_headers: dict[str, str],
    app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tests that a sender not allowed to request is refused and audited."""
    mock_auth_service = MagicMock(spec=AuthorizationService)
    mock_auth_service.validate_allowed_to_request.side_effect = (
        NotAllowedToRequestError(PersonalIdType.OPRF)
    )

    monkeypatch.setitem(
        app.dependency_overrides,
        container.get_authorization_service,
        lambda: mock_auth_service,
    )

    with capture_records("app.routers.oprf") as captured:
        response = client.post(
            "/oprf/eval",
            json={
                "encryptedPersonalId": "Zm9v",
                "recipientOrganization": oprf_context.recipient_organization,
                "recipientScope": oprf_context.recipient_scope,
            },
            headers=valid_headers,
        )

    assert response.status_code == 403
    events = captured.for_event(Log.AUTHORIZATION_DENIED)
    assert len(events) == 1
    assert events[0].message["requested_operation"] == "oprf:eval"
    assert (
        events[0].message["recipient_organization_identifier"]
        == oprf_context.recipient_organization
    )
    assert not captured.for_event(Log.OPRF_EVAL_OK)


def test_oprf_eval_failure_emits_failed_event_with_error_type(
    client: TestClient,
    oprf_context: OprfIntegrationContext,
    valid_headers: dict[str, str],
    valid_client_organization_id: Oin,
    app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tests that an OPRF evaluation failure emits the correct failed audit event."""
    mock_oprf_service = MagicMock(spec=OprfService)
    mock_oprf_service.eval_blind.side_effect = InvalidBlindedInputError()

    monkeypatch.setitem(
        app.dependency_overrides,
        container.get_oprf_service,
        lambda: mock_oprf_service,
    )

    class RecordingHandler(logging.Handler):
        def __init__(self) -> None:
            super().__init__()
            self.records: list[logging.LogRecord] = []

        def emit(self, record: logging.LogRecord) -> None:
            self.records.append(record)

    handler = RecordingHandler()
    target_logger = logging.getLogger("app.routers.oprf")

    new_handlers = target_logger.handlers + [handler]
    monkeypatch.setattr(target_logger, "handlers", new_handlers)

    response = client.post(
        "/oprf/eval",
        json={
            "encryptedPersonalId": "Zm9v",
            "recipientOrganization": oprf_context.recipient_organization,
            "recipientScope": oprf_context.recipient_scope,
        },
        headers=valid_headers,
    )

    assert response.status_code == 400
    events = [r for r in handler.records if getattr(r, "event_id", None) == "210402"]
    assert len(events) == 1
    record = events[0]
    assert record.levelno == logging.ERROR
    assert record.error_type == "invalid_blinded_input"  # type: ignore
    assert record.acting_organization_identifier == valid_client_organization_id.value  # type: ignore
    assert (
        record.recipient_organization_identifier  # type: ignore
        == oprf_context.recipient_organization
    )
    assert not [r for r in handler.records if getattr(r, "event_id", None) == "210400"]


def test_app_error_from_evaluation_keeps_its_status_and_is_audited_as_refusal(
    client: TestClient,
    oprf_context: OprfIntegrationContext,
    valid_headers: dict[str, str],
    app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tests that domain errors from evaluation are not wrapped and are audited as refusals."""
    mock_oprf_service = MagicMock(spec=OprfService)
    mock_oprf_service.eval_blind.side_effect = RecipientNotFoundError()

    monkeypatch.setitem(
        app.dependency_overrides,
        container.get_oprf_service,
        lambda: mock_oprf_service,
    )

    with capture_records("app.routers.oprf") as captured:
        response = client.post(
            "/oprf/eval",
            json={
                "encryptedPersonalId": "Zm9v",
                "recipientOrganization": oprf_context.recipient_organization,
                "recipientScope": oprf_context.recipient_scope,
            },
            headers=valid_headers,
        )

    assert response.status_code == 404
    assert response.json() == {
        "detail": "Unable to find requested recipient organization"
    }
    assert len(captured.for_event(Log.OPRF_REFUSED_NO_ACTIVE_PUBKEY)) == 1
    assert not captured.for_event(Log.OPRF_EVAL_FAILED)


def test_unreachable_hsm_answers_503_and_is_audited(
    client: TestClient,
    oprf_context: OprfIntegrationContext,
    valid_headers: dict[str, str],
    valid_client_organization_id: Oin,
    app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tests that an unreachable HSM returns 503 and is audited."""
    from app.services.oprf.oprf_service import OprfService

    mock_oprf_service = MagicMock(spec=OprfService)
    mock_oprf_service.eval_blind.side_effect = HsmUnreachableError()

    monkeypatch.setitem(
        app.dependency_overrides,
        container.get_oprf_service,
        lambda: mock_oprf_service,
    )

    with capture_records("app.routers.oprf") as captured:
        response = client.post(
            "/oprf/eval",
            json={
                "encryptedPersonalId": "Zm9v",
                "recipientOrganization": oprf_context.recipient_organization,
                "recipientScope": oprf_context.recipient_scope,
            },
            headers=valid_headers,
        )

    assert response.status_code == 503
    [event] = captured.for_event(Log.OPRF_EVAL_FAILED)
    assert event.message["error_type"] == "hsm_unreachable"
