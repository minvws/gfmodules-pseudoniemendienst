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
from app.services.oprf.oprf_service import OprfService
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
) -> None:
    """Tests that the OPRF roundtrip returns a stable pseudonym for the same input.
    Uses LocalOprfEvaluator to avoid requiring a real HSM service.
    """
    # Generate a local OPRF server key
    server_key = pyoprf.keygen()

    # Create a LocalOprfEvaluator with the server key
    local_evaluator = LocalOprfEvaluator(server_key)

    # Create an OPRF service with the local evaluator
    # Note: OprfService also needs a jwe_token_service, but we can pass None
    # and it will create a default one
    oprf_service = OprfService(local_evaluator)

    # Override the OPRF service dependency
    app.dependency_overrides[container.get_oprf_service] = lambda: oprf_service

    try:
        # Now we can use the real run_oprf_eval_and_unblind function
        # because the evaluator will do real (local) OPRF operations
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
    finally:
        app.dependency_overrides.pop(container.get_oprf_service, None)


def test_oprf_eval_success_emits_audit_event(
    client: TestClient,
    oprf_context: OprfIntegrationContext,
    valid_headers: dict[str, str],
    valid_organization_id: Oin,
    valid_client_organization_id: Oin,
    app: FastAPI,
) -> None:
    """Tests that a successful OPRF evaluation emits the correct audit event."""

    # Generate a local OPRF server key
    server_key = pyoprf.keygen()

    # Create a LocalOprfEvaluator with the server key
    local_evaluator = LocalOprfEvaluator(server_key)

    # Create an OPRF service with the local evaluator
    oprf_service = OprfService(local_evaluator)

    # Override the OPRF service dependency
    app.dependency_overrides[container.get_oprf_service] = lambda: oprf_service

    # Create a recording handler for audit events
    class RecordingHandler(logging.Handler):
        def __init__(self) -> None:
            super().__init__()
            self.records: list[logging.LogRecord] = []

        def emit(self, record: logging.LogRecord) -> None:
            self.records.append(record)

    handler = RecordingHandler()
    target_logger = logging.getLogger("app.routers.oprf")
    target_logger.addHandler(handler)

    try:
        # Run the OPRF evaluation
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
        events = [
            r for r in handler.records if getattr(r, "event_id", None) == "210400"
        ]
        assert len(events) == 1
        record = events[0]
        assert record.levelno == logging.INFO
        assert (
            record.handelende_oin == valid_client_organization_id.value  # type: ignore
        )
        assert (
            record.namens_oin  # type: ignore
            == valid_organization_id.value
        )
        assert (
            record.doel_oin  # type: ignore
            == oprf_context.recipient_organization
        )
        assert record.oprf_secret_versie == 1  # type: ignore[attr-defined]
        assert record.ontvanger_pubkey_id  # type: ignore[attr-defined]
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

    finally:
        target_logger.removeHandler(handler)
        app.dependency_overrides.pop(container.get_oprf_service, None)


def test_oprf_eval_unknown_scope_emits_refused_event(
    client: TestClient,
    oprf_context: OprfIntegrationContext,
    valid_headers: dict[str, str],
    valid_client_organization_id: Oin,
    app: FastAPI,
) -> None:
    """Tests that an unknown scope emits the correct refused audit event."""
    # Mock the organization public key service to raise DomainNotRegisteredError
    mock_pubkey_service = MagicMock(spec=OrganizationPublicKeyService)
    mock_pubkey_service.get_by_org_and_domain.side_effect = DomainNotRegisteredError()

    app.dependency_overrides[container.get_organization_public_key_service] = lambda: (
        mock_pubkey_service
    )

    try:
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
        assert entry.message["handelende_oin"] == valid_client_organization_id.value
        assert entry.message["doel_oin"] == oprf_context.recipient_organization
        assert not captured.for_event(Log.OPRF_EVAL_OK)

    finally:
        app.dependency_overrides.pop(
            container.get_organization_public_key_service, None
        )


def test_oprf_eval_unknown_recipient_emits_refused_event(
    client: TestClient,
    valid_headers: dict[str, str],
    persisted_organization: OrganizationEntity,
    app: FastAPI,
) -> None:
    """Tests that an unknown recipient emits the correct refused audit event."""
    # Mock the organization public key service to raise RecipientNotFoundError
    mock_pubkey_service = MagicMock(spec=OrganizationPublicKeyService)
    mock_pubkey_service.get_by_org_and_domain.side_effect = RecipientNotFoundError()

    app.dependency_overrides[container.get_organization_public_key_service] = lambda: (
        mock_pubkey_service
    )

    # Create a recording handler for audit events
    class RecordingHandler(logging.Handler):
        def __init__(self) -> None:
            super().__init__()
            self.records: list[logging.LogRecord] = []

        def emit(self, record: logging.LogRecord) -> None:
            self.records.append(record)

    handler = RecordingHandler()
    target_logger = logging.getLogger("app.routers.oprf")
    target_logger.addHandler(handler)

    try:
        response = client.post(
            "/oprf/eval",
            json={
                "encryptedPersonalId": "Zm9v",  # Fake blinded input
                "recipientOrganization": f"oin:{persisted_organization.external_id.value}",
                "recipientScope": "nvi",
            },
            headers=valid_headers,
        )

        assert response.status_code == 404
        events = [
            r for r in handler.records if getattr(r, "event_id", None) == "210403"
        ]
        assert len(events) == 1
        assert (
            events[0].doel_oin  # type: ignore
            == f"oin:{persisted_organization.external_id.value}"
        )
        assert not [
            r for r in handler.records if getattr(r, "event_id", None) == "210400"
        ]

    finally:
        target_logger.removeHandler(handler)
        app.dependency_overrides.pop(
            container.get_organization_public_key_service, None
        )


def test_oprf_eval_sender_not_allowed_to_request_is_refused_and_audited(
    client: TestClient,
    oprf_context: OprfIntegrationContext,
    valid_headers: dict[str, str],
    app: FastAPI,
) -> None:
    """Tests that a sender not allowed to request is refused and audited."""

    # Mock the authorization service to deny the request
    mock_auth_service = MagicMock(spec=AuthorizationService)
    mock_auth_service.validate_allowed_to_request.side_effect = (
        NotAllowedToRequestError(PersonalIdType.OPRF)
    )

    app.dependency_overrides[container.get_authorization_service] = lambda: (
        mock_auth_service
    )

    try:
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
        assert events[0].message["doel_oin"] == oprf_context.recipient_organization
        assert not captured.for_event(Log.OPRF_EVAL_OK)

    finally:
        app.dependency_overrides.pop(container.get_authorization_service, None)


def test_oprf_eval_failure_emits_failed_event_with_error_type(
    client: TestClient,
    oprf_context: OprfIntegrationContext,
    valid_headers: dict[str, str],
    valid_client_organization_id: Oin,
    app: FastAPI,
) -> None:
    """Tests that an OPRF evaluation failure emits the correct failed audit event."""
    # Mock the OPRF service to raise InvalidBlindedInputError
    mock_oprf_service = MagicMock(spec=OprfService)
    mock_oprf_service.eval_blind.side_effect = InvalidBlindedInputError()

    app.dependency_overrides[container.get_oprf_service] = lambda: mock_oprf_service

    # Create a recording handler for audit events
    class RecordingHandler(logging.Handler):
        def __init__(self) -> None:
            super().__init__()
            self.records: list[logging.LogRecord] = []

        def emit(self, record: logging.LogRecord) -> None:
            self.records.append(record)

    handler = RecordingHandler()
    target_logger = logging.getLogger("app.routers.oprf")
    target_logger.addHandler(handler)

    try:
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
        events = [
            r for r in handler.records if getattr(r, "event_id", None) == "210402"
        ]
        assert len(events) == 1
        record = events[0]
        assert record.levelno == logging.ERROR
        assert record.error_type == "invalid_blinded_input"  # type: ignore
        assert record.handelende_oin == valid_client_organization_id.value  # type: ignore
        assert record.doel_oin == oprf_context.recipient_organization  # type: ignore
        assert not [
            r for r in handler.records if getattr(r, "event_id", None) == "210400"
        ]

    finally:
        target_logger.removeHandler(handler)
        app.dependency_overrides.pop(container.get_oprf_service, None)


def test_app_error_from_evaluation_keeps_its_status_and_is_audited_as_refusal(
    client: TestClient,
    oprf_context: OprfIntegrationContext,
    valid_headers: dict[str, str],
    app: FastAPI,
) -> None:
    """Tests that domain errors from evaluation are not wrapped and are audited as refusals."""
    # Mock the OPRF service to raise RecipientNotFoundError
    mock_oprf_service = MagicMock(spec=OprfService)
    mock_oprf_service.eval_blind.side_effect = RecipientNotFoundError()

    app.dependency_overrides[container.get_oprf_service] = lambda: mock_oprf_service

    try:
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

    finally:
        app.dependency_overrides.pop(container.get_oprf_service, None)


def test_unreachable_hsm_answers_503_and_is_audited(
    client: TestClient,
    oprf_context: OprfIntegrationContext,
    valid_headers: dict[str, str],
    valid_client_organization_id: Oin,
    app: FastAPI,
) -> None:
    """Tests that an unreachable HSM returns 503 and is audited."""
    from app.services.oprf.oprf_service import OprfService

    # Mock the OPRF service to raise HsmUnreachableError
    mock_oprf_service = MagicMock(spec=OprfService)
    mock_oprf_service.eval_blind.side_effect = HsmUnreachableError()

    app.dependency_overrides[container.get_oprf_service] = lambda: mock_oprf_service

    try:
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

    finally:
        app.dependency_overrides.pop(container.get_oprf_service, None)
