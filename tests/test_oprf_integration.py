import base64
import json
import logging
from collections.abc import Generator
from dataclasses import dataclass

import pyoprf
import pytest
from conftest import setup_org_and_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import FastAPI
from jwcrypto import jwe, jwk
from starlette.testclient import TestClient

from app import container
from app.db.models import OrganizationEntity
from app.services.organization_public_key_service import OrganizationPublicKeyService


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
) -> None:

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


def test_oprf_eval_invalid_scope_returns_not_found(
    client: TestClient,
    oprf_context: OprfIntegrationContext,
    valid_headers: dict[str, str],
) -> None:
    _, blinded_input_raw = derive_blind_factor_and_input(
        personal_identifier=oprf_context.personal_identifier,
        recipient_organization=oprf_context.recipient_organization,
        recipient_scope=oprf_context.recipient_scope,
    )
    blinded_input = base64.urlsafe_b64encode(blinded_input_raw).decode("ascii")

    eval_response = client.post(
        "/oprf/eval",
        json={
            "encryptedPersonalId": blinded_input,
            "recipientOrganization": oprf_context.recipient_organization,
            "recipientScope": "invalid-scope",
        },
        headers=valid_headers,
    )

    assert eval_response.status_code == 404
    assert eval_response.json() == {"detail": "Organization domain does not exist"}


def test_oprf_eval_invalid_recipient_organization_returns_expected_error(
    client: TestClient,
    valid_headers: dict[str, str],
) -> None:
    eval_response = client.post(
        "/oprf/eval",
        json={
            "encryptedPersonalId": "Zm9v",
            "recipientOrganization": "12345678",
            "recipientScope": "nvi",
        },
        headers=valid_headers,
    )

    assert eval_response.status_code == 422
    assert eval_response.json()["detail"][0]["msg"] == (
        "Invalid recipient organization. Format: oin:<oin_number>"
    )


def test_oprf_eval_invalid_prefixed_recipient_organization_returns_expected_error(
    client: TestClient,
    valid_headers: dict[str, str],
) -> None:
    eval_response = client.post(
        "/oprf/eval",
        json={
            "encryptedPersonalId": "Zm9v",
            "recipientOrganization": "oin:00000099",
            "recipientScope": "nvi",
        },
        headers=valid_headers,
    )

    assert eval_response.status_code == 422
    assert eval_response.json()["detail"][0]["msg"] == (
        "Invalid OIN '00000099'. Expected 20 characters structured as 8 digit prefix + 8/9 alphanumeric mainnumber + 4/3 trailing zeros."
    )


def test_oprf_eval_unknown_oin_returns_not_found(
    client: TestClient,
    valid_headers: dict[str, str],
    persisted_organization: OrganizationEntity,
) -> None:
    valid_headers["x-gf-sub"] = persisted_organization.external_id.value
    eval_response = client.post(
        "/oprf/eval",
        json={
            "encryptedPersonalId": "Zm9v",
            "recipientOrganization": "oin:00000099000000003000",
            "recipientScope": "nvi",
        },
        headers=valid_headers,
    )

    assert eval_response.status_code == 404
    assert eval_response.json() == {
        "detail": "Unable to find requested recipient organization"
    }


class _RecordingHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.fixture
def oprf_event_records() -> Generator[list[logging.LogRecord], None, None]:
    handler = _RecordingHandler()
    target = logging.getLogger("app.routers.oprf")
    target.addHandler(handler)
    try:
        yield handler.records
    finally:
        target.removeHandler(handler)


def _events(records: list[logging.LogRecord], event_id: str) -> list[logging.LogRecord]:
    return [r for r in records if getattr(r, "event_id", None) == event_id]


# def test_oprf_eval_success_emits_audit_event(
#    client: TestClient,
#    oprf_context: OprfIntegrationContext,
#    oprf_event_records: list[logging.LogRecord],
#    valid_headers: dict[str, str],
#    valid_client_organization_id: Oin,
# ) -> None:
#    run_oprf_eval_and_unblind(
#        client=client,
#        private_key_pem=oprf_context.private_key_pem,
#        personal_identifier=oprf_context.personal_identifier,
#        recipient_organization=oprf_context.recipient_organization,
#        recipient_scope=oprf_context.recipient_scope,
#        headers=valid_headers,
#    )
#
#    events = _events(oprf_event_records, "210400")
#    assert len(events) == 1
#    record = events[0]
#    assert record.levelno == logging.INFO
#    assert record.handelende_oin == valid_client_organization_id.value  # type: ignore[attr-defined]
#    assert record.doel_oin == oprf_context.recipient_organization  # type: ignore[attr-defined]
#    assert record.oprf_secret_versie == 1  # type: ignore[attr-defined]
#    assert LoggingStreams.SIEM in record.stream  # type: ignore[attr-defined]


# def test_oprf_eval_unknown_scope_emits_refused_event(
#     client: TestClient,
#     oprf_context: OprfIntegrationContext,
#     oprf_event_records: list[logging.LogRecord],
#     valid_headers: dict[str, str],
#     valid_client_organization_id: Oin,
# ) -> None:
#     response = client.post(
#         "/oprf/eval",
#         json={
#             "encryptedPersonalId": "Zm9v",
#             "recipientOrganization": oprf_context.recipient_organization,
#             "recipientScope": "invalid-scope",
#         },
#         headers=valid_headers,
#     )
#
#     assert response.status_code == 404
#     events = _events(oprf_event_records, "210403")
#     assert len(events) == 1
#     record = events[0]
#     assert record.levelno == logging.WARNING
#     assert record.handelende_oin == valid_client_organization_id.value  # type: ignore[attr-defined]
#     assert record.doel_oin == oprf_context.recipient_organization  # type: ignore[attr-defined]
#     assert record.endpoint == "/oprf/eval"  # type: ignore[attr-defined]


# def test_oprf_eval_failure_emits_failed_event_with_error_type(
#    app: FastAPI,
#    client: TestClient,
#    oprf_context: OprfIntegrationContext,
#    oprf_event_records: list[logging.LogRecord],
#    valid_headers: dict[str, str],
#    valid_client_organization_id: Oin,
# ) -> None:
#    class FailingOprfService:
#        def eval_blind(
#            self, req: object, pub_key_jwk: object, pub_key_id: str | None
#        ) -> str:
#            raise OprfEvaluationError(
#                "invalid blinded input", error_type="invalid_blinded_input"
#            )
#
#    app.dependency_overrides[container.get_oprf_service] = lambda: FailingOprfService()
#    try:
#        response = client.post(
#            "/oprf/eval",
#            json={
#                "encryptedPersonalId": "Zm9v",
#                "recipientOrganization": oprf_context.recipient_organization,
#                "recipientScope": oprf_context.recipient_scope,
#            },
#            headers=valid_headers,
#        )
#    finally:
#        app.dependency_overrides.pop(container.get_oprf_service, None)
#
#    assert response.status_code == 400
#    events = _events(oprf_event_records, "210402")
#    assert len(events) == 1
#    record = events[0]
#    assert record.levelno == logging.ERROR
#    assert record.error_type == "invalid_blinded_input"  # type: ignore[attr-defined]
#    assert record.handelende_oin == valid_client_organization_id.value  # type: ignore[attr-defined]
#    assert record.doel_oin == oprf_context.recipient_organization  # type: ignore[attr-defined]


def test_oprf_eval_when_service_rejects_blind_returns_bad_request(
    app: FastAPI,
    client: TestClient,
    oprf_context: OprfIntegrationContext,
    valid_headers: dict[str, str],
) -> None:
    class FailingOprfService:
        def eval_blind(
            self, req: object, pub_key_jwk: object, pub_key_id: str | None
        ) -> str:
            raise ValueError("invalid blinded input")

    app.dependency_overrides[container.get_oprf_service] = lambda: FailingOprfService()
    try:
        eval_response = client.post(
            "/oprf/eval",
            json={
                "encryptedPersonalId": "Zm9v",
                "recipientOrganization": oprf_context.recipient_organization,
                "recipientScope": oprf_context.recipient_scope,
            },
            headers=valid_headers,
        )
    finally:
        app.dependency_overrides.pop(container.get_oprf_service, None)

    assert eval_response.status_code == 400
    assert eval_response.json() == {"detail": "Unable to evaluate blind"}
