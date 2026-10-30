import json
import logging
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

import pytest
from conftest import JWT_ISSUER, decrypt_signed, personal_id_types, setup_org_and_key
from fastapi.testclient import TestClient
from jwcrypto import jwe, jwk

from app import container
from app.db.db import Database
from app.db.models import HsmKeyVersionEntity, OrganizationEntity
from app.db.session import DbSession
from app.enums.personal_id_type import PersonalIdType
from app.models.auth.data import AuthorizationScope
from app.models.oin import Oin
from app.models.personal_id import PersonalId
from app.services.hsm_key_version_service import HsmKeyVersionService
from app.services.jwt_signer import JwtSigningService
from app.services.organization_public_key_service import OrganizationPublicKeyService

ENDPOINT = "/exchange/reversible-pseudonym"
LOGGER = "app.routers.exchange.reversible_pseudonym"

# The verified caller identity (x-gf-sub) in the valid_headers fixture.
SENDER_OIN = Oin("00000099000000002000")
# The acting organization (x-gf-act-sub) in the valid_headers fixture.
ACTOR_OIN = Oin("00000099000000001000")
RECIPIENT_OIN = Oin("00000099000000003000")
RECIPIENT = f"oin:{RECIPIENT_OIN}"
SCOPE = "nvi"
BSN = "950000012"
BODY = {
    "personalId": f"NL:bsn:{BSN}",
    "recipientOrganization": RECIPIENT,
    "recipientScope": SCOPE,
}

RecordLogs = Callable[[str], list[logging.LogRecord]]
MakeOrganization = Callable[..., OrganizationEntity]
MakeRecipient = Callable[..., str]


def _decrypt(token: str, priv_key_pem: str) -> tuple[dict[str, Any], dict[str, Any]]:
    parsed = jwe.JWE()
    parsed.deserialize(token)
    parsed.decrypt(jwk.JWK.from_pem(priv_key_pem.encode("ascii")))
    return parsed.jose_header, json.loads(parsed.payload.decode("utf-8"))


def _dump(record: logging.LogRecord) -> str:
    """Everything a handler could emit for the record: message and all extras."""
    return record.getMessage() + repr(record.__dict__)


def _events(records: list[logging.LogRecord], event_id: str) -> list[logging.LogRecord]:
    return [r for r in records if getattr(r, "event_id", None) == event_id]


def _reversible_body(value: str) -> dict[str, str]:
    return {
        "reversiblePseudonym": value,
        "recipientOrganization": RECIPIENT,
        "recipientScope": SCOPE,
    }


@pytest.fixture
def make_organization(db_session: DbSession) -> MakeOrganization:
    """Register an organization with the personal ID types it may request and
    receive (administrator-managed), and one active HSM key version."""

    def _make(
        oin: Oin,
        request: list[PersonalIdType] | None = None,
        receive: list[PersonalIdType] | None = None,
        active_key_version: bool = True,
    ) -> OrganizationEntity:
        org = OrganizationEntity(
            external_id=oin,
            name=f"org-{oin.value}",
            request_personal_id_types=personal_id_types(db_session, request or []),
            receive_personal_id_types=personal_id_types(db_session, receive or []),
            hsm_key_versions=(
                [HsmKeyVersionEntity(version=1, from_dt=datetime.now(timezone.utc))]
                if active_key_version
                else []
            ),
        )
        db_session.add(org)
        db_session.commit()
        return org

    return _make


@pytest.fixture
def sender(make_organization: MakeOrganization) -> None:
    make_organization(SENDER_OIN, request=[PersonalIdType.REVERSIBLE_PSEUDONYM])


@pytest.fixture
def make_recipient(
    make_organization: MakeOrganization,
    organization_public_key_service: OrganizationPublicKeyService,
) -> MakeRecipient:
    """Register the recipient organization with the given receivable personal ID
    types and, unless told otherwise, a public key for SCOPE. Returns the
    matching private key."""

    def _make(
        receive: list[PersonalIdType] | None = None,
        with_key: bool = True,
        domains: list[str] | None = None,
        active_key_version: bool = True,
    ) -> str:
        if receive is None:
            receive = [PersonalIdType.REVERSIBLE_PSEUDONYM]
        org = make_organization(
            RECIPIENT_OIN, receive=receive, active_key_version=active_key_version
        )
        if not with_key:
            return ""
        return setup_org_and_key(
            organization_public_key_service, org, domains or [SCOPE]
        )

    return _make


def test_happy_path_returns_jwe_with_reversible_pseudonym(
    client: TestClient,
    valid_headers: dict[str, str],
    sender: None,
    make_recipient: MakeRecipient,
    record_logs: RecordLogs,
) -> None:
    priv_key = make_recipient()
    records = record_logs(LOGGER)

    response = client.post(ENDPOINT, json=BODY, headers=valid_headers)

    assert response.status_code == 201
    assert response.headers["content-type"] == "application/jwe"

    headers, claims = _decrypt(response.text, priv_key)
    assert headers["alg"] == "RSA-OAEP"
    assert headers["enc"] == "A256GCM"
    assert claims["subject"].startswith("pseudonym:reversible:")
    assert claims["aud"] == RECIPIENT
    assert claims["scope"] == SCOPE
    assert claims["keyVersion"] == 1

    events = _events(records, "220400")
    assert len(events) == 1
    event = events[0]
    assert event.handelende_oin == str(ACTOR_OIN)  # type: ignore[attr-defined]
    assert event.namens_oin == str(SENDER_OIN)  # type: ignore[attr-defined]
    assert event.doel_oin == RECIPIENT  # type: ignore[attr-defined]
    assert event.domein == SCOPE  # type: ignore[attr-defined]
    assert event.sleutel_versie == 1  # type: ignore[attr-defined]


def test_with_jwt_signing_returns_signed_reversible_pseudonym(
    client: TestClient,
    valid_headers: dict[str, str],
    sender: None,
    make_recipient: MakeRecipient,
    jwt_signing: JwtSigningService,
) -> None:
    priv_key = make_recipient()

    response = client.post(ENDPOINT, json=BODY, headers=valid_headers)

    assert response.status_code == 201
    jwe_headers, jws_headers, claims = decrypt_signed(
        response.text, priv_key, jwt_signing
    )
    assert jwe_headers["cty"] == "JWT"
    assert jws_headers == {"alg": "PS256", "kid": jwt_signing.active.kid, "typ": "JWT"}
    assert claims["iss"] == JWT_ISSUER
    assert claims["subject"].startswith("pseudonym:reversible:")
    assert claims["aud"] == RECIPIENT
    assert claims["keyVersion"] == 1


def test_pseudonym_is_deterministic_and_accepts_both_personal_id_forms(
    client: TestClient,
    valid_headers: dict[str, str],
    sender: None,
    make_recipient: MakeRecipient,
) -> None:
    priv_key = make_recipient()
    as_dict = {**BODY, "personalId": {"landCode": "NL", "type": "bsn", "value": BSN}}

    first = client.post(ENDPOINT, json=BODY, headers=valid_headers)
    second = client.post(ENDPOINT, json=as_dict, headers=valid_headers)
    assert first.status_code == second.status_code == 201

    _, claims_first = _decrypt(first.text, priv_key)
    _, claims_second = _decrypt(second.text, priv_key)
    assert claims_first["subject"] == claims_second["subject"]


def test_scope_changes_the_pseudonym(
    client: TestClient,
    valid_headers: dict[str, str],
    sender: None,
    make_recipient: MakeRecipient,
) -> None:
    priv_key = make_recipient(domains=["*"])

    one = client.post(ENDPOINT, json=BODY, headers=valid_headers)
    other = client.post(
        ENDPOINT, json={**BODY, "recipientScope": "other"}, headers=valid_headers
    )
    assert one.status_code == other.status_code == 201

    _, claims_one = _decrypt(one.text, priv_key)
    _, claims_other = _decrypt(other.text, priv_key)
    assert claims_one["subject"] != claims_other["subject"]


@pytest.mark.parametrize(
    "as_input",
    [
        _reversible_body,
        lambda value: _reversible_body(f"pseudonym:reversible:{value}"),
    ],
    ids=["bare", "as-received"],
)
def test_reversible_pseudonym_of_the_caller_is_accepted_as_input(
    as_input: Callable[[str], dict[str, str]],
    client: TestClient,
    valid_headers: dict[str, str],
    make_organization: MakeOrganization,
    make_recipient: MakeRecipient,
    record_logs: RecordLogs,
) -> None:
    """A sender that holds a reversible pseudonym for its own organization gets
    the same reversible pseudonym for the recipient as it would for the
    personal ID."""
    make_organization(
        SENDER_OIN,
        request=[PersonalIdType.REVERSIBLE_PSEUDONYM],
        receive=[PersonalIdType.REVERSIBLE_PSEUDONYM],
    )
    priv_key = make_recipient()
    reversible = container.get_reversible_pseudonym_service().generate(
        PersonalId.from_str(f"NL:bsn:{BSN}"), SENDER_OIN, "own-scope"
    )
    records = record_logs(LOGGER)

    from_personal_id = client.post(ENDPOINT, json=BODY, headers=valid_headers)
    from_pseudonym = client.post(
        ENDPOINT, json=as_input(reversible.value), headers=valid_headers
    )

    assert from_pseudonym.status_code == 201
    _, claims_personal_id = _decrypt(from_personal_id.text, priv_key)
    _, claims_pseudonym = _decrypt(from_pseudonym.text, priv_key)
    assert claims_pseudonym["subject"] == claims_personal_id["subject"]
    assert len(_events(records, "220400")) == 2
    for record in records:
        assert BSN not in _dump(record)


def test_reversible_pseudonym_of_another_organization_is_refused(
    client: TestClient,
    valid_headers: dict[str, str],
    sender: None,
    make_recipient: MakeRecipient,
    record_logs: RecordLogs,
) -> None:
    """The reversible pseudonym was issued to the recipient, not to the caller,
    so the caller cannot have it reversed."""
    make_recipient()
    reversible = container.get_reversible_pseudonym_service().generate(
        PersonalId.from_str(f"NL:bsn:{BSN}"), RECIPIENT_OIN, SCOPE
    )
    records = record_logs(LOGGER)

    response = client.post(
        ENDPOINT, json=_reversible_body(reversible.value), headers=valid_headers
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid pseudonym"}
    failed = _events(records, "220403")
    assert len(failed) == 1
    assert failed[0].error_type == "invalid_pseudonym"  # type: ignore[attr-defined]
    assert _events(records, "220400") == []


def test_reversible_pseudonym_with_destroyed_key_version_is_gone(
    client: TestClient,
    valid_headers: dict[str, str],
    database: Database,
    sender: None,
    make_recipient: MakeRecipient,
    record_logs: RecordLogs,
) -> None:
    """The caller's own pseudonym was valid, but the key version it was issued
    under has since been destroyed by the HSM key cleanup."""
    make_recipient()
    reversible = container.get_reversible_pseudonym_service().generate(
        PersonalId.from_str(f"NL:bsn:{BSN}"), SENDER_OIN, "own-scope"
    )
    versions = HsmKeyVersionService(database)
    for version in versions.get_versions_by_organization_id(SENDER_OIN):
        versions.mark_removed(version.id)
    records = record_logs(LOGGER)

    response = client.post(
        ENDPOINT, json=_reversible_body(reversible.value), headers=valid_headers
    )

    assert response.status_code == 410
    assert response.json() == {"detail": "Pseudonym key version no longer available"}
    failed = _events(records, "220403")
    assert len(failed) == 1
    assert failed[0].error_type == "version_destroyed"  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "value",
    ["not-a-pseudonym", "pseudonym:irreversible:AQAB"],
    ids=["garbage", "irreversible-subject"],
)
def test_garbage_reversible_pseudonym_is_refused(
    value: str,
    client: TestClient,
    valid_headers: dict[str, str],
    sender: None,
    make_recipient: MakeRecipient,
    record_logs: RecordLogs,
) -> None:
    make_recipient()
    records = record_logs(LOGGER)

    response = client.post(
        ENDPOINT, json=_reversible_body(value), headers=valid_headers
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid pseudonym"}
    assert len(_events(records, "220403")) == 1


@pytest.mark.parametrize(
    "fields",
    [{}, {"personalId": f"NL:bsn:{BSN}", "reversiblePseudonym": "AQAB"}],
    ids=["neither", "both"],
)
def test_not_exactly_one_input_is_rejected_without_echoing_it(
    client: TestClient,
    valid_headers: dict[str, str],
    fields: dict[str, str],
) -> None:
    response = client.post(
        ENDPOINT,
        json={**fields, "recipientOrganization": RECIPIENT, "recipientScope": SCOPE},
        headers=valid_headers,
    )

    assert response.status_code == 422
    assert BSN not in response.text


def test_requires_the_pseudonym_scope(
    client: TestClient,
    headers_with_scopes: Callable[..., dict[str, str]],
    sender: None,
    make_recipient: MakeRecipient,
) -> None:
    make_recipient()
    headers = headers_with_scopes(
        AuthorizationScope.ADMINISTRATION, AuthorizationScope.OPRF_PSEUDONYM
    )

    response = client.post(ENDPOINT, json=BODY, headers=headers)

    assert response.status_code == 403


def test_unregistered_caller_is_rejected(
    client: TestClient, valid_headers: dict[str, str], make_recipient: MakeRecipient
) -> None:
    make_recipient()

    response = client.post(ENDPOINT, json=BODY, headers=valid_headers)

    assert response.status_code == 403
    assert response.json() == {"detail": "Organization does not exist"}


def test_sender_not_allowed_to_request_is_refused_before_anything_else(
    client: TestClient,
    valid_headers: dict[str, str],
    make_organization: MakeOrganization,
    record_logs: RecordLogs,
) -> None:
    """The recipient is not even registered here: the sender check comes first,
    so the caller cannot use the 404 to probe which organizations exist."""
    make_organization(SENDER_OIN, request=[PersonalIdType.OPRF])
    records = record_logs(LOGGER)

    response = client.post(ENDPOINT, json=BODY, headers=valid_headers)

    assert response.status_code == 403
    assert "Not allowed to request" in response.json()["detail"]

    events = _events(records, "200402")
    assert len(events) == 1
    event = events[0]
    assert event.requested_operation == "exchange:reversible-pseudonym"  # type: ignore[attr-defined]
    assert event.namens_oin == str(SENDER_OIN)  # type: ignore[attr-defined]
    assert event.doel_oin == RECIPIENT  # type: ignore[attr-defined]


def test_sender_permission_is_read_from_the_verified_caller_not_the_acting_org(
    client: TestClient,
    valid_headers: dict[str, str],
    make_organization: MakeOrganization,
    make_recipient: MakeRecipient,
) -> None:
    make_recipient()
    make_organization(SENDER_OIN, request=[PersonalIdType.OPRF])
    # x-gf-act-sub in valid_headers; being allowed here must not help.
    make_organization(ACTOR_OIN, request=[PersonalIdType.REVERSIBLE_PSEUDONYM])

    response = client.post(ENDPOINT, json=BODY, headers=valid_headers)

    assert response.status_code == 403


def test_recipient_not_allowed_to_receive_is_refused(
    client: TestClient,
    valid_headers: dict[str, str],
    sender: None,
    make_recipient: MakeRecipient,
    record_logs: RecordLogs,
) -> None:
    make_recipient(receive=[PersonalIdType.IRREVERSIBLE_PSEUDONYM])
    records = record_logs(LOGGER)

    response = client.post(ENDPOINT, json=BODY, headers=valid_headers)

    assert response.status_code == 404
    assert response.json() == {
        "detail": "Unable to find requested recipient organization"
    }
    assert len(_events(records, "200402")) == 1
    assert _events(records, "220400") == []


def test_unknown_recipient_is_not_found(
    client: TestClient, valid_headers: dict[str, str], sender: None
) -> None:
    response = client.post(ENDPOINT, json=BODY, headers=valid_headers)

    assert response.status_code == 404
    assert response.json() == {
        "detail": "Unable to find requested recipient organization"
    }


def test_recipient_without_public_key_for_scope_is_not_found(
    client: TestClient,
    valid_headers: dict[str, str],
    sender: None,
    make_recipient: MakeRecipient,
    record_logs: RecordLogs,
) -> None:
    make_recipient(with_key=False)
    records = record_logs(LOGGER)

    response = client.post(ENDPOINT, json=BODY, headers=valid_headers)

    assert response.status_code == 404
    assert response.json() == {"detail": "Organization domain is not registered"}
    assert len(_events(records, "220407")) == 1
    assert _events(records, "220400") == []


def test_recipient_without_active_key_version_is_not_found(
    client: TestClient,
    valid_headers: dict[str, str],
    sender: None,
    make_recipient: MakeRecipient,
    record_logs: RecordLogs,
) -> None:
    make_recipient(active_key_version=False)
    records = record_logs(LOGGER)

    response = client.post(ENDPOINT, json=BODY, headers=valid_headers)

    # Same answer as for an unknown recipient: the caller must not be able to
    # tell the recipient's key rotation state apart from its non-existence.
    assert response.status_code == 404
    assert response.json() == {
        "detail": "Unable to find requested recipient organization"
    }
    failed = _events(records, "220403")
    assert len(failed) == 1
    assert failed[0].error_type == "no_active_key_version"  # type: ignore[attr-defined]
    assert _events(records, "220400") == []


@pytest.mark.parametrize(
    "personal_id,kind",
    [
        ("950000012", "formaat"),
        ("NL:passport:950000012", "formaat"),
        ("N:bsn:950000012", "formaat"),
        ({"landCode": "NL", "value": BSN}, "formaat"),
        ("NL:bsn:95000001a", "formaat"),
        ("NL:bsn:95000001", "lengte"),
        ("NL:bsn:950000013", "elfproef"),
        ({"landCode": "NL", "type": "bsn", "value": "123456789"}, "elfproef"),
        ("pseudonym:reversible:AQAB", "formaat"),
    ],
)
def test_malformed_personal_id_is_rejected_and_audited_without_the_value(
    client: TestClient,
    valid_headers: dict[str, str],
    sender: None,
    make_recipient: MakeRecipient,
    record_logs: RecordLogs,
    personal_id: Any,
    kind: str,
) -> None:
    make_recipient()
    records = record_logs(LOGGER)

    response = client.post(
        ENDPOINT, json={**BODY, "personalId": personal_id}, headers=valid_headers
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid personal ID"}

    events = _events(records, "220404")
    assert len(events) == 1
    assert events[0].validation_error == kind  # type: ignore[attr-defined]
    number = (
        personal_id["value"]
        if isinstance(personal_id, dict)
        else personal_id.split(":")[-1]
    )
    for record in records:
        assert BSN not in _dump(record)
        assert number not in _dump(record)


def test_personal_id_value_never_appears_in_logs_on_success(
    client: TestClient,
    valid_headers: dict[str, str],
    sender: None,
    make_recipient: MakeRecipient,
    record_logs: RecordLogs,
) -> None:
    make_recipient()
    records = record_logs(LOGGER)

    response = client.post(ENDPOINT, json=BODY, headers=valid_headers)

    assert response.status_code == 201
    for record in records:
        assert BSN not in _dump(record)


def test_old_exchange_pseudonym_route_is_gone(
    client: TestClient, valid_headers: dict[str, str]
) -> None:
    response = client.post(
        "/exchange/pseudonym",
        json={**BODY, "pseudonymType": "reversible"},
        headers=valid_headers,
    )

    assert response.status_code == 404
