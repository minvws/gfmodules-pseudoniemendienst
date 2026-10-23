"""Releasing a caller-owned reversible pseudonym encrypted for that caller."""

# ruff: noqa: F811 - imported fixtures are used by name as test parameters

import base64
from datetime import timedelta
from typing import Any
from unittest.mock import patch

import pytest
from conftest import create_signed_jws, generate_rsa_keypair, setup_org_and_key
from fastapi import FastAPI
from fastapi.testclient import TestClient
from requests.exceptions import ConnectionError
from test_reversible_pseudonym_router import (  # noqa: F401 - fixtures
    ACTOR_OIN,
    BSN,
    RECIPIENT_OIN,
    SCOPE,
    SENDER_OIN,
    MakeOrganization,
    RecordLogs,
    _decrypt,
    _dump,
    _events,
    make_organization,
)

from app import container
from app.config import get_config
from app.db.db import Database
from app.db.models import OrganizationEntity
from app.db.session import DbSession
from app.enums.personal_id_type import PersonalIdType
from app.models.personal_id import PersonalId
from app.services.hsm_key_version_service import HsmKeyVersionService
from app.services.organization_public_key_service import OrganizationPublicKeyService
from app.utils.datetime import now_utc

ENDPOINT = "/exchange/personal-id"
LOGGER = "app.routers.exchange.personal_id"
PERSONAL_ID = "NL:bsn:950000012"
CALLER = f"oin:{SENDER_OIN}"


def _body(value: str) -> dict[str, str]:
    return {
        "reversiblePseudonym": value,
        "recipientOrganization": CALLER,
        "recipientScope": SCOPE,
    }


@pytest.fixture
def sender(make_organization: MakeOrganization) -> OrganizationEntity:
    return make_organization(
        SENDER_OIN,
        request=[PersonalIdType.REVERSIBLE_PSEUDONYM],
        receive=[PersonalIdType.REVERSIBLE_PSEUDONYM],
    )


@pytest.fixture
def caller_key(
    sender: OrganizationEntity,
    organization_public_key_service: OrganizationPublicKeyService,
) -> str:
    return setup_org_and_key(organization_public_key_service, sender, [SCOPE])


@pytest.fixture
def reversible_pseudonym(client: TestClient, sender: OrganizationEntity) -> str:
    return (
        container.get_reversible_pseudonym_service()
        .generate(PersonalId.from_str(PERSONAL_ID), SENDER_OIN, "source-scope")
        .value
    )


@pytest.mark.parametrize("prefix", ["", "pseudonym:reversible:"])
def test_returns_canonical_id_encrypted_to_the_verified_caller(
    prefix: str,
    client: TestClient,
    valid_headers: dict[str, str],
    reversible_pseudonym: str,
    caller_key: str,
    record_logs: RecordLogs,
) -> None:
    records = record_logs(LOGGER)

    response = client.post(
        ENDPOINT, json=_body(prefix + reversible_pseudonym), headers=valid_headers
    )

    assert response.status_code == 201
    assert response.headers["content-type"] == "application/jwe"
    header, claims = _decrypt(response.text, caller_key)
    assert header["alg"] == "RSA-OAEP"
    assert header["enc"] == "A256GCM"
    assert claims["subject"] == PERSONAL_ID
    assert claims["aud"] == CALLER
    assert claims["scope"] == SCOPE
    assert claims["version"] == "1.1"
    assert claims["exp"] - claims["iat"] == 300
    assert "keyVersion" not in claims
    assert "extraVersions" not in claims
    assert BSN not in response.text

    success = _events(records, "220405")
    assert len(success) == 1
    assert success[0].handelende_oin == str(ACTOR_OIN)  # type: ignore[attr-defined]
    assert success[0].namens_oin == str(SENDER_OIN)  # type: ignore[attr-defined]
    assert success[0].doel_oin == CALLER  # type: ignore[attr-defined]
    assert success[0].domein == SCOPE  # type: ignore[attr-defined]
    assert success[0].sleutel_versie == 1  # type: ignore[attr-defined]
    assert success[0].ontvanger_pubkey_id == header["kid"]  # type: ignore[attr-defined]
    for record in records:
        assert BSN not in _dump(record)
        assert reversible_pseudonym not in _dump(record)


def test_personal_id_round_trip_through_exchange_endpoints(
    client: TestClient,
    valid_headers: dict[str, str],
    sender: OrganizationEntity,
    caller_key: str,
    organization_public_key_service: OrganizationPublicKeyService,
) -> None:
    source_key = setup_org_and_key(
        organization_public_key_service, sender, ["source-scope"]
    )
    issued = client.post(
        "/exchange/reversible-pseudonym",
        json={
            "personalId": PERSONAL_ID,
            "recipientOrganization": f"oin:{SENDER_OIN}",
            "recipientScope": "source-scope",
        },
        headers=valid_headers,
    )
    assert issued.status_code == 201
    _, issued_claims = _decrypt(issued.text, source_key)

    recovered = client.post(
        ENDPOINT, json=_body(issued_claims["subject"]), headers=valid_headers
    )

    assert recovered.status_code == 201
    assert _decrypt(recovered.text, caller_key)[1]["subject"] == PERSONAL_ID


def test_audit_identifies_the_recipient_key_after_replacement(
    client: TestClient,
    valid_headers: dict[str, str],
    reversible_pseudonym: str,
    caller_key: str,
    organization_public_key_service: OrganizationPublicKeyService,
    record_logs: RecordLogs,
) -> None:
    registered = organization_public_key_service.get_by_org_and_domain(
        SENDER_OIN, SCOPE
    )
    records = record_logs(LOGGER)
    first = client.post(
        ENDPOINT, json=_body(reversible_pseudonym), headers=valid_headers
    )
    assert first.status_code == 201
    first_header, first_claims = _decrypt(first.text, caller_key)

    replacement_key, _ = generate_rsa_keypair()
    updated = organization_public_key_service.update(
        registered.id,
        SENDER_OIN,
        [SCOPE],
        create_signed_jws(replacement_key, SENDER_OIN),
    )
    assert updated["id"] == str(registered.id)
    second = client.post(
        ENDPOINT, json=_body(reversible_pseudonym), headers=valid_headers
    )
    assert second.status_code == 201
    second_header, second_claims = _decrypt(second.text, replacement_key)

    success = _events(records, "220405")
    assert len(success) == 2
    assert success[0].ontvanger_pubkey_id == first_header["kid"]  # type: ignore[attr-defined]
    assert success[1].ontvanger_pubkey_id == second_header["kid"]  # type: ignore[attr-defined]
    assert first_header["kid"] != second_header["kid"]
    assert first_claims["subject"] == second_claims["subject"] == PERSONAL_ID
    for event in success:
        assert event.sleutel_versie == 1  # type: ignore[attr-defined]
        assert BSN not in _dump(event)
        assert reversible_pseudonym not in _dump(event)


@pytest.mark.parametrize("source_state", ["expired", "ends-now", "future"])
def test_retained_source_outside_its_window_is_refused_before_cleanup(
    source_state: str,
    client: TestClient,
    valid_headers: dict[str, str],
    reversible_pseudonym: str,
    sender: OrganizationEntity,
    db_session: DbSession,
    caller_key: str,
    monkeypatch: pytest.MonkeyPatch,
    record_logs: RecordLogs,
) -> None:
    now = now_utc()
    monkeypatch.setattr("app.services.hsm_key_version_service.now_utc", lambda: now)
    version = sender.hsm_key_versions[0]
    if source_state == "future":
        version.from_dt = now + timedelta(seconds=1)
    else:
        version.until_dt = now - timedelta(seconds=source_state == "expired")
    db_session.commit()
    assert version.removed_at is None
    records = record_logs(LOGGER)

    response = client.post(
        ENDPOINT, json=_body(reversible_pseudonym), headers=valid_headers
    )

    assert response.status_code == 410
    assert response.json() == {"detail": "Pseudonym key version no longer available"}
    assert _events(records, "220405") == []
    failed = _events(records, "220406")
    assert len(failed) == 1
    assert failed[0].error_type == "version_destroyed"  # type: ignore[attr-defined]


def test_older_source_version_within_grace_still_reverses(
    client: TestClient,
    valid_headers: dict[str, str],
    reversible_pseudonym: str,
    sender: OrganizationEntity,
    db_session: DbSession,
    database: Database,
    caller_key: str,
) -> None:
    sender.hsm_key_versions[0].until_dt = now_utc() + timedelta(hours=1)
    db_session.commit()
    versions = HsmKeyVersionService(database)
    versions.increase_version_for_org(SENDER_OIN)
    assert versions.get_active_version_numbers_by_organization_oin(SENDER_OIN) == [1, 2]

    response = client.post(
        ENDPOINT, json=_body(reversible_pseudonym), headers=valid_headers
    )

    assert response.status_code == 201
    assert _decrypt(response.text, caller_key)[1]["subject"] == PERSONAL_ID


@pytest.mark.parametrize("scope", [None, "", "prs:oprf-pseudonym"])
def test_requires_pseudonym_scope(
    scope: str | None, client: TestClient, valid_headers: dict[str, str]
) -> None:
    headers = {k: v for k, v in valid_headers.items() if k != "x-gf-scope"}
    if scope is not None:
        headers["x-gf-scope"] = scope
    assert (
        client.post(ENDPOINT, json=_body("invalid"), headers=headers).status_code == 403
    )


def test_unregistered_caller_is_refused(
    client: TestClient, valid_headers: dict[str, str]
) -> None:
    response = client.post(ENDPOINT, json=_body("invalid"), headers=valid_headers)
    assert response.status_code == 403
    assert response.json() == {"detail": "Organization does not exist"}


def test_sender_denied_before_recipient_lookup_or_reversal(
    client: TestClient,
    valid_headers: dict[str, str],
    make_organization: MakeOrganization,
    record_logs: RecordLogs,
) -> None:
    make_organization(SENDER_OIN, request=[PersonalIdType.OPRF])
    # Actor grants must not authorize the verified subject.
    make_organization(ACTOR_OIN, request=[PersonalIdType.REVERSIBLE_PSEUDONYM])
    records = record_logs(LOGGER)

    response = client.post(ENDPOINT, json=_body("invalid"), headers=valid_headers)

    assert response.status_code == 403
    events = _events(records, "200402")
    assert len(events) == 1
    assert events[0].requested_operation == "exchange:personal-id"  # type: ignore[attr-defined]
    assert _events(records, "220406") == []


@pytest.mark.parametrize(
    "recipient_state", ["unknown", "registered", "authorized", "acting"]
)
def test_recipient_must_match_caller_before_any_lookup_or_reversal(
    recipient_state: str,
    client: TestClient,
    valid_headers: dict[str, str],
    reversible_pseudonym: str,
    caller_key: str,
    make_organization: MakeOrganization,
    organization_public_key_service: OrganizationPublicKeyService,
    record_logs: RecordLogs,
) -> None:
    recipient_oin = ACTOR_OIN if recipient_state == "acting" else RECIPIENT_OIN
    if recipient_state != "unknown":
        recipient = make_organization(
            recipient_oin,
            receive=(
                [PersonalIdType.REVERSIBLE_PSEUDONYM]
                if recipient_state in {"authorized", "acting"}
                else []
            ),
        )
        setup_org_and_key(organization_public_key_service, recipient, [SCOPE])
    body = {
        **_body(reversible_pseudonym),
        "recipientOrganization": f"oin:{recipient_oin}",
    }
    authorization = container.get_authorization_service()
    delivery_keys = container.get_organization_public_key_service()
    reversible = container.get_reversible_pseudonym_service()
    records = record_logs(LOGGER)

    with (
        patch.object(
            authorization,
            "validate_allowed_to_request",
            wraps=authorization.validate_allowed_to_request,
        ) as may_request,
        patch.object(
            authorization,
            "validate_allowed_to_receive",
            wraps=authorization.validate_allowed_to_receive,
        ) as may_receive,
        patch.object(
            delivery_keys,
            "get_by_org_and_domain",
            wraps=delivery_keys.get_by_org_and_domain,
        ) as lookup_key,
        patch.object(reversible, "reverse", wraps=reversible.reverse) as reverse,
    ):
        response = client.post(ENDPOINT, json=body, headers=valid_headers)

    assert response.status_code == 403
    assert response.json() == {"detail": "Unauthorized request"}
    may_request.assert_not_called()
    may_receive.assert_not_called()
    lookup_key.assert_not_called()
    reverse.assert_not_called()
    denied = _events(records, "200402")
    assert len(denied) == 1
    assert denied[0].handelende_oin == str(ACTOR_OIN)  # type: ignore[attr-defined]
    assert denied[0].namens_oin == str(SENDER_OIN)  # type: ignore[attr-defined]
    assert denied[0].doel_oin == body["recipientOrganization"]  # type: ignore[attr-defined]
    assert denied[0].requested_operation == "exchange:personal-id"  # type: ignore[attr-defined]
    assert _events(records, "220405") == []
    assert _events(records, "220406") == []
    for record in records:
        assert BSN not in _dump(record)
        assert reversible_pseudonym not in _dump(record)


@pytest.mark.parametrize("caller_state", ["no-receive", "no-key", "wrong-scope"])
def test_caller_without_receive_grant_or_delivery_key_is_refused(
    caller_state: str,
    client: TestClient,
    valid_headers: dict[str, str],
    sender: OrganizationEntity,
    db_session: DbSession,
    organization_public_key_service: OrganizationPublicKeyService,
) -> None:
    if caller_state == "no-receive":
        sender.receive_personal_id_types.clear()
        db_session.commit()
        setup_org_and_key(organization_public_key_service, sender, [SCOPE])
    elif caller_state == "wrong-scope":
        setup_org_and_key(organization_public_key_service, sender, ["another-scope"])

    response = client.post(ENDPOINT, json=_body("invalid"), headers=valid_headers)

    assert response.status_code == 404


def test_pseudonym_for_another_organization_cannot_be_reversed(
    client: TestClient,
    valid_headers: dict[str, str],
    caller_key: str,
    make_organization: MakeOrganization,
) -> None:
    make_organization(RECIPIENT_OIN, receive=[PersonalIdType.REVERSIBLE_PSEUDONYM])
    foreign = container.get_reversible_pseudonym_service().generate(
        PersonalId.from_str(PERSONAL_ID), RECIPIENT_OIN, SCOPE
    )

    response = client.post(ENDPOINT, json=_body(foreign.value), headers=valid_headers)

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid pseudonym"}


@pytest.mark.parametrize(
    "value", ["not-a-pseudonym", "pseudonym:irreversible:AQAB", ""]
)
def test_invalid_pseudonym_is_rejected_and_audited_without_its_value(
    value: str,
    client: TestClient,
    valid_headers: dict[str, str],
    sender: OrganizationEntity,
    caller_key: str,
    record_logs: RecordLogs,
) -> None:
    records = record_logs(LOGGER)

    response = client.post(ENDPOINT, json=_body(value), headers=valid_headers)

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid pseudonym"}
    failed = _events(records, "220406")
    assert len(failed) == 1
    assert failed[0].error_type == "invalid_pseudonym"  # type: ignore[attr-defined]
    assert _events(records, "220405") == []
    for record in records:
        if value:
            assert value not in _dump(record)
        assert BSN not in _dump(record)


def test_tampered_pseudonym_is_refused(
    client: TestClient,
    valid_headers: dict[str, str],
    reversible_pseudonym: str,
    caller_key: str,
) -> None:
    raw = bytearray(base64.urlsafe_b64decode(reversible_pseudonym))
    raw[-1] ^= 1
    tampered = base64.urlsafe_b64encode(raw).decode("ascii")

    response = client.post(ENDPOINT, json=_body(tampered), headers=valid_headers)

    assert response.status_code == 400
    assert BSN not in response.text
    assert tampered not in response.text


def test_destroyed_source_version_is_gone(
    client: TestClient,
    valid_headers: dict[str, str],
    reversible_pseudonym: str,
    database: Database,
    caller_key: str,
    record_logs: RecordLogs,
) -> None:
    versions = HsmKeyVersionService(database)
    for version in versions.get_versions_by_organization_id(SENDER_OIN):
        versions.mark_removed(version.id)
    records = record_logs(LOGGER)

    response = client.post(
        ENDPOINT, json=_body(reversible_pseudonym), headers=valid_headers
    )

    assert response.status_code == 410
    assert response.json() == {"detail": "Pseudonym key version no longer available"}
    assert _events(records, "220406")[0].error_type == "version_destroyed"  # type: ignore[attr-defined]


def test_hsm_failure_returns_503_without_sensitive_values(
    client: TestClient,
    valid_headers: dict[str, str],
    reversible_pseudonym: str,
    caller_key: str,
    monkeypatch: pytest.MonkeyPatch,
    record_logs: RecordLogs,
) -> None:
    service = container.get_reversible_pseudonym_service()

    def unreachable(*args: Any) -> bytes:
        raise ConnectionError("HSM unreachable")

    monkeypatch.setattr(service._keys, "decrypt", unreachable)
    records = record_logs(LOGGER)

    response = client.post(
        ENDPOINT, json=_body(reversible_pseudonym), headers=valid_headers
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "Pseudonym exchange failed"}
    assert _events(records, "220406")[0].error_type == "hsm_unreachable"  # type: ignore[attr-defined]
    for record in records:
        assert BSN not in _dump(record)
        assert reversible_pseudonym not in _dump(record)


@pytest.mark.parametrize(
    "fields",
    [
        {},
        {"reversiblePseudonym": None},
        {"reversiblePseudonym": 123},
        {"reversiblePseudonym": "AQAB", "personalId": PERSONAL_ID},
        {"reversiblePseudonym": "AQAB", "unexpected": "value"},
        {"reversiblePseudonym": "AQAB", "recipientScope": "bad|scope"},
    ],
)
def test_invalid_request_shape_never_echoes_input(
    fields: dict[str, Any], client: TestClient, valid_headers: dict[str, str]
) -> None:
    body = {"recipientOrganization": CALLER, "recipientScope": SCOPE, **fields}
    response = client.post(ENDPOINT, json=body, headers=valid_headers)
    assert response.status_code == 422
    assert BSN not in response.text
    assert "AQAB" not in response.text


def test_recipient_organization_is_still_required(
    client: TestClient, valid_headers: dict[str, str]
) -> None:
    body = {"reversiblePseudonym": "AQAB", "recipientScope": SCOPE}
    response = client.post(ENDPOINT, json=body, headers=valid_headers)

    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"] == ["body", "recipientOrganization"]


def test_openapi_describes_the_personal_id_exchange(app: FastAPI) -> None:
    schema = app.openapi()
    operation = schema["paths"][ENDPOINT]["post"]
    assert "application/jwe" in operation["responses"]["201"]["content"]
    assert {"400", "403", "404", "410", "422", "500", "503"} <= set(
        operation["responses"]
    )
    request = schema["components"]["schemas"][
        "PersonalIdFromReversiblePseudonymRequest"
    ]
    assert "recipientOrganization" in request["required"]
    assert "Must match the verified calling organization" in request["properties"][
        "recipientOrganization"
    ]["description"]


def test_exchange_flag_hides_route_and_openapi(
    monkeypatch: pytest.MonkeyPatch, valid_headers: dict[str, str]
) -> None:
    from app.application import setup_fastapi

    monkeypatch.setattr(get_config().app, "enable_exchange_services_routes", False)
    app = setup_fastapi()
    assert ENDPOINT not in app.openapi()["paths"]
    assert (
        TestClient(app)
        .post(ENDPOINT, json=_body("AQAB"), headers=valid_headers)
        .status_code
        == 404
    )
