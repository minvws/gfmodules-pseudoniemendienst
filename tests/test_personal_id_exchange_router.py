# ruff: noqa: F811 - the imported fixtures are used by name as test parameters

from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient
from test_reversible_pseudonym_router import (  # noqa: F401 - fixtures
    ACTOR_OIN,
    BSN,
    RECIPIENT,
    RECIPIENT_OIN,
    SCOPE,
    SENDER_OIN,
    MakeOrganization,
    MakeRecipient,
    RecordLogs,
    _decrypt,
    _dump,
    _events,
    make_organization,
    make_recipient,
)

from app import container
from app.db.db import Database
from app.enums.personal_id_type import PersonalIdType
from app.models.auth.data import AuthorizationScope
from app.models.oin import Oin
from app.models.personal_id import PersonalId
from app.services.hsm_key_version_service import HsmKeyVersionService
from app.utils.datetime import now_utc

ENDPOINT = "/exchange/personal-id"
LOGGER = "app.routers.exchange.personal_id"
PERSONAL_ID = f"NL:bsn:{BSN}"


def _body(value: str) -> dict[str, str]:
    return {
        "reversiblePseudonym": value,
        "recipientOrganization": RECIPIENT,
        "recipientScope": SCOPE,
    }


def _issue(oin: Oin) -> str:
    return (
        container.get_reversible_pseudonym_service()
        .generate(PersonalId.from_str(PERSONAL_ID), oin, "own-scope")
        .value
    )


@pytest.fixture
def sender(make_organization: MakeOrganization) -> None:
    make_organization(SENDER_OIN, request=[PersonalIdType.REVERSIBLE_PSEUDONYM])


@pytest.fixture
def pseudonym(client: TestClient, sender: None) -> str:
    return _issue(SENDER_OIN)


@pytest.mark.parametrize(
    "as_input",
    [lambda value: value, lambda value: f"pseudonym:reversible:{value}"],
    ids=["bare", "as-received"],
)
def test_happy_path_returns_jwe_with_personal_id(
    as_input: Callable[[str], str],
    client: TestClient,
    valid_headers: dict[str, str],
    pseudonym: str,
    make_recipient: MakeRecipient,
    record_logs: RecordLogs,
) -> None:
    priv_key = make_recipient()
    records = record_logs(LOGGER)

    response = client.post(
        ENDPOINT, json=_body(as_input(pseudonym)), headers=valid_headers
    )

    assert response.status_code == 201
    assert response.headers["content-type"] == "application/jwe"
    headers, claims = _decrypt(response.text, priv_key)
    assert claims["subject"] == PERSONAL_ID
    assert claims["aud"] == RECIPIENT
    assert claims["scope"] == SCOPE
    assert "keyVersion" not in claims

    events = _events(records, "220405")
    assert len(events) == 1
    event = events[0]
    assert event.handelende_oin == str(ACTOR_OIN)  # type: ignore[attr-defined]
    assert event.namens_oin == str(SENDER_OIN)  # type: ignore[attr-defined]
    assert event.doel_oin == RECIPIENT  # type: ignore[attr-defined]
    assert event.domein == SCOPE  # type: ignore[attr-defined]
    assert event.sleutel_versie == 1  # type: ignore[attr-defined]
    assert event.ontvanger_pubkey_id == headers["kid"]  # type: ignore[attr-defined]
    for record in records:
        assert BSN not in _dump(record)
        assert pseudonym not in _dump(record)


def test_requires_the_pseudonym_scope(
    client: TestClient,
    headers_with_scopes: Callable[..., dict[str, str]],
    pseudonym: str,
    make_recipient: MakeRecipient,
) -> None:
    make_recipient()
    headers = headers_with_scopes(
        AuthorizationScope.ADMINISTRATION, AuthorizationScope.OPRF_PSEUDONYM
    )

    response = client.post(ENDPOINT, json=_body(pseudonym), headers=headers)

    assert response.status_code == 403


def test_unregistered_caller_is_rejected(
    client: TestClient, valid_headers: dict[str, str], make_recipient: MakeRecipient
) -> None:
    make_recipient()

    response = client.post(ENDPOINT, json=_body("AQAB"), headers=valid_headers)

    assert response.status_code == 403
    assert response.json() == {"detail": "Organization does not exist"}


def test_sender_not_allowed_to_request_is_refused_before_anything_else(
    client: TestClient,
    valid_headers: dict[str, str],
    make_organization: MakeOrganization,
    record_logs: RecordLogs,
) -> None:
    make_organization(SENDER_OIN, request=[PersonalIdType.IRREVERSIBLE_PSEUDONYM])
    records = record_logs(LOGGER)

    response = client.post(ENDPOINT, json=_body("AQAB"), headers=valid_headers)

    assert response.status_code == 403
    events = _events(records, "200402")
    assert len(events) == 1
    assert events[0].requested_operation == "exchange:personal-id"  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "recipient",
    [None, {"receive": [PersonalIdType.IRREVERSIBLE_PSEUDONYM]}, {"with_key": False}],
    ids=["unknown", "not-allowed-to-receive", "without-public-key"],
)
def test_unavailable_recipient_is_not_found(
    recipient: dict[str, Any] | None,
    client: TestClient,
    valid_headers: dict[str, str],
    pseudonym: str,
    make_recipient: MakeRecipient,
) -> None:
    if recipient is not None:
        make_recipient(**recipient)

    response = client.post(ENDPOINT, json=_body(pseudonym), headers=valid_headers)

    assert response.status_code == 404


def test_reversible_pseudonym_of_another_organization_is_refused(
    client: TestClient,
    valid_headers: dict[str, str],
    sender: None,
    make_recipient: MakeRecipient,
    record_logs: RecordLogs,
) -> None:
    make_recipient()
    foreign = _issue(RECIPIENT_OIN)
    records = record_logs(LOGGER)

    response = client.post(ENDPOINT, json=_body(foreign), headers=valid_headers)

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid pseudonym"}
    failed = _events(records, "220406")
    assert len(failed) == 1
    assert failed[0].error_type == "invalid_pseudonym"  # type: ignore[attr-defined]
    assert _events(records, "220405") == []


def test_reversible_pseudonym_with_expired_key_version_is_gone(
    client: TestClient,
    valid_headers: dict[str, str],
    database: Database,
    pseudonym: str,
    make_recipient: MakeRecipient,
    record_logs: RecordLogs,
) -> None:
    make_recipient()
    versions = HsmKeyVersionService(database)
    for version in versions.get_versions_by_organization_id(SENDER_OIN):
        versions.update_version_by_organization_id(version.id, SENDER_OIN, now_utc())
    records = record_logs(LOGGER)

    response = client.post(ENDPOINT, json=_body(pseudonym), headers=valid_headers)

    assert response.status_code == 410
    assert response.json() == {"detail": "Pseudonym key version no longer available"}
    failed = _events(records, "220406")
    assert len(failed) == 1
    assert failed[0].error_type == "version_destroyed"  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "value",
    ["not-a-pseudonym", "pseudonym:irreversible:AQAB"],
    ids=["garbage", "irreversible-subject"],
)
def test_garbage_reversible_pseudonym_is_refused_without_logging_it(
    value: str,
    client: TestClient,
    valid_headers: dict[str, str],
    sender: None,
    make_recipient: MakeRecipient,
    record_logs: RecordLogs,
) -> None:
    make_recipient()
    records = record_logs(LOGGER)

    response = client.post(ENDPOINT, json=_body(value), headers=valid_headers)

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid pseudonym"}
    assert len(_events(records, "220406")) == 1
    for record in records:
        assert value not in _dump(record)
