"""POST /exchange/irreversible-pseudonym.

The fixtures for organizations come from the reversible router tests; only the
personal ID type the sender and recipient are provisioned for differs.
"""

# ruff: noqa: F811 - the imported fixture is used by name as a test parameter

from collections.abc import Callable
from typing import Any

import pytest
from conftest import setup_org_and_key
from fastapi.testclient import TestClient
from test_reversible_pseudonym_router import (  # noqa: F401 - fixtures
    ACTOR_OIN,
    BSN,
    RECIPIENT,
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
from app.db.db import Database
from app.enums.personal_id_type import PersonalIdType
from app.models.auth.data import AuthorizationScope
from app.personal_id import PersonalId
from app.services.hsm_key_version_service import HsmKeyVersionService
from app.services.organization_public_key_service import OrganizationPublicKeyService

ENDPOINT = "/exchange/irreversible-pseudonym"
LOGGER = "app.routers.irreversible_pseudonym"
BODY = {
    "personalId": f"NL:bsn:{BSN}",
    "recipientOrganization": RECIPIENT,
    "recipientScope": SCOPE,
}
MakeRecipient = Callable[..., str]


@pytest.fixture
def sender(make_organization: MakeOrganization) -> None:
    make_organization(SENDER_OIN, request=[PersonalIdType.IRREVERSIBLE_PSEUDONYM])


@pytest.fixture
def make_recipient(
    make_organization: MakeOrganization,
    organization_public_key_service: OrganizationPublicKeyService,
) -> MakeRecipient:
    def _make(
        receive: list[PersonalIdType] | None = None,
        with_key: bool = True,
        active_key_version: bool = True,
    ) -> str:
        if receive is None:
            receive = [PersonalIdType.IRREVERSIBLE_PSEUDONYM]
        org = make_organization(
            RECIPIENT_OIN, receive=receive, active_key_version=active_key_version
        )
        if not with_key:
            return ""
        return setup_org_and_key(organization_public_key_service, org, [SCOPE])

    return _make


def _subject(response: Any, priv_key: str) -> tuple[dict[str, Any], str]:
    _, claims = _decrypt(response.text, priv_key)
    return claims, claims["subject"]


def test_happy_path_returns_jwe_with_irreversible_pseudonym(
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
    assert claims["subject"].startswith("pseudonym:irreversible:")
    assert claims["aud"] == RECIPIENT
    assert claims["scope"] == SCOPE
    assert claims["keyVersion"] == 1
    assert "extraVersions" not in claims

    events = _events(records, "220401")
    assert len(events) == 1
    event = events[0]
    assert event.handelende_oin == str(ACTOR_OIN)  # type: ignore[attr-defined]
    assert event.namens_oin == str(SENDER_OIN)  # type: ignore[attr-defined]
    assert event.doel_oin == RECIPIENT  # type: ignore[attr-defined]
    assert event.domein == SCOPE  # type: ignore[attr-defined]
    assert event.sleutel_versie == 1  # type: ignore[attr-defined]
    assert _events(records, "220402") == []
    for record in records:
        assert BSN not in _dump(record)
        assert claims["subject"] not in _dump(record)


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

    assert _subject(first, priv_key)[1] == _subject(second, priv_key)[1]


def test_pseudonym_differs_per_personal_id(
    client: TestClient,
    valid_headers: dict[str, str],
    sender: None,
    make_recipient: MakeRecipient,
) -> None:
    priv_key = make_recipient()

    one = client.post(ENDPOINT, json=BODY, headers=valid_headers)
    other = client.post(
        ENDPOINT, json={**BODY, "personalId": "NL:bsn:950000024"}, headers=valid_headers
    )

    assert _subject(one, priv_key)[1] != _subject(other, priv_key)[1]


def test_reversible_pseudonym_of_the_caller_is_accepted_as_input(
    client: TestClient,
    valid_headers: dict[str, str],
    make_organization: MakeOrganization,
    make_recipient: MakeRecipient,
) -> None:
    """A sender that holds a reversible pseudonym for its own organization gets
    the same irreversible pseudonym as it would for the personal ID."""
    make_organization(
        SENDER_OIN,
        request=[PersonalIdType.IRREVERSIBLE_PSEUDONYM],
        receive=[PersonalIdType.REVERSIBLE_PSEUDONYM],
    )
    priv_key = make_recipient()
    reversible = container.get_reversible_pseudonym_service().generate(
        PersonalId.from_str(f"NL:bsn:{BSN}"), SENDER_OIN, "own-scope"
    )

    from_personal_id = client.post(ENDPOINT, json=BODY, headers=valid_headers)
    from_pseudonym = client.post(
        ENDPOINT,
        json={**BODY, "personalId": f"pseudonym:reversible:{reversible.value}"},
        headers=valid_headers,
    )

    assert from_pseudonym.status_code == 201
    assert (
        _subject(from_personal_id, priv_key)[1] == _subject(from_pseudonym, priv_key)[1]
    )


def test_reversible_pseudonym_of_another_organization_is_refused(
    client: TestClient,
    valid_headers: dict[str, str],
    make_organization: MakeOrganization,
    make_recipient: MakeRecipient,
    record_logs: RecordLogs,
) -> None:
    """The reversible pseudonym was issued to the recipient, not to the caller,
    so the caller cannot have it reversed."""
    make_organization(SENDER_OIN, request=[PersonalIdType.IRREVERSIBLE_PSEUDONYM])
    make_recipient(
        receive=[
            PersonalIdType.IRREVERSIBLE_PSEUDONYM,
            PersonalIdType.REVERSIBLE_PSEUDONYM,
        ]
    )
    reversible = container.get_reversible_pseudonym_service().generate(
        PersonalId.from_str(f"NL:bsn:{BSN}"), RECIPIENT_OIN, SCOPE
    )
    records = record_logs(LOGGER)

    response = client.post(
        ENDPOINT,
        json={**BODY, "personalId": f"pseudonym:reversible:{reversible.value}"},
        headers=valid_headers,
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid pseudonym"}
    failed = _events(records, "220403")
    assert len(failed) == 1
    assert failed[0].error_type == "invalid_pseudonym"  # type: ignore[attr-defined]
    assert _events(records, "220401") == []


def test_reversible_pseudonym_with_destroyed_key_version_is_gone(
    client: TestClient,
    valid_headers: dict[str, str],
    database: Database,
    make_organization: MakeOrganization,
    make_recipient: MakeRecipient,
    record_logs: RecordLogs,
) -> None:
    """The caller's own pseudonym was valid, but the key version it was issued
    under has since been destroyed by the HSM key cleanup."""
    make_organization(
        SENDER_OIN,
        request=[PersonalIdType.IRREVERSIBLE_PSEUDONYM],
        receive=[PersonalIdType.REVERSIBLE_PSEUDONYM],
    )
    make_recipient()
    reversible = container.get_reversible_pseudonym_service().generate(
        PersonalId.from_str(f"NL:bsn:{BSN}"), SENDER_OIN, "own-scope"
    )
    versions = HsmKeyVersionService(database)
    for version in versions.get_versions_by_organization_id(SENDER_OIN):
        versions.mark_removed(version.id)
    records = record_logs(LOGGER)

    response = client.post(
        ENDPOINT,
        json={**BODY, "personalId": f"pseudonym:reversible:{reversible.value}"},
        headers=valid_headers,
    )

    assert response.status_code == 410
    assert response.json() == {"detail": "Pseudonym key version no longer available"}
    failed = _events(records, "220403")
    assert len(failed) == 1
    assert failed[0].error_type == "version_destroyed"  # type: ignore[attr-defined]


def test_garbage_reversible_pseudonym_is_refused(
    client: TestClient,
    valid_headers: dict[str, str],
    sender: None,
    make_recipient: MakeRecipient,
    record_logs: RecordLogs,
) -> None:
    make_recipient()
    records = record_logs(LOGGER)

    response = client.post(
        ENDPOINT,
        json={**BODY, "personalId": "pseudonym:reversible:not-a-pseudonym"},
        headers=valid_headers,
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid pseudonym"}
    assert len(_events(records, "220403")) == 1


def test_dual_version_during_grace_returns_both_and_is_audited(
    client: TestClient,
    valid_headers: dict[str, str],
    sender: None,
    make_recipient: MakeRecipient,
    database: Database,
    record_logs: RecordLogs,
) -> None:
    priv_key = make_recipient()
    before = client.post(ENDPOINT, json=BODY, headers=valid_headers)
    _, old_subject = _subject(before, priv_key)

    HsmKeyVersionService(database).increase_version_for_org(RECIPIENT_OIN)
    records = record_logs(LOGGER)

    during = client.post(ENDPOINT, json=BODY, headers=valid_headers)

    assert during.status_code == 201
    claims, new_subject = _subject(during, priv_key)
    assert claims["keyVersion"] == 2
    assert new_subject != old_subject
    assert claims["extraVersions"] == {
        "1": old_subject.removeprefix("pseudonym:irreversible:")
    }

    dual = _events(records, "220402")
    assert len(dual) == 1
    assert dual[0].sleutel_versie_oud == 1  # type: ignore[attr-defined]
    assert dual[0].sleutel_versie_actueel == 2  # type: ignore[attr-defined]
    assert dual[0].domein == SCOPE  # type: ignore[attr-defined]
    assert _events(records, "220401") == []


def test_requires_the_pseudonym_scope(
    client: TestClient,
    headers_with_scopes: Callable[..., dict[str, str]],
    sender: None,
    make_recipient: MakeRecipient,
) -> None:
    make_recipient()

    without = headers_with_scopes(AuthorizationScope.OPRF_PSEUDONYM)
    assert client.post(ENDPOINT, json=BODY, headers=without).status_code == 403

    granted = headers_with_scopes(AuthorizationScope.PSEUDONYM)
    assert client.post(ENDPOINT, json=BODY, headers=granted).status_code == 201


def test_sender_not_allowed_to_request_is_refused_before_anything_else(
    client: TestClient,
    valid_headers: dict[str, str],
    make_organization: MakeOrganization,
    record_logs: RecordLogs,
) -> None:
    make_organization(SENDER_OIN, request=[PersonalIdType.REVERSIBLE_PSEUDONYM])
    records = record_logs(LOGGER)

    response = client.post(ENDPOINT, json=BODY, headers=valid_headers)

    assert response.status_code == 403
    assert "Not allowed to request" in response.json()["detail"]
    events = _events(records, "200402")
    assert len(events) == 1
    assert events[0].requested_operation == "exchange:irreversible-pseudonym"  # type: ignore[attr-defined]


def test_recipient_not_allowed_to_receive_is_refused(
    client: TestClient,
    valid_headers: dict[str, str],
    sender: None,
    make_recipient: MakeRecipient,
    record_logs: RecordLogs,
) -> None:
    make_recipient(receive=[PersonalIdType.REVERSIBLE_PSEUDONYM])
    records = record_logs(LOGGER)

    response = client.post(ENDPOINT, json=BODY, headers=valid_headers)

    assert response.status_code == 404
    assert response.json() == {
        "detail": "Unable to find requested recipient organization"
    }
    assert len(_events(records, "200402")) == 1


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

    assert response.status_code == 404
    assert response.json() == {
        "detail": "Unable to find requested recipient organization"
    }
    failed = _events(records, "220403")
    assert len(failed) == 1
    assert failed[0].error_type == "no_active_key_version"  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "personal_id,kind",
    [
        ("NL:passport:950000012", "formaat"),
        ("NL:bsn:95000001", "lengte"),
        ("NL:bsn:950000013", "elfproef"),
    ],
)
def test_malformed_personal_id_is_rejected_and_audited_without_the_value(
    client: TestClient,
    valid_headers: dict[str, str],
    sender: None,
    make_recipient: MakeRecipient,
    record_logs: RecordLogs,
    personal_id: str,
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
    for record in records:
        assert personal_id.split(":")[-1] not in _dump(record)
