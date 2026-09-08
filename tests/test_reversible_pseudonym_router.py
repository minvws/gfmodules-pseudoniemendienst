import json
import logging
from collections.abc import Callable
from typing import Any

import pytest
from Crypto.PublicKey import RSA
from fastapi.testclient import TestClient
from jwcrypto import jwe, jwk

from app.models.auth.data import AuthorizationScope
from app.models.oin import Oin
from app.rid import RidUsage
from app.services.key_resolver import KeyResolver
from app.services.org_service import OrgService

ENDPOINT = "/exchange/reversible-pseudonym"
LOGGER = "app.routers.reversible_pseudonym"

# The verified caller identity (x-gf-sub) in the valid_headers fixture.
SENDER_OIN = Oin("00000099000000002000")
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
MakeRecipient = Callable[..., str]


def _rsa_keypair() -> tuple[str, str]:
    key = RSA.generate(1024)
    return key.export_key().decode(), key.publickey().export_key().decode()


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


@pytest.fixture
def sender(org_service: OrgService) -> None:
    org_service.create(
        SENDER_OIN,
        "Sender",
        RidUsage.IrreversiblePseudonym,
        may_provide_personal_id=True,
    )


@pytest.fixture
def make_recipient(org_service: OrgService, key_resolver: KeyResolver) -> MakeRecipient:
    """Register the recipient organization with the given usage level and, unless
    told otherwise, a public key for SCOPE. Returns the matching private key."""

    def _make(
        max_rid_usage: RidUsage = RidUsage.ReversiblePseudonym, with_key: bool = True
    ) -> str:
        org = org_service.create(RECIPIENT_OIN, "Recipient", max_rid_usage)
        priv_key, pub_key = _rsa_keypair()
        if with_key:
            key_resolver.create(org.id, [SCOPE], None, pub_key)
        return priv_key

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

    events = _events(records, "220400")
    assert len(events) == 1
    event = events[0]
    assert event.handelende_oin == "00000099000000001000"  # type: ignore[attr-defined]
    assert event.namens_oin == str(SENDER_OIN)  # type: ignore[attr-defined]
    assert event.doel_oin == RECIPIENT  # type: ignore[attr-defined]
    assert event.domein == SCOPE  # type: ignore[attr-defined]


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
    org_service: OrgService,
    key_resolver: KeyResolver,
) -> None:
    org = org_service.create(RECIPIENT_OIN, "Recipient", RidUsage.ReversiblePseudonym)
    priv_key, pub_key = _rsa_keypair()
    key_resolver.create(org.id, ["*"], None, pub_key)

    one = client.post(ENDPOINT, json=BODY, headers=valid_headers)
    other = client.post(
        ENDPOINT, json={**BODY, "recipientScope": "other"}, headers=valid_headers
    )
    assert one.status_code == other.status_code == 201

    _, claims_one = _decrypt(one.text, priv_key)
    _, claims_other = _decrypt(other.text, priv_key)
    assert claims_one["subject"] != claims_other["subject"]


def test_requires_the_reversible_pseudonym_scope(
    client: TestClient,
    headers_with_scopes: Callable[..., dict[str, str]],
    sender: None,
    make_recipient: MakeRecipient,
) -> None:
    make_recipient()
    headers = headers_with_scopes(AuthorizationScope.PSEUDONYM, AuthorizationScope.OPRF)

    response = client.post(ENDPOINT, json=BODY, headers=headers)

    assert response.status_code == 403


def test_unregistered_caller_is_rejected(
    client: TestClient, valid_headers: dict[str, str], make_recipient: MakeRecipient
) -> None:
    make_recipient()

    response = client.post(ENDPOINT, json=BODY, headers=valid_headers)

    assert response.status_code == 401


def test_sender_without_provide_flag_is_refused_before_anything_else(
    client: TestClient,
    valid_headers: dict[str, str],
    org_service: OrgService,
    record_logs: RecordLogs,
) -> None:
    """The recipient is not even registered here: the sender check comes first,
    so the caller cannot use the 404 to probe which organizations exist."""
    org_service.create(
        SENDER_OIN, "Sender", RidUsage.Bsn, may_provide_personal_id=False
    )
    records = record_logs(LOGGER)

    response = client.post(ENDPOINT, json=BODY, headers=valid_headers)

    assert response.status_code == 403
    assert "not allowed to provide a personal ID" in response.json()["detail"]

    events = _events(records, "200402")
    assert len(events) == 1
    event = events[0]
    assert event.requested_operation == "exchange:reversible-pseudonym"  # type: ignore[attr-defined]
    assert event.namens_oin == str(SENDER_OIN)  # type: ignore[attr-defined]
    assert event.doel_oin == RECIPIENT  # type: ignore[attr-defined]


def test_sender_flag_is_read_from_the_verified_caller_not_the_acting_org(
    client: TestClient,
    valid_headers: dict[str, str],
    org_service: OrgService,
    make_recipient: MakeRecipient,
) -> None:
    make_recipient()
    org_service.create(
        SENDER_OIN, "Sender", RidUsage.Bsn, may_provide_personal_id=False
    )
    # x-gf-act-sub in valid_headers; having the flag here must not help.
    org_service.create(
        Oin("00000099000000001000"), "Actor", RidUsage.Bsn, may_provide_personal_id=True
    )

    response = client.post(ENDPOINT, json=BODY, headers=valid_headers)

    assert response.status_code == 403


def test_recipient_with_irreversible_usage_only_is_refused(
    client: TestClient,
    valid_headers: dict[str, str],
    sender: None,
    make_recipient: MakeRecipient,
    record_logs: RecordLogs,
) -> None:
    make_recipient(RidUsage.IrreversiblePseudonym)
    records = record_logs(LOGGER)

    response = client.post(ENDPOINT, json=BODY, headers=valid_headers)

    assert response.status_code == 403
    assert "not allowed to receive reversible pseudonyms" in response.json()["detail"]
    assert len(_events(records, "200402")) == 1
    assert _events(records, "220400") == []


def test_recipient_with_bsn_usage_is_allowed(
    client: TestClient,
    valid_headers: dict[str, str],
    sender: None,
    make_recipient: MakeRecipient,
) -> None:
    make_recipient(RidUsage.Bsn)

    response = client.post(ENDPOINT, json=BODY, headers=valid_headers)

    assert response.status_code == 201


def test_unknown_recipient_is_not_found(
    client: TestClient, valid_headers: dict[str, str], sender: None
) -> None:
    response = client.post(ENDPOINT, json=BODY, headers=valid_headers)

    assert response.status_code == 404
    assert response.json() == {
        "detail": f"Organization with OIN '{RECIPIENT_OIN}' not found"
    }


def test_recipient_without_public_key_for_scope_is_not_found(
    client: TestClient,
    valid_headers: dict[str, str],
    sender: None,
    make_recipient: MakeRecipient,
) -> None:
    make_recipient(with_key=False)

    response = client.post(ENDPOINT, json=BODY, headers=valid_headers)

    assert response.status_code == 404
    assert response.json() == {
        "detail": f"No public key found for organization '{RECIPIENT_OIN}' and scope '{SCOPE}'"
    }


@pytest.mark.parametrize(
    "personal_id",
    [
        "950000012",
        "NL:passport:950000012",
        "N:bsn:950000012",
        {"landCode": "NL", "value": BSN},
    ],
)
def test_malformed_personal_id_is_rejected_and_audited_without_the_value(
    client: TestClient,
    valid_headers: dict[str, str],
    sender: None,
    make_recipient: MakeRecipient,
    record_logs: RecordLogs,
    personal_id: Any,
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
    assert events[0].validation_error == "format"  # type: ignore[attr-defined]
    for record in records:
        assert BSN not in _dump(record)


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
