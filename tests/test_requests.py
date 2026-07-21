from typing import cast

from pydantic import ValidationError

from app.models.oin import Oin, RecipientOrganizationOin
from app.models.requests import (
    BlindRequest,
    ExchangeRequest,
    RegisterRequest,
    RidExchangeRequest,
)
from app.services.pseudonym_service import PseudonymType


def test_blind_request_encrypted_personal_id_is_normalized() -> None:
    request = BlindRequest(
        encryptedPersonalId="YQ",
        recipientOrganization=RecipientOrganizationOin("oin:00000099000000001000"),
        recipientScope="nvi",
    )

    assert request.encryptedPersonalId == "YQ=="


def test_blind_request_encrypted_personal_id_invalid_base64url() -> None:
    try:
        BlindRequest(
            encryptedPersonalId="a?",
            recipientOrganization=RecipientOrganizationOin("oin:00000099000000001000"),
            recipientScope="nvi",
        )
        assert False, "Expected ValidationError for invalid base64url"
    except ValidationError as e:
        assert "must be base64url" in str(e)


def test_blind_request_invalid_recipient_organization_throws_validation_error() -> None:
    try:
        BlindRequest(
            encryptedPersonalId="YQ",
            recipientOrganization=cast(RecipientOrganizationOin, "not-a-valid-oin"),
            recipientScope="nvi",
        )
        assert False, "Expected ValidationError for invalid organization OIN"
    except ValidationError as e:
        assert "Invalid recipient organization. Format: oin:<oin_number>" in str(e)


def test_blind_request_invalid_prefixed_recipient_organization_throws_oin_validation_error() -> (
    None
):
    try:
        BlindRequest(
            encryptedPersonalId="YQ",
            recipientOrganization=cast(RecipientOrganizationOin, "oin:00000099"),
            recipientScope="nvi",
        )
        assert False, "Expected ValidationError for invalid organization OIN"
    except ValidationError as e:
        assert "Invalid OIN '00000099'." in str(e)


def test_rid_exchange_request_recipient_organization_is_parsed_to_oin() -> None:
    request = RidExchangeRequest(
        personalId={"landCode": "NL", "type": "bsn", "value": "9500009012"},
        recipientOrganization=RecipientOrganizationOin("oin:00000099000000002000"),
        recipientScope="scope",
        ridUsage="irp",
    )

    assert request.recipientOrganization == Oin("00000099000000002000")


def test_rid_exchange_request_invalid_recipient_organization_throws_validation_error() -> (
    None
):
    try:
        RidExchangeRequest(
            personalId={"landCode": "NL", "type": "bsn", "value": "9500009012"},
            recipientOrganization=cast(RecipientOrganizationOin, "bad-oin"),
            recipientScope="scope",
            ridUsage="irp",
        )
        assert False, "Expected ValidationError for invalid organization OIN"
    except ValidationError as e:
        assert "Invalid recipient organization. Format: oin:<oin_number>" in str(e)


def test_exchange_request_recipient_organization_is_parsed_to_oin() -> None:
    request = ExchangeRequest(
        personalId={"landCode": "NL", "type": "bsn", "value": "9500009012"},
        recipientOrganization=RecipientOrganizationOin("oin:00000099000000003000"),
        recipientScope="scope",
        pseudonymType=PseudonymType.Irreversible,
    )

    assert request.recipientOrganization == Oin("00000099000000003000")


def test_exchange_request_invalid_recipient_organization_throws_validation_error() -> (
    None
):
    try:
        ExchangeRequest(
            personalId={"landCode": "NL", "type": "bsn", "value": "9500009012"},
            recipientOrganization=cast(RecipientOrganizationOin, "bad-oin"),
            recipientScope="scope",
            pseudonymType=PseudonymType.Irreversible,
        )
        assert False, "Expected ValidationError for invalid organization OIN"
    except ValidationError as e:
        assert "Invalid recipient organization. Format: oin:<oin_number>" in str(e)


def test_register_request_with_key_id() -> None:
    request = RegisterRequest(scope=["nvi"], key_id="kid-2024")

    assert request.scope == ["nvi"]
    assert request.key_id == "kid-2024"


def test_register_request_key_id_may_be_none() -> None:
    request = RegisterRequest(scope=["nvi"], key_id=None)

    assert request.key_id is None


def test_register_request_key_id_is_required() -> None:
    try:
        RegisterRequest(scope=["nvi"])  # type: ignore[call-arg]
        assert False, "Expected ValidationError when key_id is missing"
    except ValidationError as e:
        assert "key_id" in str(e)
