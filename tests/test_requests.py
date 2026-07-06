from typing import cast
from datetime import datetime, timedelta, timezone

from app.models.oin import Oin, RecipientOrganizationOin
from app.services.pseudonym_service import PseudonymType
from app.models.requests import (
    BlindRequest,
    HsmKeyVersionRequest,
    HsmKeyVersionUpdateRequest,
    ExchangeRequest,
    RegisterRequest,
    RidExchangeRequest,
)
from pydantic import ValidationError


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


def test_hsm_key_version_request_from_dt_must_not_be_in_the_past() -> None:
    past = datetime.now(timezone.utc) - timedelta(days=1)

    try:
        HsmKeyVersionRequest(from_dt=past)
        assert False, "Expected ValidationError when from_dt is in the past"
    except ValidationError as e:
        assert "from_dt" in str(e)
        assert "now" in str(e)


def test_hsm_key_version_request_until_dt_must_not_be_before_from_dt() -> None:
    from_dt = datetime.now(timezone.utc) + timedelta(days=1)
    until_dt = from_dt - timedelta(hours=1)

    try:
        HsmKeyVersionRequest(from_dt=from_dt, until_dt=until_dt)
        assert False, "Expected ValidationError when until_dt is before from_dt"
    except ValidationError as e:
        assert "until_dt" in str(e)
        assert "from_dt" in str(e)


def test_hsm_key_version_request_until_dt_with_no_from_dt_defaults_to_now() -> None:
    until_dt = datetime.now(timezone.utc) - timedelta(days=1)

    try:
        HsmKeyVersionRequest(until_dt=until_dt)
        assert False, (
            "Expected ValidationError when until_dt is before implicit now from_dt"
        )
    except ValidationError as e:
        assert "until_dt" in str(e)
        assert "from_dt" in str(e)


def test_hsm_key_version_request_rejects_naive_datetimes() -> None:
    naive_from_dt = (datetime.now(timezone.utc) + timedelta(days=1)).replace(
        tzinfo=None
    )

    try:
        HsmKeyVersionRequest(from_dt=naive_from_dt)
        assert False, "Expected ValidationError for naive from_dt"
    except ValidationError as e:
        assert "timezone" in str(e)


def test_hsm_key_version_update_request_rejects_naive_datetime() -> None:
    naive_until_dt = (datetime.now(timezone.utc) + timedelta(days=1)).replace(
        tzinfo=None
    )

    try:
        HsmKeyVersionUpdateRequest(until_dt=naive_until_dt)
        assert False, "Expected ValidationError for naive until_dt"
    except ValidationError as e:
        assert "timezone" in str(e)


def test_hsm_key_version_request_accepts_timezone_aware_dates() -> None:
    from_dt = datetime(
        2027,
        1,
        1,
        12,
        tzinfo=timezone(offset=timedelta(hours=2)),
    )
    until_dt = datetime(
        2027,
        1,
        2,
        12,
        tzinfo=timezone(offset=timedelta(hours=-4)),
    )

    request = HsmKeyVersionRequest(from_dt=from_dt, until_dt=until_dt)

    assert request.from_dt is not None
    assert request.until_dt is not None
    assert request.from_dt.tzinfo is not None
    assert request.until_dt.tzinfo is not None
    assert request.from_dt.astimezone(timezone.utc) == from_dt.astimezone(timezone.utc)
    assert request.until_dt.astimezone(timezone.utc) == until_dt.astimezone(
        timezone.utc
    )


def test_hsm_key_version_update_request_accepts_timezone_aware_dates() -> None:
    new_until_dt = datetime(
        2027,
        1,
        1,
        0,
        0,
        tzinfo=timezone(offset=timedelta(hours=5, minutes=30)),
    )
    request = HsmKeyVersionUpdateRequest(until_dt=new_until_dt)

    assert request.until_dt is not None
    assert request.until_dt.tzinfo is not None
    assert request.until_dt.utcoffset() == timedelta(hours=5, minutes=30)
