from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import ValidationError

from app.models.oin import Oin, RecipientOrganizationOin
from app.models.organization_public_key import OrganizationPublicKeyRequest
from app.models.requests import (
    BlindRequest,
    ExchangeRequest,
    HsmKeyVersionRequest,
    HsmKeyVersionUpdateRequest,
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
            recipientOrganization="not-a-valid-oin",  # type: ignore[arg-type]
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
            recipientOrganization="oin:00000099",  # type: ignore[arg-type]
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
            recipientOrganization="bad-oin",  # type: ignore[arg-type]
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
            recipientOrganization="bad-oin",  # type: ignore[arg-type]
            recipientScope="scope",
            pseudonymType=PseudonymType.Irreversible,
        )
        assert False, "Expected ValidationError for invalid organization OIN"
    except ValidationError as e:
        assert "Invalid recipient organization. Format: oin:<oin_number>" in str(e)


def test_register_request_with_key_id() -> None:
    request = OrganizationPublicKeyRequest(domains=["nvi"], jws="jw" * 16)

    assert request.domains == ["nvi"]
    assert request.jws == "jw" * 16


@pytest.mark.parametrize(
    "values,error_count",
    [
        ({}, 2),
        ({"domains": ["nvi"]}, 1),
        ({"jws": "jw" * 16}, 1),
    ],
)
def test_register_request_key_id_required_fields(
    values: dict[str, Any], error_count: int
) -> None:
    with pytest.raises(ValidationError) as e:
        OrganizationPublicKeyRequest(**values)
    assert e.value.error_count() == error_count


def test_hsm_key_version_request_from_dt_in_the_past_with_future_until_dt() -> None:
    from_dt = datetime.now(timezone.utc) - timedelta(days=1)
    until_dt = datetime.now(timezone.utc) + timedelta(days=1)

    request = HsmKeyVersionRequest(from_dt=from_dt, until_dt=until_dt)

    assert request.from_dt == from_dt
    assert request.until_dt == until_dt


def test_hsm_key_version_request_until_dt_must_not_equal_from_dt() -> None:
    from_dt = datetime.now(timezone.utc) + timedelta(days=1)

    try:
        HsmKeyVersionRequest(from_dt=from_dt, until_dt=from_dt)
        assert False, "Expected ValidationError when until_dt equals from_dt"
    except ValidationError as e:
        assert "until_dt" in str(e)
        assert "from_dt" in str(e)


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
        assert "now" in str(e)


def test_hsm_key_version_request_rejects_naive_datetimes() -> None:
    naive_from_dt = (datetime.now(timezone.utc) + timedelta(days=1)).replace(
        tzinfo=None
    )

    try:
        HsmKeyVersionRequest(from_dt=naive_from_dt)
        assert False, "Expected ValidationError for naive from_dt"
    except ValidationError as e:
        assert "timezone" in str(e)


def test_hsm_key_version_request_rejects_unknown_fields() -> None:
    try:
        HsmKeyVersionRequest(oin="00000099000000001000")  # type: ignore[call-arg]
        assert False, "Expected ValidationError for extra input fields"
    except ValidationError as e:
        assert "oin" in str(e)


def test_hsm_key_version_update_request_rejects_unknown_fields() -> None:
    try:
        HsmKeyVersionUpdateRequest(oin="00000099000000001000")  # type: ignore[call-arg]
        assert False, "Expected ValidationError for extra input fields"
    except ValidationError as e:
        assert "oin" in str(e)


def test_hsm_key_version_update_request_rejects_naive_datetime() -> None:
    naive_until_dt = (datetime.now(timezone.utc) + timedelta(days=1)).replace(
        tzinfo=None
    )

    try:
        HsmKeyVersionUpdateRequest(until_dt=naive_until_dt)
        assert False, "Expected ValidationError for naive until_dt"
    except ValidationError as e:
        assert "timezone" in str(e)


def test_hsm_key_version_update_request_until_dt_must_not_be_in_the_past() -> None:
    until_dt = datetime.now(timezone.utc) - timedelta(minutes=1)

    try:
        HsmKeyVersionUpdateRequest(until_dt=until_dt)
        assert False, "Expected ValidationError when until_dt is in the past"
    except ValidationError as e:
        assert "until_dt" in str(e)
        assert "now" in str(e)


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
