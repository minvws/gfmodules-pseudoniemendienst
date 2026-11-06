import pytest
from pydantic import ValidationError

from app.models.oin import Oin, RecipientOrganizationOin
from app.models.requests.oprf import BlindRequest


def test_blind_request_should_validate_with_valid_base64(
    valid_organization_id: Oin,
) -> None:
    # Valid base64url encoded string - will be normalized with padding
    request = BlindRequest(
        encryptedPersonalId="SGVsbG8gV29ybGQ",  # "Hello World" in base64
        recipientOrganization=RecipientOrganizationOin(valid_organization_id),
        recipientScope="test",
    )
    # The validator adds padding
    assert request.encryptedPersonalId == "SGVsbG8gV29ybGQ="
    assert request.recipientOrganization.value == valid_organization_id.value
    assert request.recipientScope == "test"


def test_blind_request_should_validate_with_base64_without_padding(
    valid_organization_id: Oin,
) -> None:
    # Base64 without padding - should be normalized
    request = BlindRequest(
        encryptedPersonalId="SGVsbG8gV29ybG",  # Missing padding
        recipientOrganization=RecipientOrganizationOin(valid_organization_id),
        recipientScope="test",
    )
    # Should be normalized with padding
    assert request.encryptedPersonalId == "SGVsbG8gV29ybG=="


def test_blind_request_should_raise_when_invalid_base64(
    valid_organization_id: Oin,
) -> None:
    # Use a string with a character not in base64url alphabet
    with pytest.raises(ValidationError, match="must be base64url"):
        BlindRequest(
            encryptedPersonalId="SGVsbG8gV29ybGQ$",  # $ is not in base64url
            recipientOrganization=RecipientOrganizationOin(valid_organization_id),
            recipientScope="test",
        )


def test_blind_request_should_raise_when_encrypted_personal_id_too_short(
    valid_organization_id: Oin,
) -> None:
    with pytest.raises(ValidationError, match="at least 2 characters"):
        BlindRequest(
            encryptedPersonalId="a",  # Only 1 character
            recipientOrganization=RecipientOrganizationOin(valid_organization_id),
            recipientScope="test",
        )


def test_blind_request_should_raise_when_recipient_scope_too_short(
    valid_organization_id: Oin,
) -> None:
    with pytest.raises(ValidationError, match="at least 2 characters"):
        BlindRequest(
            encryptedPersonalId="SGVsbG8=",
            recipientOrganization=RecipientOrganizationOin(valid_organization_id),
            recipientScope="a",  # Only 1 character
        )
