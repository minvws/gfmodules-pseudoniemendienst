from app.models.requests import BlindRequest
from pydantic import ValidationError


def test_blind_request_encrypted_personal_id_is_normalized() -> None:
    request = BlindRequest(
        encryptedPersonalId="YQ",
        recipientOrganization="ura:12345678",
        recipientScope="nvi",
    )

    assert request.encryptedPersonalId == "YQ=="


def test_blind_request_encrypted_personal_id_invalid_base64url() -> None:
    try:
        BlindRequest(
            encryptedPersonalId="a?",
            recipientOrganization="ura:12345678",
            recipientScope="nvi",
        )
        assert False, "Expected ValidationError for invalid base64url"
    except ValidationError as e:
        assert "must be base64url" in str(e)
