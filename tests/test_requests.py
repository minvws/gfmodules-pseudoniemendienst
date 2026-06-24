from app.models.requests import BlindRequest, RegisterRequest
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
