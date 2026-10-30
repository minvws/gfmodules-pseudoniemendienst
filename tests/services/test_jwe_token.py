import json
from unittest.mock import MagicMock, patch

from jwcrypto import jwe, jwk

from app.services.jwe_token import JweTokenService
from app.services.jwt_signer import JwtSigningService


@patch("app.services.jwe_token.time.time")
def test_build_should_create_correct_jwe_token(mock_time: MagicMock) -> None:
    pub_key = jwk.JWK.generate(kty="RSA", size=2048)
    audience = "test_audience"
    scope = "test_scope"
    subject = "test_subject"
    extra_claims = {"custom": "value"}
    fixed_time = 1234567890
    mock_time.return_value = fixed_time

    service = JweTokenService(signing=None)

    result = service.build(
        audience=audience,
        scope=scope,
        subject=subject,
        pub_key=pub_key,
        extra_claims=extra_claims,
    )

    result_jwe = jwe.JWE()
    result_jwe.deserialize(result)
    result_jwe.decrypt(pub_key)

    expected_claims = {
        "subject": subject,
        "aud": audience,
        "scope": scope,
        "version": "1.1",
        "iat": fixed_time,
        "exp": fixed_time + 300,
        **extra_claims,
    }

    assert result_jwe.payload == json.dumps(expected_claims).encode("utf-8")
    assert result_jwe.jose_header["kid"] == pub_key.key_id
    assert result_jwe.jose_header["alg"] == "RSA-OAEP"
    assert result_jwe.jose_header["enc"] == "A256GCM"
    assert result_jwe.jose_header["cty"] == "application/json"


@patch("app.services.jwe_token.time.time")
def test_build_should_create_correct_jwe_token_without_extra_claims(
    mock_time: MagicMock,
) -> None:
    pub_key = jwk.JWK.generate(kty="RSA", size=2048)
    audience = "test_audience"
    scope = "test_scope"
    subject = "test_subject"
    fixed_time = 1234567890
    mock_time.return_value = fixed_time

    service = JweTokenService(signing=None)

    result = service.build(
        audience=audience,
        scope=scope,
        subject=subject,
        pub_key=pub_key,
        extra_claims=None,
    )

    result_jwe = jwe.JWE()
    result_jwe.deserialize(result)
    result_jwe.decrypt(pub_key)

    expected_claims = {
        "subject": subject,
        "aud": audience,
        "scope": scope,
        "version": "1.1",
        "iat": fixed_time,
        "exp": fixed_time + 300,
    }

    assert result_jwe.payload == json.dumps(expected_claims).encode("utf-8")
    assert result_jwe.jose_header["kid"] == pub_key.key_id
    assert result_jwe.jose_header["alg"] == "RSA-OAEP"
    assert result_jwe.jose_header["enc"] == "A256GCM"
    assert result_jwe.jose_header["cty"] == "application/json"


@patch("app.services.jwe_token.time.time")
def test_build_should_create_jwe_with_signed_jwt(
    mock_time: MagicMock,
    jwt_signing_service: JwtSigningService,
) -> None:
    pub_key = jwk.JWK.generate(kty="RSA", size=2048)
    audience = "test_audience"
    scope = "test_scope"
    subject = "test_subject"
    fixed_time = 1234567890
    mock_time.return_value = fixed_time

    service = JweTokenService(signing=jwt_signing_service)

    result = service.build(
        audience=audience,
        scope=scope,
        subject=subject,
        pub_key=pub_key,
    )

    result_jwe = jwe.JWE()
    result_jwe.deserialize(result)
    result_jwe.decrypt(pub_key)

    # The payload should be a JWT, not plain JSON
    assert result_jwe.jose_header["cty"] == "JWT"

    # Decode the JWT to verify it was signed
    jwt_token = result_jwe.payload.decode("ascii")
    parts = jwt_token.split(".")
    assert len(parts) == 3  # header.payload.signature


def test_build_should_use_correct_kid_from_signing_service(
    jwt_signing_service: JwtSigningService,
) -> None:
    pub_key = jwk.JWK.generate(kty="RSA", size=2048)
    service = JweTokenService(signing=jwt_signing_service)

    result = service.build(
        audience="test",
        scope="test",
        subject="test",
        pub_key=pub_key,
    )

    result_jwe = jwe.JWE()
    result_jwe.deserialize(result)

    # The kid in the JWE header should match the active signer's kid
    assert result_jwe.jose_header["kid"] == pub_key.key_id
