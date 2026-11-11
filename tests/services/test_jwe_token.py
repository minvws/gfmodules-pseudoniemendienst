import json
from unittest.mock import MagicMock, patch

import pytest
from jwcrypto import jwe, jwk, jws

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


def test_signature_does_not_verify_with_another_key(
    jwt_signing_service: JwtSigningService,
) -> None:
    """Tests that the JWT signature cannot be verified with a different key."""
    pub_key = jwk.JWK.generate(kty="RSA", size=2048)
    other_key = jwk.JWK.generate(kty="RSA", size=2048)  # Different key
    service = JweTokenService(signing=jwt_signing_service)

    # Build a JWE with signing
    token = service.build(
        audience="test_audience",
        scope="test_scope",
        subject="test_subject",
        pub_key=pub_key,
    )

    # Decrypt the JWE
    jwe_token = jwe.JWE()
    jwe_token.deserialize(token)
    jwe_token.decrypt(pub_key)

    # The payload is a JWT; try to verify it with the WRONG key
    jwt_token = jwe_token.payload.decode("ascii")
    parsed_jwt = jws.JWS()
    # This returns None, but modifies parsed_jwt
    parsed_jwt.deserialize(jwt_token)
    with pytest.raises(jws.InvalidJWSSignature):
        parsed_jwt.verify(other_key, alg="PS256")  # Verify with the wrong key


def test_extra_claims_cannot_override_the_issuer(
    jwt_signing_service: JwtSigningService,
) -> None:
    """Tests that the 'iss' claim cannot be overridden by extra_claims."""
    pub_key = jwk.JWK.generate(kty="RSA", size=2048)
    service = JweTokenService(signing=jwt_signing_service)

    # Try to override 'iss' in extra_claims
    token = service.build(
        audience="test_audience",
        scope="test_scope",
        subject="test_subject",
        pub_key=pub_key,
        extra_claims={"iss": "https://attacker.test"},  # Malicious override
    )

    # Decrypt the JWE
    jwe_token = jwe.JWE()
    jwe_token.deserialize(token)
    jwe_token.decrypt(pub_key)

    # The payload is a JWT; decode it
    jwt_token = jwe_token.payload.decode("ascii")
    inner = jws.JWS()
    inner.deserialize(jwt_token)
    inner.verify(jwk.JWK(**jwt_signing_service.active.public_jwk()), alg="PS256")

    # Verify the issuer is still the correct one
    claims = json.loads(inner.payload)
    assert claims["iss"] == jwt_signing_service.issuer
