import json

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwcrypto import jwe, jwk, jws

from app.services.jwe_token import Jwe
from app.services.jwt_signer import JwtSigningKeys, LocalJwtSigner

ISSUER = "https://prs.test"


@pytest.fixture(scope="module")
def recipient_key() -> jwk.JWK:
    return jwk.JWK.generate(kty="RSA", size=3072, kid="recipient")


@pytest.fixture(scope="module")
def signing() -> JwtSigningKeys:
    signer = LocalJwtSigner(
        rsa.generate_private_key(public_exponent=65537, key_size=3072)
    )
    return JwtSigningKeys(issuer=ISSUER, active=signer, signers=(signer,))


def _build(builder: Jwe, recipient_key: jwk.JWK) -> str:
    return builder.build(
        audience="oin:00000099000000003000",
        scope="nvi",
        subject="pseudonym:reversible:abc",
        pub_key=recipient_key,
        extra_claims={"keyVersion": 1},
    )


def _decrypt(token: str, recipient_key: jwk.JWK) -> jwe.JWE:
    outer = jwe.JWE()
    outer.deserialize(token)
    outer.decrypt(recipient_key)
    return outer


def test_without_signing_the_content_is_plain_json(recipient_key: jwk.JWK) -> None:
    outer = _decrypt(_build(Jwe(), recipient_key), recipient_key)

    assert outer.jose_header["cty"] == "application/json"
    claims = json.loads(outer.payload)
    assert claims["subject"] == "pseudonym:reversible:abc"
    assert "iss" not in claims


def test_with_signing_the_content_is_a_signed_jwt(
    recipient_key: jwk.JWK, signing: JwtSigningKeys
) -> None:
    outer = _decrypt(_build(Jwe(signing), recipient_key), recipient_key)

    assert outer.jose_header["cty"] == "JWT"
    assert outer.jose_header["kid"] == "recipient"

    inner = jws.JWS()
    inner.deserialize(outer.payload.decode("ascii"))
    inner.verify(jwk.JWK(**signing.active.public_jwk()), alg="PS256")
    assert inner.jose_header == {
        "alg": "PS256",
        "kid": signing.active.kid,
        "typ": "JWT",
    }

    claims = json.loads(inner.payload)
    assert claims["iss"] == ISSUER
    assert claims["subject"] == "pseudonym:reversible:abc"
    assert claims["aud"] == "oin:00000099000000003000"
    assert claims["scope"] == "nvi"
    assert claims["keyVersion"] == 1
    assert claims["exp"] - claims["iat"] == 300


def test_signature_does_not_verify_with_another_key(
    recipient_key: jwk.JWK, signing: JwtSigningKeys
) -> None:
    outer = _decrypt(_build(Jwe(signing), recipient_key), recipient_key)
    other = jwk.JWK.generate(kty="RSA", size=3072)

    inner = jws.JWS()
    inner.deserialize(outer.payload.decode("ascii"))
    other_public = jwk.JWK(**other.export_public(as_dict=True))
    with pytest.raises(jws.InvalidJWSSignature):
        inner.verify(other_public, alg="PS256")


def test_extra_claims_cannot_override_the_issuer(
    recipient_key: jwk.JWK, signing: JwtSigningKeys
) -> None:
    token = Jwe(signing).build(
        audience="oin:00000099000000003000",
        scope="nvi",
        subject="pseudonym:reversible:abc",
        pub_key=recipient_key,
        extra_claims={"iss": "https://attacker.test"},
    )
    outer = _decrypt(token, recipient_key)

    inner = jws.JWS()
    inner.deserialize(outer.payload.decode("ascii"))
    inner.verify(jwk.JWK(**signing.active.public_jwk()), alg="PS256")
    assert json.loads(inner.payload)["iss"] == ISSUER
