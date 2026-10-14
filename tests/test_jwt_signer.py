import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwcrypto import jwk, jws

from app.config import ConfigJwtSigning
from app.services.jwt_signer import JwtSigningKeys, LocalJwtSigner


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _write_pem(path: Path, key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey) -> str:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(path)


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


@pytest.fixture(scope="module")
def other_rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)


def test_signature_verifies_as_ps256(rsa_key: rsa.RSAPrivateKey) -> None:
    signer = LocalJwtSigner(rsa_key)
    header = {"alg": signer.alg, "kid": signer.kid, "typ": "JWT"}
    signing_input = _b64url(json.dumps(header).encode()) + "." + _b64url(b'{"sub":"x"}')
    token = signing_input + "." + _b64url(signer.sign(signing_input.encode()))

    verifier = jws.JWS()
    verifier.deserialize(token)
    verifier.verify(jwk.JWK(**signer.public_jwk()), alg="PS256")
    assert verifier.payload == b'{"sub":"x"}'


def test_kid_is_rfc7638_thumbprint(rsa_key: rsa.RSAPrivateKey) -> None:
    signer = LocalJwtSigner(rsa_key)
    expected = jwk.JWK.from_pyca(rsa_key.public_key()).thumbprint()
    assert signer.kid == expected
    assert LocalJwtSigner(rsa_key).kid == signer.kid


def test_public_jwk_has_no_private_members(rsa_key: rsa.RSAPrivateKey) -> None:
    public = LocalJwtSigner(rsa_key).public_jwk()
    assert public["kty"] == "RSA"
    assert public["alg"] == "PS256"
    assert public["use"] == "sig"
    assert not {"d", "p", "q", "dp", "dq", "qi"} & public.keys()


def test_rejects_key_shorter_than_3072_bits() -> None:
    short = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(ValueError, match="at least 3072 bits"):
        LocalJwtSigner(short)


def test_rejects_non_rsa_key_file(tmp_path: Path) -> None:
    path = _write_pem(tmp_path / "ec.pem", ec.generate_private_key(ec.SECP256R1()))
    with pytest.raises(TypeError, match="not an RSA private key"):
        LocalJwtSigner.from_pem_file(path)


def test_rejects_missing_key_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="not found"):
        LocalJwtSigner.from_pem_file(str(tmp_path / "missing.pem"))


def test_from_config_uses_active_key_and_publishes_all(
    tmp_path: Path,
    rsa_key: rsa.RSAPrivateKey,
    other_rsa_key: rsa.RSAPrivateKey,
) -> None:
    old = _write_pem(tmp_path / "old.pem", rsa_key)
    new = _write_pem(tmp_path / "new.pem", other_rsa_key)

    keys = JwtSigningKeys.from_config(
        ConfigJwtSigning.model_validate(
            {"key_files": f"{old}, {new}", "active_key_file": new}
        )
    )

    assert keys.active.kid == LocalJwtSigner(other_rsa_key).kid
    assert [k["kid"] for k in keys.public_jwks()] == [
        LocalJwtSigner(rsa_key).kid,
        LocalJwtSigner(other_rsa_key).kid,
    ]


def test_from_config_requires_key_files() -> None:
    with pytest.raises(ValueError, match="key_files is not configured"):
        JwtSigningKeys.from_config(ConfigJwtSigning())


def test_from_config_requires_active_key_in_key_files(
    tmp_path: Path, rsa_key: rsa.RSAPrivateKey
) -> None:
    path = _write_pem(tmp_path / "key.pem", rsa_key)
    with pytest.raises(ValueError, match="active_key_file must be one of"):
        JwtSigningKeys.from_config(
            ConfigJwtSigning(key_files=[path], active_key_file="other.pem")
        )


def test_from_config_rejects_same_key_twice(
    tmp_path: Path, rsa_key: rsa.RSAPrivateKey
) -> None:
    first = _write_pem(tmp_path / "a.pem", rsa_key)
    second = _write_pem(tmp_path / "b.pem", rsa_key)
    with pytest.raises(ValueError, match="configured more than once"):
        JwtSigningKeys.from_config(
            ConfigJwtSigning(key_files=[first, second], active_key_file=first)
        )
