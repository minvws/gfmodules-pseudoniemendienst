import base64
import hashlib
import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests
from conftest import hsm_client
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from jwcrypto import jwk, jws

from app.config import ConfigJwtSigning
from app.services.hsm.client import HsmClient, HsmKeyNotFound
from app.services.jwt_signer import HsmJwtSigner, JwtSigningKeys, LocalJwtSigner


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


ISSUER = "https://prs.test"


def _config(**fields: Any) -> ConfigJwtSigning:
    return ConfigJwtSigning(issuer=ISSUER, **fields)


def test_from_config_uses_active_key_and_publishes_all(
    tmp_path: Path,
    rsa_key: rsa.RSAPrivateKey,
    other_rsa_key: rsa.RSAPrivateKey,
) -> None:
    old = _write_pem(tmp_path / "old.pem", rsa_key)
    new = _write_pem(tmp_path / "new.pem", other_rsa_key)

    keys = JwtSigningKeys.from_config(
        ConfigJwtSigning.model_validate(
            {"issuer": ISSUER, "key_files": f"{old}, {new}", "active_key_file": new}
        ),
        None,
    )

    assert keys.issuer == ISSUER
    assert keys.active.kid == LocalJwtSigner(other_rsa_key).kid
    assert [k["kid"] for k in keys.public_jwks()] == [
        LocalJwtSigner(rsa_key).kid,
        LocalJwtSigner(other_rsa_key).kid,
    ]


def test_from_config_requires_issuer() -> None:
    with pytest.raises(ValueError, match="issuer is not configured"):
        JwtSigningKeys.from_config(ConfigJwtSigning(), None)


def test_from_config_requires_a_key() -> None:
    with pytest.raises(ValueError, match="key_files or jwt_signing.hsm_key_labels"):
        JwtSigningKeys.from_config(_config(), None)


@pytest.mark.parametrize(
    "active", [{}, {"active_key_file": "a", "active_key_label": "b"}]
)
def test_from_config_requires_exactly_one_active_key(active: dict[str, str]) -> None:
    with pytest.raises(ValueError, match="exactly one of"):
        JwtSigningKeys.from_config(
            _config(key_files=["a"], hsm_key_labels=["b"], **active), None
        )


def test_from_config_requires_active_key_in_key_files(
    tmp_path: Path, rsa_key: rsa.RSAPrivateKey
) -> None:
    path = _write_pem(tmp_path / "key.pem", rsa_key)
    with pytest.raises(ValueError, match="active_key_file must be one of"):
        JwtSigningKeys.from_config(
            _config(key_files=[path], active_key_file="other.pem"), None
        )


def test_from_config_requires_active_label_in_hsm_key_labels() -> None:
    with pytest.raises(ValueError, match="active_key_label must be one of"):
        JwtSigningKeys.from_config(
            _config(hsm_key_labels=["a"], active_key_label="b"), None
        )


def test_from_config_hsm_labels_need_the_hsm() -> None:
    with pytest.raises(ValueError, match="needs the HSM"):
        JwtSigningKeys.from_config(
            _config(hsm_key_labels=["a"], active_key_label="a"), None
        )


def test_from_config_rejects_same_key_twice(
    tmp_path: Path, rsa_key: rsa.RSAPrivateKey
) -> None:
    first = _write_pem(tmp_path / "a.pem", rsa_key)
    second = _write_pem(tmp_path / "b.pem", rsa_key)
    with pytest.raises(ValueError, match="configured more than once"):
        JwtSigningKeys.from_config(
            _config(key_files=[first, second], active_key_file=first), None
        )


# --- HSM-backed signing, against a fake HSM API


class FakeRsaHsm:
    """Behaves like nl-rdo-hsm-api-service for the RSA calls the PRS makes:
    lookup returns the public key PEM, sign does RSA_PKCS_PSS over the given
    SHA-256 digest with MGF1-SHA256 and a 32 byte salt."""

    def __init__(self) -> None:
        self.keys: dict[str, rsa.RSAPrivateKey] = {}
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def post(
        self, method: str, url: str, json: dict[str, Any], **kwargs: Any
    ) -> MagicMock:
        path = url.split("/SoftHSMLabel", 1)[1]
        self.calls.append((path, json))
        resp = MagicMock()
        resp.status_code = 200
        key = self.keys.get(json["label"])
        if path == "":
            assert json["objtype"] == "PUBLIC_KEY"
            pem = (
                key.public_key()
                .public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                .decode("ascii")
                if key
                else None
            )
            resp.json.return_value = {
                "objects": [{"CLASS": "PUBLIC_KEY", "publickey": pem}] if pem else []
            }
        elif path == "/sign":
            if key is None:
                description = f"No such key: {json['label']!r}"
                resp.status_code = 422
                resp.raise_for_status.side_effect = requests.HTTPError(description)
                resp.json.return_value = {"error_description": description}
                return resp
            assert json["objtype"] == "PRIVATE_KEY"
            assert json["mechanism"] == "RSA_PKCS_PSS"
            assert json["hashmethod"] == "sha256"
            digest = base64.b64decode(json["data"])
            assert len(digest) == 32
            signature = key.sign(
                digest,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                Prehashed(hashes.SHA256()),
            )
            resp.json.return_value = {"result": base64.b64encode(signature).decode()}
        else:
            raise AssertionError(f"unexpected HSM call {path}")
        return resp


@pytest.fixture
def fake_hsm(rsa_key: rsa.RSAPrivateKey) -> FakeRsaHsm:
    fake = FakeRsaHsm()
    fake.keys["prs-jwt-1"] = rsa_key
    return fake


@pytest.fixture
def hsm(fake_hsm: FakeRsaHsm) -> Any:
    with patch("requests.Session.request", side_effect=fake_hsm.post):
        yield hsm_client()


def test_hsm_signer_signs_ps256(hsm: HsmClient, rsa_key: rsa.RSAPrivateKey) -> None:
    signer = HsmJwtSigner(hsm, "prs-jwt-1")
    signing_input = _b64url(b'{"alg":"PS256"}') + "." + _b64url(b'{"sub":"x"}')
    token = signing_input + "." + _b64url(signer.sign(signing_input.encode()))

    verifier = jws.JWS()
    verifier.deserialize(token)
    verifier.verify(jwk.JWK(**signer.public_jwk()), alg="PS256")
    assert signer.kid == LocalJwtSigner(rsa_key).kid
    assert signer.public_jwk() == LocalJwtSigner(rsa_key).public_jwk()


def test_hsm_signer_sends_only_the_digest(hsm: HsmClient, fake_hsm: FakeRsaHsm) -> None:
    HsmJwtSigner(hsm, "prs-jwt-1").sign(b"header.payload")

    path, body = fake_hsm.calls[-1]
    assert path == "/sign"
    assert base64.b64decode(body["data"]) == hashlib.sha256(b"header.payload").digest()


def test_hsm_signer_missing_label(hsm: HsmClient) -> None:
    with pytest.raises(HsmKeyNotFound):
        HsmJwtSigner(hsm, "prs-jwt-missing")


def test_hsm_signer_rejects_short_key(hsm: HsmClient, fake_hsm: FakeRsaHsm) -> None:
    fake_hsm.keys["short"] = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    with pytest.raises(ValueError, match="at least 3072 bits"):
        HsmJwtSigner(hsm, "short")


def test_from_config_publishes_file_and_hsm_keys_with_hsm_active(
    tmp_path: Path,
    hsm: HsmClient,
    other_rsa_key: rsa.RSAPrivateKey,
    rsa_key: rsa.RSAPrivateKey,
) -> None:
    old = _write_pem(tmp_path / "old.pem", other_rsa_key)

    keys = JwtSigningKeys.from_config(
        _config(
            key_files=[old],
            hsm_key_labels=["prs-jwt-1"],
            active_key_label="prs-jwt-1",
        ),
        hsm,
    )

    assert isinstance(keys.active, HsmJwtSigner)
    assert keys.active.kid == LocalJwtSigner(rsa_key).kid
    assert [k["kid"] for k in keys.public_jwks()] == [
        LocalJwtSigner(other_rsa_key).kid,
        LocalJwtSigner(rsa_key).kid,
    ]
