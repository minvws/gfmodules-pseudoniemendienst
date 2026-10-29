from collections.abc import Generator
from pathlib import Path

import inject
import pytest
from conftest import JWT_ISSUER, generate_rsa_keypair
from fastapi import FastAPI
from starlette.testclient import TestClient

from app.application import create_fastapi_app
from app.config import ConfigJwtSigning, get_config, set_config
from app.services.jwt_signer import JwtSigningKeys

ENDPOINT = "/.well-known/jwks"
PRIVATE_MEMBERS = {"d", "p", "q", "dp", "dq", "qi"}


def test_not_mounted_when_jwt_signing_is_disabled(client: TestClient) -> None:
    assert client.get(ENDPOINT).status_code == 404


def test_returns_the_signing_key_without_authentication(
    jwt_signing: JwtSigningKeys,
) -> None:
    client = TestClient(create_fastapi_app())

    response = client.get(ENDPOINT)

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert response.headers["cache-control"] == "public, max-age=900"
    keys = response.json()["keys"]
    assert len(keys) == 1
    key = keys[0]
    assert key["kid"] == jwt_signing.active.kid
    assert key["kty"] == "RSA"
    assert key["alg"] == "PS256"
    assert key["use"] == "sig"
    assert not PRIVATE_MEMBERS & key.keys()


@pytest.fixture
def rotated_signing(
    app: FastAPI, tmp_path: Path, jwt_signing_key_pem: str
) -> Generator[tuple[JwtSigningKeys, TestClient], None, None]:
    """Two signing keys configured, the newer one active."""
    from app.container import container_config
    from app.services.jwe_token import Jwe

    old = tmp_path / "old.pem"
    old.write_text(jwt_signing_key_pem)
    new = tmp_path / "new.pem"
    new.write_text(generate_rsa_keypair()[0])

    original = get_config()
    config = original.model_copy(deep=True)
    config.jwt_signing = ConfigJwtSigning(
        enabled=True,
        issuer=JWT_ISSUER,
        key_files=[str(old), str(new)],
        active_key_file=str(new),
    )
    set_config(config)
    try:
        inject.configure(container_config, clear=True)
        signing = inject.instance(Jwe).signing
        assert signing is not None
        yield signing, TestClient(create_fastapi_app())
    finally:
        set_config(original)


def test_lists_inactive_keys_next_to_the_active_one(
    rotated_signing: tuple[JwtSigningKeys, TestClient],
) -> None:
    signing, client = rotated_signing

    keys = client.get(ENDPOINT).json()["keys"]

    assert [key["kid"] for key in keys] == [signer.kid for signer in signing.signers]
    assert signing.active.kid == keys[1]["kid"]
    assert keys[0]["kid"] != keys[1]["kid"]
    for key in keys:
        assert key["use"] == "sig"
        assert not PRIVATE_MEMBERS & key.keys()
