from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.container import get_jwt_signing_service
from app.services.jwt_signer import JwtSigningService, LocalJwtSigner
from tests.conftest import generate_rsa_keypair


def test_get_jwks_should_return_200_when_signing_enabled(
    client: TestClient,
) -> None:
    """Happy flow: JWT signing enabled returns JWKS."""
    response = client.get("/.well-known/jwks")

    assert response.status_code == 200
    data = response.json()
    assert "keys" in data
    assert isinstance(data["keys"], list)


def test_get_jwks_should_have_content_type_header(
    client: TestClient,
) -> None:
    """Happy flow: Verify Content-Type header is set."""
    response = client.get("/.well-known/jwks")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"


def test_get_jwks_should_have_cache_headers(
    client: TestClient,
) -> None:
    """Happy flow: Verify cache headers are set."""
    response = client.get("/.well-known/jwks")

    assert response.status_code == 200
    assert "Cache-Control" in response.headers
    assert "public, max-age=900" in response.headers["Cache-Control"]


def test_get_jwks_should_return_correct_jwks(
    client: TestClient,
) -> None:
    """Happy flow: Verify JWKS contains expected keys."""
    response = client.get("/.well-known/jwks")

    assert response.status_code == 200
    data = response.json()
    keys = data["keys"]
    assert len(keys) == 1  # Our fixture has one signer
    assert keys[0]["kty"] == "RSA"
    assert keys[0]["use"] == "sig"
    assert keys[0]["alg"] == "PS256"


def test_get_jwks_should_not_expose_private_key_members(
    client: TestClient,
) -> None:
    """Happy flow: Verify JWKS doesn't expose private key components."""
    response = client.get("/.well-known/jwks")
    assert response.status_code == 200
    keys = response.json()["keys"]
    for key in keys:
        private_members = {"d", "p", "q", "dp", "dq", "qi"}
        assert not private_members & key.keys()


def test_get_jwks_should_list_all_keys_including_inactive(
    client: TestClient,
    app: FastAPI,
) -> None:
    """Happy flow: JWKS endpoint lists all keys, not just the active one."""

    # Create two signers
    private_key_1_pem, _ = generate_rsa_keypair()
    private_key_2_pem, _ = generate_rsa_keypair()

    private_key_1 = load_pem_private_key(
        private_key_1_pem.encode("ascii"), password=None
    )
    private_key_2 = load_pem_private_key(
        private_key_2_pem.encode("ascii"), password=None
    )

    assert isinstance(private_key_1, RSAPrivateKey)
    signer_1 = LocalJwtSigner(private_key_1, "key-1")
    assert isinstance(private_key_2, RSAPrivateKey)
    signer_2 = LocalJwtSigner(private_key_2, "key-2")

    # Create service with key-2 as active
    service = JwtSigningService(
        issuer="test-issuer", active=signer_2, signers=(signer_1, signer_2)
    )

    # Override the dependency for this test
    app.dependency_overrides[get_jwt_signing_service] = lambda: service

    try:
        response = client.get("/.well-known/jwks")
        assert response.status_code == 200

        keys = response.json()["keys"]
        assert len(keys) == 2  # Both keys should be present

        kids = {key["kid"] for key in keys}
        assert signer_1.kid in kids
        assert signer_2.kid in kids
    finally:
        app.dependency_overrides.pop(get_jwt_signing_service, None)


def test_get_jwks_should_return_404_when_signing_disabled(
    app: FastAPI,
) -> None:
    """Unhappy flow: JWT signing disabled returns 404."""
    app.dependency_overrides[get_jwt_signing_service] = lambda: None
    client = TestClient(app)
    response = client.get("/.well-known/jwks")
    assert response.status_code == 404
