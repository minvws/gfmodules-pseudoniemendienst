
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.container import get_jwt_signing_service


def test_get_jwks_should_return_200_when_signing_enabled(
    client: TestClient,
) -> None:
    """Happy flow: JWT signing enabled returns JWKS."""
    response = client.get("/.well-known/jwks")

    assert response.status_code == 200
    data = response.json()
    assert "keys" in data
    assert isinstance(data["keys"], list)


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


def test_get_jwks_should_have_cache_headers(
    client: TestClient,
) -> None:
    """Happy flow: Verify cache headers are set."""
    response = client.get("/.well-known/jwks")

    assert response.status_code == 200
    assert "Cache-Control" in response.headers
    assert "public, max-age=900" in response.headers["Cache-Control"]


def test_get_jwks_should_return_404_when_signing_disabled(
    app: FastAPI,
) -> None:
    """Unhappy flow: JWT signing disabled returns 404."""
    app.dependency_overrides[get_jwt_signing_service] = lambda: None
    client = TestClient(app)
    response = client.get("/.well-known/jwks")
    assert response.status_code == 404
