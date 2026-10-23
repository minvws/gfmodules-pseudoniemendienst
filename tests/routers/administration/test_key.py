from uuid import uuid4

import pytest
from starlette.testclient import TestClient

from app.db.models.organization import OrganizationEntity
from app.db.session import DbSession
from app.models.auth.data import AuthorizationScope
from app.models.oin import Oin
from tests.conftest import create_signed_jws, generate_rsa_keypair


def test_post_key_should_create_new_key(
    client: TestClient,
    persisted_organization: OrganizationEntity,
    db_session: DbSession,
    valid_headers: dict[str, str],
) -> None:
    # Generate RSA key pair
    private_key_pem, _ = generate_rsa_keypair()

    # Create signed JWS
    jws = create_signed_jws(private_key_pem, persisted_organization.external_id)

    # Create request body
    request_body = {
        "domains": ["test.example.com"],
        "jws": jws,
    }

    response = client.post(
        "/keys",
        json=request_body,
        headers=valid_headers,
    )

    assert response.status_code == 201
    data = response.json()
    assert "id" in data
    assert data["domains"] == ["test.example.com"]
    assert "jwk" in data

    # Verify it was actually created in the database
    db_session.session.refresh(persisted_organization)
    assert len(persisted_organization.public_keys) == 1


def test_post_key_should_return_403_when_unauthorized(
    client: TestClient,
) -> None:
    # Make request without auth headers
    response = client.post(
        "/keys",
        json={"domains": ["test.example.com"], "jws": "fake_jws"},
    )

    assert response.status_code == 403


@pytest.mark.parametrize(
    "request_body,_description",
    [
        ({"domains": ["example.com"]}, "missing jws"),
        ({"jws": "fake_jws"}, "missing domains"),
        ({"domains": [], "jws": "fake_jws"}, "empty domains"),
        ({"domains": ["example.com"], "jws": "short"}, "jws too short"),
    ],
)
def test_post_key_should_return_422_when_invalid_request_body(
    client: TestClient,
    valid_headers: dict[str, str],
    request_body: dict[str, str | list[str]],
    _description: str,
) -> None:
    response = client.post(
        "/keys",
        json=request_body,
        headers=valid_headers,
    )

    assert response.status_code == 422


def test_get_keys_should_return_keys_for_organization(
    client: TestClient,
    persisted_organization: OrganizationEntity,
    db_session: DbSession,
    valid_headers: dict[str, str],
) -> None:
    # Create a key for the organization
    private_key_pem, _ = generate_rsa_keypair()
    jws = create_signed_jws(private_key_pem, persisted_organization.external_id)

    # Register the key
    client.post(
        "/keys",
        json={"domains": ["test.example.com"], "jws": jws},
        headers=valid_headers,
    )

    # Get the keys
    response = client.get("/keys", headers=valid_headers)

    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["domains"] == ["test.example.com"]
    assert "jwk" in data[0]


def test_get_keys_should_return_403_when_unauthorized(
    client: TestClient,
) -> None:
    response = client.get("/keys")

    assert response.status_code == 403


def test_get_keys_should_return_empty_list_when_no_keys(
    client: TestClient,
    org_without_key_versions: OrganizationEntity,
    db_session: DbSession,
    valid_client_organization_id: Oin,
    valid_client_common_name: str,
    expected_audiences: list[str],
) -> None:
    db_session.add(org_without_key_versions)
    db_session.commit()

    # Create headers for this organization
    all_scopes = " ".join(scope.value for scope in AuthorizationScope)
    headers = {
        "x-gf-sub": org_without_key_versions.external_id.value,
        "x-gf-act-sub": valid_client_organization_id.value,
        "x-gf-act-cn": valid_client_common_name,
        "x-gf-audience": expected_audiences[0],
        "x-gf-scope": all_scopes,
    }

    response = client.get("/keys", headers=headers)

    assert response.status_code == 200
    data = response.json()
    assert data == []


def test_put_key_should_update_key(
    client: TestClient,
    persisted_organization: OrganizationEntity,
    db_session: DbSession,
    valid_headers: dict[str, str],
) -> None:
    # Create a key for the organization
    private_key_pem, _ = generate_rsa_keypair()
    jws = create_signed_jws(private_key_pem, persisted_organization.external_id)

    # Register the key
    create_response = client.post(
        "/keys",
        json={"domains": ["test.example.com"], "jws": jws},
        headers=valid_headers,
    )
    key_id = create_response.json()["id"]

    # Update the key with new domains
    new_private_key_pem, _ = generate_rsa_keypair()
    new_jws = create_signed_jws(new_private_key_pem, persisted_organization.external_id)

    response = client.put(
        f"/keys/{key_id}",
        json={"domains": ["updated.example.com"], "jws": new_jws},
        headers=valid_headers,
    )

    assert response.status_code == 200
    data = response.json()
    assert data["id"] == key_id
    assert data["domains"] == ["updated.example.com"]
    assert "jwk" in data


def test_put_key_should_return_403_when_unauthorized(
    client: TestClient,
) -> None:
    non_existent_id = uuid4()
    response = client.put(
        f"/keys/{non_existent_id}",
        json={"domains": ["test.example.com"], "jws": "fake_jws"},
    )

    assert response.status_code == 403


def test_put_key_should_return_404_when_not_found(
    client: TestClient,
    persisted_organization: OrganizationEntity,
    db_session: DbSession,
    valid_headers: dict[str, str],
) -> None:
    # Create a valid JWS for the organization
    private_key_pem, _ = generate_rsa_keypair()
    jws = create_signed_jws(private_key_pem, persisted_organization.external_id)

    # Use a non-existent key ID
    non_existent_id = uuid4()

    response = client.put(
        f"/keys/{non_existent_id}",
        json={"domains": ["test.example.com"], "jws": jws},
        headers=valid_headers,
    )

    assert response.status_code == 404


def test_delete_key_should_delete_key(
    client: TestClient,
    persisted_organization: OrganizationEntity,
    db_session: DbSession,
    valid_headers: dict[str, str],
) -> None:
    # Create a key for the organization
    private_key_pem, _ = generate_rsa_keypair()
    jws = create_signed_jws(private_key_pem, persisted_organization.external_id)

    # Register the key
    create_response = client.post(
        "/keys",
        json={"domains": ["test.example.com"], "jws": jws},
        headers=valid_headers,
    )
    key_id = create_response.json()["id"]

    # Delete the key
    response = client.delete(f"/keys/{key_id}", headers=valid_headers)

    assert response.status_code == 200
    assert response.json() == {"message": "key deleted"}

    # Verify it was actually deleted from the database
    db_session.session.refresh(persisted_organization)
    assert len(persisted_organization.public_keys) == 0


def test_delete_key_should_return_403_when_unauthorized(
    client: TestClient,
) -> None:
    non_existent_id = uuid4()
    response = client.delete(f"/keys/{non_existent_id}")

    assert response.status_code == 403


def test_delete_key_should_return_404_when_not_found(
    client: TestClient,
    persisted_organization: OrganizationEntity,
    db_session: DbSession,
    valid_headers: dict[str, str],
) -> None:
    # Use a non-existent key ID
    non_existent_id = uuid4()

    response = client.delete(f"/keys/{non_existent_id}", headers=valid_headers)

    assert response.status_code == 404


def test_put_key_should_return_422_when_invalid_request_body(
    client: TestClient,
    persisted_organization: OrganizationEntity,
    db_session: DbSession,
    valid_headers: dict[str, str],
) -> None:
    # Create a key for the organization
    private_key_pem, _ = generate_rsa_keypair()
    jws = create_signed_jws(private_key_pem, persisted_organization.external_id)

    # Register the key
    create_response = client.post(
        "/keys",
        json={"domains": ["test.example.com"], "jws": jws},
        headers=valid_headers,
    )
    key_id = create_response.json()["id"]

    # Try to update with invalid body (missing domains)
    response = client.put(
        f"/keys/{key_id}",
        json={"jws": jws},
        headers=valid_headers,
    )

    assert response.status_code == 422
