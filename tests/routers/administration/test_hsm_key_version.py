from datetime import timedelta
from uuid import uuid4

import pytest
from starlette.testclient import TestClient

from app.db.models.organization import OrganizationEntity
from app.db.session import DbSession
from app.models.auth.data import AuthorizationScope
from app.models.oin import Oin
from app.utils.datetime import now_utc


def test_post_key_version_should_create_new_version(
    client: TestClient,
    persisted_organization: OrganizationEntity,
    db_session: DbSession,
    valid_headers: dict[str, str],
) -> None:
    # Count versions before
    initial_count = len(persisted_organization.hsm_key_versions)

    # Create request body with valid ISO-8601 datetime with timezone
    request_body = {
        "from_dt": now_utc().isoformat(),
        "until_dt": (now_utc() + timedelta(days=365)).isoformat(),
    }

    # Make request with auth headers
    response = client.post(
        "/key-versions",
        json=request_body,
        headers=valid_headers,
    )

    # Verify response
    assert response.status_code == 201
    data = response.json()
    assert "id" in data
    assert "version" in data
    assert data["version"] == initial_count + 1

    # Verify it was actually created in the database
    db_session.session.refresh(persisted_organization)
    assert len(persisted_organization.hsm_key_versions) == initial_count + 1


@pytest.mark.parametrize(
    "headers,_description",
    [
        ({}, "no auth headers"),
        ({"x-gf-sub": "00000099000000002000"}, "missing required headers"),
        (
            {"x-gf-sub": "00000099000000002000", "x-gf-audience": "wrong-audience"},
            "invalid audience",
        ),
    ],
)
def test_post_key_version_should_return_403_when_unauthorized(
    client: TestClient,
    headers: dict[str, str],
    _description: str,
) -> None:
    response = client.post("/key-versions", json={}, headers=headers)

    assert response.status_code == 403


@pytest.mark.parametrize(
    "request_body,_description",
    [
        ({"from_dt": "2026-01-01T00:00:00"}, "missing timezone in from_dt"),
        ({"until_dt": "2026-01-01T00:00:00"}, "missing timezone in until_dt"),
        (
            {"from_dt": "2026-01-01T00:00:00Z", "until_dt": "2020-01-01T00:00:00Z"},
            "until_dt in the past",
        ),
        (
            {"from_dt": "2026-01-01T00:00:00Z", "until_dt": "2025-01-01T00:00:00Z"},
            "until_dt before from_dt",
        ),
    ],
)
def test_post_key_version_should_return_422_when_invalid_request_body(
    client: TestClient,
    valid_headers: dict[str, str],
    request_body: dict[str, str],
    _description: str,
) -> None:
    response = client.post(
        "/key-versions",
        json=request_body,
        headers=valid_headers,
    )

    assert response.status_code == 422


def test_post_key_version_should_return_409_when_no_key_version_exists(
    client: TestClient,
    db_session: DbSession,
    org_without_key_versions: OrganizationEntity,
    valid_client_organization_id: Oin,
    valid_client_common_name: str,
    expected_audiences: list[str],
) -> None:
    db_session.add(org_without_key_versions)
    db_session.commit()

    # Create headers for this specific organization using fixture values
    all_scopes = " ".join(scope.value for scope in AuthorizationScope)
    headers = {
        "x-gf-sub": org_without_key_versions.external_id.value,
        "x-gf-act-sub": valid_client_organization_id.value,
        "x-gf-act-cn": valid_client_common_name,
        "x-gf-audience": expected_audiences[0],
        "x-gf-scope": all_scopes,
    }

    # Try to create a new version for this organization
    response = client.post(
        "/key-versions",
        json={
            "from_dt": now_utc().isoformat(),
            "until_dt": (now_utc() + timedelta(days=365)).isoformat(),
        },
        headers=headers,
    )

    assert response.status_code == 409


def test_get_key_versions_should_return_versions_for_organization(
    client: TestClient,
    persisted_organization: OrganizationEntity,
    db_session: DbSession,
    valid_headers: dict[str, str],
) -> None:
    response = client.get(
        "/key-versions",
        headers=valid_headers,
    )

    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == len(persisted_organization.hsm_key_versions)

    # Verify the first version's data
    assert data[0]["id"] == str(persisted_organization.hsm_key_versions[0].id)
    assert data[0]["version"] == persisted_organization.hsm_key_versions[0].version


def test_get_key_versions_should_return_403_when_unauthorized(
    client: TestClient,
) -> None:
    response = client.get("/key-versions")

    assert response.status_code == 403


def test_get_key_versions_should_return_empty_list_when_no_versions(
    client: TestClient,
    db_session: DbSession,
    org_without_key_versions: OrganizationEntity,
    valid_client_organization_id: Oin,
    valid_client_common_name: str,
    expected_audiences: list[str],
) -> None:
    db_session.add(org_without_key_versions)
    db_session.commit()

    # Create headers for this specific organization
    all_scopes = " ".join(scope.value for scope in AuthorizationScope)
    headers = {
        "x-gf-sub": org_without_key_versions.external_id.value,
        "x-gf-act-sub": valid_client_organization_id.value,
        "x-gf-act-cn": valid_client_common_name,
        "x-gf-audience": expected_audiences[0],
        "x-gf-scope": all_scopes,
    }

    response = client.get("/key-versions", headers=headers)

    assert response.status_code == 200
    data = response.json()
    assert data == []


def test_put_key_version_should_update_version(
    client: TestClient,
    persisted_organization: OrganizationEntity,
    db_session: DbSession,
    valid_headers: dict[str, str],
) -> None:
    # Get the existing version
    version = persisted_organization.hsm_key_versions[0]
    original_until_dt = version.until_dt

    # Update with a new until_dt
    new_until_dt = (now_utc() + timedelta(days=730)).isoformat()

    response = client.put(
        f"/key-versions/{version.id}",
        json={"until_dt": new_until_dt},
        headers=valid_headers,
    )

    assert response.status_code == 200
    data = response.json()
    assert data["id"] == str(version.id)
    assert data["until_dt"] == new_until_dt

    # Verify it was actually updated in the database
    db_session.session.refresh(version)
    assert version.until_dt is not None
    assert version.until_dt.isoformat() == new_until_dt
    assert original_until_dt != new_until_dt


def test_put_key_version_should_return_403_when_unauthorized(
    client: TestClient,
) -> None:
    non_existent_id = uuid4()
    response = client.put(
        f"/key-versions/{non_existent_id}", json={"until_dt": "2027-01-01T00:00:00Z"}
    )

    assert response.status_code == 403


def test_put_key_version_should_return_403_when_not_found(
    client: TestClient,
    db_session: DbSession,
    valid_headers: dict[str, str],
) -> None:

    non_existent_id = uuid4()
    response = client.put(
        f"/key-versions/{non_existent_id}",
        json={"until_dt": "2027-01-01T00:00:00Z"},
        headers=valid_headers,
    )

    assert response.status_code == 403


def test_put_key_version_should_return_422_when_invalid_request_body(
    client: TestClient,
    persisted_organization: OrganizationEntity,
    db_session: DbSession,
    valid_headers: dict[str, str],
) -> None:
    version = persisted_organization.hsm_key_versions[0]
    # Missing timezone
    response = client.put(
        f"/key-versions/{version.id}",
        json={"until_dt": "2027-01-01T00:00:00"},
        headers=valid_headers,
    )

    assert response.status_code == 422
