import uuid
from datetime import datetime, timedelta, timezone

from starlette.testclient import TestClient

from app.db.db import Database
from app.db.models import OrganizationEntity
from app.models.oin import Oin
from app.services.hsm_key_version_service import HsmKeyVersionService

TEST_ORGANIZATION_A_OIN = Oin("00000099000000001000")
TEST_ORGANIZATION_B_OIN = Oin("00000099000000002000")
TEST_ORGANIZATION_A_OIN_VALUE = TEST_ORGANIZATION_A_OIN.value
TEST_ORGANIZATION_B_OIN_VALUE = TEST_ORGANIZATION_B_OIN.value
TEST_CLIENT_CN = "client_cn"

TEST_ORGANIZATION_A_HEADERS = {
    "x-gf-sub": TEST_ORGANIZATION_A_OIN_VALUE,
    "x-gf-act-sub": TEST_ORGANIZATION_B_OIN_VALUE,
    "x-gf-act-cn": TEST_CLIENT_CN,
    "x-gf-audience": "prs.service",
}

TEST_ORGANIZATION_B_HEADERS = {
    "x-gf-sub": TEST_ORGANIZATION_B_OIN_VALUE,
    "x-gf-act-sub": TEST_ORGANIZATION_B_OIN_VALUE,
    "x-gf-act-cn": TEST_CLIENT_CN,
    "x-gf-audience": "prs.service",
}


def test_create_increments_version(
    client: TestClient,
    database: Database,
    persisted_organization: OrganizationEntity,
    valid_headers: dict[str, str],
) -> None:
    first = client.post("/administration/key-versions", headers=valid_headers)
    second = client.post("/administration/key-versions", headers=valid_headers)

    assert first.json()["version"] == 2
    assert second.json()["version"] == 3


def test_create_with_explicit_window(
    client: TestClient,
    database: Database,
    persisted_organization: OrganizationEntity,
    valid_headers: dict[str, str],
) -> None:
    from_dt = datetime.now(timezone.utc) + timedelta(days=1)
    until_dt = from_dt + timedelta(days=365)
    response = client.post(
        "/administration/key-versions",
        json={
            "from_dt": from_dt.isoformat(),
            "until_dt": until_dt.isoformat(),
        },
        headers=valid_headers,
    )

    assert response.status_code == 201
    body = response.json()
    assert body["from_dt"] == from_dt.isoformat()
    assert body["until_dt"] == until_dt.isoformat()


def test_create_unknown_org_is_unauthorized(
    client: TestClient,
    database: Database,
    valid_headers: dict[str, str],
) -> None:
    response = client.post(
        "/administration/key-versions",
        headers=valid_headers,
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "unauthorized"}


def test_update_rejects_unknown_fields(
    client: TestClient,
    database: Database,
    persisted_organization: OrganizationEntity,
    valid_headers: dict[str, str],
) -> None:
    created = client.post(
        "/administration/key-versions",
        headers=valid_headers,
    ).json()

    response = client.put(
        f"/administration/key-versions/{created['id']}",
        json={"oin": TEST_ORGANIZATION_A_OIN_VALUE},
        headers=TEST_ORGANIZATION_A_HEADERS,
    )

    assert response.status_code == 422


def test_create_persists_version(
    client: TestClient,
    database: Database,
    persisted_organization: OrganizationEntity,
    valid_headers: dict[str, str],
) -> None:
    client.post("/administration/key-versions", headers=valid_headers)

    service = HsmKeyVersionService(database)
    active = service.get_active_versions_by_organization_id(persisted_organization.id)
    assert [v.version for v in active] == [1, 2]


def test_update_sets_until_dt(
    client: TestClient,
    database: Database,
    persisted_organization: OrganizationEntity,
    valid_headers: dict[str, str],
) -> None:
    created = client.post(
        "/administration/key-versions",
        headers=valid_headers,
    ).json()

    until_dt = datetime.now(timezone.utc) + timedelta(minutes=1)
    response = client.put(
        f"/administration/key-versions/{created['id']}",
        json={"until_dt": until_dt.isoformat()},
        headers=valid_headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == created["id"]
    assert body["removed_at"] is None
    assert body["until_dt"] == until_dt.isoformat()

    # The same version now has an updated future end date.
    service = HsmKeyVersionService(database)
    assert (
        len(service.get_active_versions_by_organization_id(persisted_organization.id))
        == 2
    )


def test_update_clears_until_dt(
    client: TestClient,
    database: Database,
    persisted_organization: OrganizationEntity,
    valid_headers: dict[str, str],
) -> None:
    until_dt = datetime(2027, 1, 1, tzinfo=timezone.utc)
    created = client.post(
        "/administration/key-versions",
        json={"until_dt": until_dt.isoformat()},
        headers=valid_headers,
    ).json()

    response = client.put(
        f"/administration/key-versions/{created['id']}",
        json={"until_dt": None},
        headers=valid_headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["until_dt"] is None
    assert body["removed_at"] is None


def test_update_removed_version_is_unauthorized(
    client: TestClient,
    database: Database,
    persisted_organization: OrganizationEntity,
    valid_headers: dict[str, str],
) -> None:
    created = client.post(
        "/administration/key-versions",
        headers=valid_headers,
    ).json()

    HsmKeyVersionService(database).mark_removed(uuid.UUID(created["id"]))

    response = client.put(
        f"/administration/key-versions/{created['id']}",
        json={
            "until_dt": (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat()
        },
        headers=valid_headers,
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "forbidden"}


def test_update_unknown_version_is_unauthorized(
    client: TestClient,
    database: Database,
    persisted_organization: OrganizationEntity,
    valid_headers: dict[str, str],
) -> None:
    response = client.put(
        f"/administration/key-versions/{uuid.uuid4()}",
        json={},
        headers=valid_headers,
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "KeyVersion not found"}


def test_update_invalid_id_returns_422(
    client: TestClient,
    database: Database,
    persisted_organization: OrganizationEntity,
    valid_headers: dict[str, str],
) -> None:
    # FastAPI validates the UUID path param, so a malformed id is a 422.
    response = client.put(
        "/administration/key-versions/not-a-uuid",
        json={},
        headers=valid_headers,
    )

    assert response.status_code == 422


def test_list_versions_returns_all_for_org(
    client: TestClient,
    database: Database,
    persisted_organization: OrganizationEntity,
    valid_headers: dict[str, str],
) -> None:
    client.post("/administration/key-versions", headers=valid_headers)
    client.post("/administration/key-versions", headers=valid_headers)

    response = client.get(
        "/administration/key-versions",
        headers=valid_headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert [v["version"] for v in body] == [1, 2, 3]


def test_list_versions_includes_removed(
    client: TestClient,
    database: Database,
    persisted_organization: OrganizationEntity,
    valid_headers: dict[str, str],
) -> None:
    created = client.post("/administration/key-versions", headers=valid_headers).json()
    HsmKeyVersionService(database).mark_removed(uuid.UUID(created["id"]))

    response = client.get(
        "/administration/key-versions",
        headers=valid_headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 2
    assert body[1]["removed_at"] is not None


def test_list_versions_only_default_for_new_org(
    client: TestClient,
    database: Database,
    persisted_organization: OrganizationEntity,
    valid_headers: dict[str, str],
) -> None:
    response = client.get(
        "/administration/key-versions",
        headers=valid_headers,
    )

    assert response.status_code == 200
    assert len(response.json()) == 1


def test_list_versions_isolated_for_different_organizations(
    client: TestClient,
    database: Database,
    persisted_organization: OrganizationEntity,
    persisted_organization_2: OrganizationEntity,
    valid_headers: dict[str, str],
) -> None:
    client.post("/administration/key-versions", headers=valid_headers)
    client.post("/administration/key-versions", headers=valid_headers)

    client.post(
        "/administration/key-versions",
        headers={
            **valid_headers,
            "x-gf-sub": persisted_organization_2.external_id.value,
        },
    )

    response_for_auth_org = client.get(
        "/administration/key-versions", headers=valid_headers
    )
    assert response_for_auth_org.status_code == 200
    assert [entry["version"] for entry in response_for_auth_org.json()] == [1, 2, 3]

    response_for_other_org = client.get(
        "/administration/key-versions",
        headers={
            **valid_headers,
            "x-gf-sub": persisted_organization_2.external_id.value,
        },
    )
    assert response_for_other_org.status_code == 200
    assert [entry["version"] for entry in response_for_other_org.json()] == [1, 2]

    service = HsmKeyVersionService(database)
    assert (
        len(service.get_versions_by_organization_id(persisted_organization.external_id))
        == 3
    )
    assert (
        len(
            service.get_versions_by_organization_id(
                persisted_organization_2.external_id
            )
        )
        == 2
    )


def test_update_other_org_version_is_unauthorized(
    client: TestClient,
    database: Database,
    persisted_organization: OrganizationEntity,
    persisted_organization_2: OrganizationEntity,
    valid_headers: dict[str, str],
) -> None:
    created = client.post("/administration/key-versions", headers=valid_headers).json()

    response = client.put(
        f"/administration/key-versions/{created['id']}",
        json={
            "until_dt": (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat()
        },
        headers={
            **valid_headers,
            "x-gf-sub": persisted_organization_2.external_id.value,
        },
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "KeyVersion not found"}

    # Ensure the version still belongs to the authenticated owner organization.
    service = HsmKeyVersionService(database)
    assert (
        len(service.get_active_versions_by_organization_id(persisted_organization.id))
        == 2
    )
