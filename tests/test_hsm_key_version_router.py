import uuid
from datetime import datetime, timedelta, timezone

from starlette.testclient import TestClient

from app.db.db import Database
from app.models.oin import Oin
from app.rid import RidUsage
from app.services.hsm_key_version_service import HsmKeyVersionService
from app.services.org_service import OrgService

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


def test_create_first_version(
    client: TestClient, database: Database, org_service: OrgService
) -> None:
    org_service.create(
        TEST_ORGANIZATION_A_OIN,
        f"MyOrg-{TEST_ORGANIZATION_A_OIN}",
        RidUsage.IrreversiblePseudonym,
    )

    response = client.post(
        "/administration/key-versions", headers=TEST_ORGANIZATION_A_HEADERS
    )

    assert response.status_code == 201
    body = response.json()
    assert body["version"] == 1
    assert body["removed"] is False
    assert body["until_dt"] is None
    assert body["from_dt"] is not None


def test_create_increments_version(
    client: TestClient, database: Database, org_service: OrgService
) -> None:
    org_service.create(
        TEST_ORGANIZATION_A_OIN,
        "MyOrg-12345678",
        RidUsage.IrreversiblePseudonym,
    )

    first = client.post(
        "/administration/key-versions", headers=TEST_ORGANIZATION_A_HEADERS
    )
    second = client.post(
        "/administration/key-versions", headers=TEST_ORGANIZATION_A_HEADERS
    )

    assert first.json()["version"] == 1
    assert second.json()["version"] == 2


def test_create_with_explicit_window(
    client: TestClient, database: Database, org_service: OrgService
) -> None:
    org_service.create(
        TEST_ORGANIZATION_A_OIN,
        "MyOrg-12345678",
        RidUsage.IrreversiblePseudonym,
    )

    from_dt = datetime.now(timezone.utc) + timedelta(days=1)
    until_dt = from_dt + timedelta(days=365)
    response = client.post(
        "/administration/key-versions",
        json={
            "from_dt": from_dt.isoformat(),
            "until_dt": until_dt.isoformat(),
        },
        headers=TEST_ORGANIZATION_A_HEADERS,
    )

    assert response.status_code == 201
    body = response.json()
    assert body["from_dt"] == from_dt.isoformat()
    assert body["until_dt"] == until_dt.isoformat()


def test_create_unknown_org_is_unauthorized(
    client: TestClient, database: Database
) -> None:
    response = client.post(
        "/administration/key-versions",
        headers=TEST_ORGANIZATION_A_HEADERS,
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "unauthorized"}


def test_update_rejects_unknown_fields(
    client: TestClient, database: Database, org_service: OrgService
) -> None:
    org_service.create(
        TEST_ORGANIZATION_A_OIN,
        f"MyOrg-{TEST_ORGANIZATION_A_OIN}",
        RidUsage.IrreversiblePseudonym,
    )
    created = client.post(
        "/administration/key-versions", headers=TEST_ORGANIZATION_A_HEADERS
    ).json()

    response = client.put(
        f"/administration/key-versions/{created['id']}",
        json={"oin": TEST_ORGANIZATION_A_OIN_VALUE},
        headers=TEST_ORGANIZATION_A_HEADERS,
    )

    assert response.status_code == 422


def test_create_persists_version(
    client: TestClient, database: Database, org_service: OrgService
) -> None:
    auth_org = org_service.create(
        TEST_ORGANIZATION_A_OIN,
        f"MyOrg-{TEST_ORGANIZATION_A_OIN}",
        RidUsage.IrreversiblePseudonym,
    )

    client.post("/administration/key-versions", headers=TEST_ORGANIZATION_A_HEADERS)

    service = HsmKeyVersionService(database)
    active = service.get_active_versions_by_organization_id(auth_org.id)
    assert [v.version for v in active] == [1]


def test_update_sets_until_dt(
    client: TestClient, database: Database, org_service: OrgService
) -> None:
    auth_org = org_service.create(
        TEST_ORGANIZATION_A_OIN,
        f"MyOrg-{TEST_ORGANIZATION_A_OIN}",
        RidUsage.IrreversiblePseudonym,
    )
    created = client.post(
        "/administration/key-versions",
        headers=TEST_ORGANIZATION_A_HEADERS,
    ).json()

    until_dt = datetime.now(timezone.utc) + timedelta(minutes=1)
    response = client.put(
        f"/administration/key-versions/{created['id']}",
        json={"until_dt": until_dt.isoformat()},
        headers=TEST_ORGANIZATION_A_HEADERS,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == created["id"]
    assert body["removed"] is False
    assert body["until_dt"] == until_dt.isoformat()

    # The same version now has an updated future end date.
    service = HsmKeyVersionService(database)
    assert len(service.get_active_versions_by_organization_id(auth_org.id)) == 1


def test_update_clears_until_dt(
    client: TestClient, database: Database, org_service: OrgService
) -> None:
    org_service.create(
        TEST_ORGANIZATION_A_OIN,
        f"MyOrg-{TEST_ORGANIZATION_A_OIN}",
        RidUsage.IrreversiblePseudonym,
    )
    until_dt = datetime(2027, 1, 1, tzinfo=timezone.utc)
    created = client.post(
        "/administration/key-versions",
        json={"until_dt": until_dt.isoformat()},
        headers=TEST_ORGANIZATION_A_HEADERS,
    ).json()

    response = client.put(
        f"/administration/key-versions/{created['id']}",
        json={"until_dt": None},
        headers=TEST_ORGANIZATION_A_HEADERS,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["until_dt"] is None
    assert body["removed"] is False


def test_update_removed_version_is_unauthorized(
    client: TestClient, database: Database, org_service: OrgService
) -> None:
    org_service.create(
        TEST_ORGANIZATION_A_OIN,
        f"MyOrg-{TEST_ORGANIZATION_A_OIN}",
        RidUsage.IrreversiblePseudonym,
    )
    created = client.post(
        "/administration/key-versions",
        headers=TEST_ORGANIZATION_A_HEADERS,
    ).json()

    HsmKeyVersionService(database).mark_removed(uuid.UUID(created["id"]))

    response = client.put(
        f"/administration/key-versions/{created['id']}",
        json={
            "until_dt": (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat()
        },
        headers=TEST_ORGANIZATION_A_HEADERS,
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "forbidden"}


def test_update_unknown_version_is_unauthorized(
    client: TestClient, database: Database, org_service: OrgService
) -> None:
    org_service.create(
        TEST_ORGANIZATION_A_OIN,
        f"MyOrg-{TEST_ORGANIZATION_A_OIN}",
        RidUsage.IrreversiblePseudonym,
    )

    response = client.put(
        f"/administration/key-versions/{uuid.uuid4()}",
        json={},
        headers=TEST_ORGANIZATION_A_HEADERS,
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "forbidden"}


def test_update_invalid_id_returns_422(
    client: TestClient, database: Database, org_service: OrgService
) -> None:
    org_service.create(
        TEST_ORGANIZATION_A_OIN,
        f"MyOrg-{TEST_ORGANIZATION_A_OIN}",
        RidUsage.IrreversiblePseudonym,
    )

    # FastAPI validates the UUID path param, so a malformed id is a 422.
    response = client.put(
        "/administration/key-versions/not-a-uuid",
        json={},
        headers=TEST_ORGANIZATION_A_HEADERS,
    )

    assert response.status_code == 422


def test_list_versions_returns_all_for_org(
    client: TestClient, database: Database, org_service: OrgService
) -> None:
    org_service.create(
        TEST_ORGANIZATION_A_OIN,
        f"MyOrg-{TEST_ORGANIZATION_A_OIN}",
        RidUsage.IrreversiblePseudonym,
    )
    client.post("/administration/key-versions", headers=TEST_ORGANIZATION_A_HEADERS)
    client.post("/administration/key-versions", headers=TEST_ORGANIZATION_A_HEADERS)

    response = client.get(
        "/administration/key-versions",
        headers=TEST_ORGANIZATION_A_HEADERS,
    )

    assert response.status_code == 200
    body = response.json()
    assert [v["version"] for v in body] == [1, 2]


def test_list_versions_includes_removed(
    client: TestClient, database: Database, org_service: OrgService
) -> None:
    org_service.create(
        TEST_ORGANIZATION_A_OIN,
        f"MyOrg-{TEST_ORGANIZATION_A_OIN}",
        RidUsage.IrreversiblePseudonym,
    )
    created = client.post(
        "/administration/key-versions", headers=TEST_ORGANIZATION_A_HEADERS
    ).json()
    HsmKeyVersionService(database).mark_removed(uuid.UUID(created["id"]))

    response = client.get(
        "/administration/key-versions",
        headers=TEST_ORGANIZATION_A_HEADERS,
    )

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["removed"] is True


def test_list_versions_empty_for_org_without_versions(
    client: TestClient, database: Database, org_service: OrgService
) -> None:
    org_service.create(
        TEST_ORGANIZATION_A_OIN,
        f"MyOrg-{TEST_ORGANIZATION_A_OIN}",
        RidUsage.IrreversiblePseudonym,
    )

    response = client.get(
        "/administration/key-versions",
        headers=TEST_ORGANIZATION_A_HEADERS,
    )

    assert response.status_code == 200
    assert response.json() == []


def test_list_versions_isolated_for_different_organizations(
    client: TestClient, database: Database, org_service: OrgService
) -> None:
    auth_org = org_service.create(
        TEST_ORGANIZATION_A_OIN,
        f"MyOrg-{TEST_ORGANIZATION_A_OIN}",
        RidUsage.IrreversiblePseudonym,
    )
    other_org = org_service.create(
        TEST_ORGANIZATION_B_OIN,
        f"MyOrg-{TEST_ORGANIZATION_B_OIN}",
        RidUsage.IrreversiblePseudonym,
    )

    client.post("/administration/key-versions", headers=TEST_ORGANIZATION_A_HEADERS)
    client.post("/administration/key-versions", headers=TEST_ORGANIZATION_A_HEADERS)

    client.post("/administration/key-versions", headers=TEST_ORGANIZATION_B_HEADERS)

    response_for_auth_org = client.get(
        "/administration/key-versions", headers=TEST_ORGANIZATION_A_HEADERS
    )
    assert response_for_auth_org.status_code == 200
    assert [entry["version"] for entry in response_for_auth_org.json()] == [1, 2]

    response_for_other_org = client.get(
        "/administration/key-versions", headers=TEST_ORGANIZATION_B_HEADERS
    )
    assert response_for_other_org.status_code == 200
    assert [entry["version"] for entry in response_for_other_org.json()] == [1]

    service = HsmKeyVersionService(database)
    assert len(service.get_versions_by_organization_id(auth_org.id)) == 2
    assert len(service.get_versions_by_organization_id(other_org.id)) == 1


def test_update_other_org_version_is_unauthorized(
    client: TestClient, database: Database, org_service: OrgService
) -> None:
    auth_org = org_service.create(
        TEST_ORGANIZATION_A_OIN,
        f"MyOrg-{TEST_ORGANIZATION_A_OIN}",
        RidUsage.IrreversiblePseudonym,
    )
    org_service.create(
        TEST_ORGANIZATION_B_OIN,
        f"MyOrg-{TEST_ORGANIZATION_B_OIN}",
        RidUsage.IrreversiblePseudonym,
    )

    created = client.post(
        "/administration/key-versions", headers=TEST_ORGANIZATION_A_HEADERS
    ).json()

    response = client.put(
        f"/administration/key-versions/{created['id']}",
        json={
            "until_dt": (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat()
        },
        headers=TEST_ORGANIZATION_B_HEADERS,
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "forbidden"}

    # Ensure the version still belongs to the authenticated owner organization.
    service = HsmKeyVersionService(database)
    assert len(service.get_active_versions_by_organization_id(auth_org.id)) == 1
