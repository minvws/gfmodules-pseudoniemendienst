import uuid
from datetime import datetime, timezone

from starlette.testclient import TestClient

from app.db.db import Database
from app.rid import RidUsage
from app.services.hsm_key_version_service import HsmKeyVersionService
from app.services.org_service import OrgService


def test_create_first_version(
    client: TestClient, database: Database, org_service: OrgService
) -> None:
    org_service.create("12345678", "MyOrg-12345678", RidUsage.IrreversiblePseudonym)

    response = client.post("/key-versions", json={"ura": "12345678"})

    assert response.status_code == 201
    body = response.json()
    assert body["ura"] == "12345678"
    assert body["version"] == 1
    assert body["removed"] is False
    assert body["until_dt"] is None
    assert body["from_dt"] is not None


def test_create_increments_version(
    client: TestClient, database: Database, org_service: OrgService
) -> None:
    org_service.create("12345678", "MyOrg-12345678", RidUsage.IrreversiblePseudonym)

    first = client.post("/key-versions", json={"ura": "12345678"})
    second = client.post("/key-versions", json={"ura": "12345678"})

    assert first.json()["version"] == 1
    assert second.json()["version"] == 2


def test_create_with_explicit_window(
    client: TestClient, database: Database, org_service: OrgService
) -> None:
    org_service.create("12345678", "MyOrg-12345678", RidUsage.IrreversiblePseudonym)

    from_dt = datetime(2026, 1, 1, tzinfo=timezone.utc)
    until_dt = datetime(2027, 1, 1, tzinfo=timezone.utc)
    response = client.post(
        "/key-versions",
        json={
            "ura": "12345678",
            "from_dt": from_dt.isoformat(),
            "until_dt": until_dt.isoformat(),
        },
    )

    assert response.status_code == 201
    body = response.json()
    assert body["from_dt"] == from_dt.isoformat()
    assert body["until_dt"] == until_dt.isoformat()


def test_create_unknown_org_returns_404(client: TestClient, database: Database) -> None:
    response = client.post("/key-versions", json={"ura": "99999999"})

    assert response.status_code == 404
    assert response.json() == {"detail": "organization with ura 99999999 not found"}


def test_create_invalid_ura_returns_422(client: TestClient, database: Database) -> None:
    response = client.post("/key-versions", json={"ura": "not-a-ura"})

    assert response.status_code == 422


def test_create_persists_version(
    client: TestClient, database: Database, org_service: OrgService
) -> None:
    org_service.create("12345678", "MyOrg-12345678", RidUsage.IrreversiblePseudonym)

    client.post("/key-versions", json={"ura": "12345678"})

    service = HsmKeyVersionService(database)
    active = service.get_active_versions(ura="12345678")
    assert [v.version for v in active] == [1]


def test_update_sets_removed_and_until_dt(
    client: TestClient, database: Database, org_service: OrgService
) -> None:
    org_service.create("12345678", "MyOrg-12345678", RidUsage.IrreversiblePseudonym)
    created = client.post("/key-versions", json={"ura": "12345678"}).json()

    until_dt = datetime(2027, 1, 1, tzinfo=timezone.utc)
    response = client.put(
        f"/key-versions/{created['id']}",
        json={"removed": True, "until_dt": until_dt.isoformat()},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == created["id"]
    assert body["removed"] is True
    assert body["until_dt"] == until_dt.isoformat()

    # The removed version is no longer returned as active.
    service = HsmKeyVersionService(database)
    assert service.get_active_versions(ura="12345678") == []


def test_update_clears_until_dt(
    client: TestClient, database: Database, org_service: OrgService
) -> None:
    org_service.create("12345678", "MyOrg-12345678", RidUsage.IrreversiblePseudonym)
    until_dt = datetime(2027, 1, 1, tzinfo=timezone.utc)
    created = client.post(
        "/key-versions",
        json={"ura": "12345678", "until_dt": until_dt.isoformat()},
    ).json()

    response = client.put(f"/key-versions/{created['id']}", json={"removed": False})

    assert response.status_code == 200
    body = response.json()
    assert body["until_dt"] is None
    assert body["removed"] is False


def test_update_unknown_version_returns_404(
    client: TestClient, database: Database
) -> None:
    response = client.put(f"/key-versions/{uuid.uuid4()}", json={"removed": True})

    assert response.status_code == 404
    assert response.json() == {"detail": "key version not found"}


def test_update_invalid_id_returns_400(client: TestClient, database: Database) -> None:
    response = client.put("/key-versions/not-a-uuid", json={"removed": True})

    assert response.status_code == 400
    assert response.json() == {"detail": "invalid key version id"}
