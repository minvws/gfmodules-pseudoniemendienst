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
    org_service.create(
        "00000099000000001000",
        "MyOrg-00000099000000001000",
        RidUsage.IrreversiblePseudonym,
    )

    response = client.post(
        "/key-versions",
        json={"oin": "00000099000000001000"},
        headers={"x-gf-oin": "00000099000000001000", "x-gf-audience": "prs.service"},
    )

    assert response.status_code == 201
    body = response.json()
    assert body["oin"] == "00000099000000001000"
    assert body["version"] == 1
    assert body["removed"] is False
    assert body["until_dt"] is None
    assert body["from_dt"] is not None


def test_create_increments_version(
    client: TestClient, database: Database, org_service: OrgService
) -> None:
    org_service.create(
        "00000099000000001000", "MyOrg-12345678", RidUsage.IrreversiblePseudonym
    )

    first = client.post(
        "/key-versions",
        json={"oin": "00000099000000001000"},
        headers={"x-gf-oin": "00000099000000001000", "x-gf-audience": "prs.service"},
    )
    second = client.post(
        "/key-versions",
        json={"oin": "00000099000000001000"},
        headers={"x-gf-oin": "00000099000000001000", "x-gf-audience": "prs.service"},
    )

    assert first.json()["version"] == 1
    assert second.json()["version"] == 2


def test_create_with_explicit_window(
    client: TestClient, database: Database, org_service: OrgService
) -> None:
    org_service.create(
        "00000099000000001000", "MyOrg-12345678", RidUsage.IrreversiblePseudonym
    )

    from_dt = datetime(2026, 1, 1, tzinfo=timezone.utc)
    until_dt = datetime(2027, 1, 1, tzinfo=timezone.utc)
    response = client.post(
        "/key-versions",
        json={
            "oin": "00000099000000001000",
            "from_dt": from_dt.isoformat(),
            "until_dt": until_dt.isoformat(),
        },
        headers={"x-gf-oin": "00000099000000001000", "x-gf-audience": "prs.service"},
    )

    assert response.status_code == 201
    body = response.json()
    assert body["from_dt"] == from_dt.isoformat()
    assert body["until_dt"] == until_dt.isoformat()


def test_create_unknown_org_returns_404(client: TestClient, database: Database) -> None:
    response = client.post(
        "/key-versions",
        json={"oin": "00000099000000001000"},
        headers={"x-gf-oin": "00000099000000001000", "x-gf-audience": "prs.service"},
    )

    assert response.status_code == 404
    assert response.json() == {
        "detail": "organization with oin 00000099000000001000 not found"
    }


def test_create_invalid_oin_returns_422(client: TestClient, database: Database) -> None:
    response = client.post(
        "/key-versions",
        json={"oin": "not-a-oin"},
        headers={"x-gf-oin": "00000099000000001000", "x-gf-audience": "prs.service"},
    )

    assert response.status_code == 422


def test_create_persists_version(
    client: TestClient, database: Database, org_service: OrgService
) -> None:
    org_service.create(
        "00000099000000001000",
        "MyOrg-00000099000000001000",
        RidUsage.IrreversiblePseudonym,
    )

    client.post(
        "/key-versions",
        json={"oin": "00000099000000001000"},
        headers={"x-gf-oin": "00000099000000001000", "x-gf-audience": "prs.service"},
    )

    service = HsmKeyVersionService(database)
    active = service.get_active_versions(oin="00000099000000001000")
    assert [v.version for v in active] == [1]


def test_update_sets_removed_and_until_dt(
    client: TestClient, database: Database, org_service: OrgService
) -> None:
    org_service.create(
        "00000099000000001000",
        "MyOrg-00000099000000001000",
        RidUsage.IrreversiblePseudonym,
    )
    created = client.post(
        "/key-versions",
        json={"oin": "00000099000000001000"},
        headers={"x-gf-oin": "00000099000000001000", "x-gf-audience": "prs.service"},
    ).json()

    until_dt = datetime(2027, 1, 1, tzinfo=timezone.utc)
    response = client.put(
        f"/key-versions/{created['id']}",
        json={"removed": True, "until_dt": until_dt.isoformat()},
        headers={"x-gf-oin": "00000099000000001000", "x-gf-audience": "prs.service"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == created["id"]
    assert body["removed"] is True
    assert body["until_dt"] == until_dt.isoformat()

    # The removed version is no longer returned as active.
    service = HsmKeyVersionService(database)
    assert service.get_active_versions(oin="00000099000000001000") == []


def test_update_clears_until_dt(
    client: TestClient, database: Database, org_service: OrgService
) -> None:
    org_service.create(
        "00000099000000001000",
        "MyOrg-00000099000000001000",
        RidUsage.IrreversiblePseudonym,
    )
    until_dt = datetime(2027, 1, 1, tzinfo=timezone.utc)
    created = client.post(
        "/key-versions",
        json={"oin": "00000099000000001000", "until_dt": until_dt.isoformat()},
        headers={"x-gf-oin": "00000099000000001000", "x-gf-audience": "prs.service"},
    ).json()

    response = client.put(
        f"/key-versions/{created['id']}",
        json={"removed": False},
        headers={"x-gf-oin": "00000099000000001000", "x-gf-audience": "prs.service"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["until_dt"] is None
    assert body["removed"] is False


def test_update_unknown_version_returns_404(
    client: TestClient, database: Database
) -> None:
    response = client.put(
        f"/key-versions/{uuid.uuid4()}",
        json={"removed": True},
        headers={"x-gf-oin": "00000099000000001000", "x-gf-audience": "prs.service"},
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "key version not found"}


def test_update_invalid_id_returns_422(client: TestClient, database: Database) -> None:
    # FastAPI validates the UUID path param, so a malformed id is a 422.
    response = client.put(
        "/key-versions/not-a-uuid",
        json={"removed": True},
        headers={"x-gf-oin": "00000099000000001000", "x-gf-audience": "prs.service"},
    )

    assert response.status_code == 422


def test_list_versions_returns_all_for_org(
    client: TestClient, database: Database, org_service: OrgService
) -> None:
    org_service.create(
        "00000099000000001000",
        "MyOrg-00000099000000001000",
        RidUsage.IrreversiblePseudonym,
    )
    client.post(
        "/key-versions",
        json={"oin": "00000099000000001000"},
        headers={"x-gf-oin": "00000099000000001000", "x-gf-audience": "prs.service"},
    )
    client.post(
        "/key-versions",
        json={"oin": "00000099000000001000"},
        headers={"x-gf-oin": "00000099000000001000", "x-gf-audience": "prs.service"},
    )

    response = client.get(
        "/key-versions/00000099000000001000",
        headers={"x-gf-oin": "00000099000000001000", "x-gf-audience": "prs.service"},
    )

    assert response.status_code == 200
    body = response.json()
    assert [v["version"] for v in body] == [1, 2]
    assert {v["oin"] for v in body} == {"00000099000000001000"}


def test_list_versions_includes_removed(
    client: TestClient, database: Database, org_service: OrgService
) -> None:
    org_service.create(
        "00000099000000001000",
        "MyOrg-00000099000000001000",
        RidUsage.IrreversiblePseudonym,
    )
    created = client.post(
        "/key-versions",
        json={"oin": "00000099000000001000"},
        headers={"x-gf-oin": "00000099000000001000", "x-gf-audience": "prs.service"},
    ).json()
    client.put(
        f"/key-versions/{created['id']}",
        json={"removed": True},
        headers={"x-gf-oin": "00000099000000001000", "x-gf-audience": "prs.service"},
    )

    response = client.get(
        "/key-versions/00000099000000001000",
        headers={"x-gf-oin": "00000099000000001000", "x-gf-audience": "prs.service"},
    )

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["removed"] is True


def test_list_versions_empty_for_org_without_versions(
    client: TestClient, database: Database, org_service: OrgService
) -> None:
    org_service.create(
        "00000099000000001000",
        "MyOrg-00000099000000001000",
        RidUsage.IrreversiblePseudonym,
    )

    response = client.get(
        "/key-versions/00000099000000001000",
        headers={"x-gf-oin": "00000099000000001000", "x-gf-audience": "prs.service"},
    )

    assert response.status_code == 200
    assert response.json() == []


def test_list_versions_unknown_org_returns_404(
    client: TestClient, database: Database
) -> None:
    response = client.get(
        "/key-versions/00000099000000001000",
        headers={"x-gf-oin": "00000099000000001000", "x-gf-audience": "prs.service"},
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "organization not found"}
