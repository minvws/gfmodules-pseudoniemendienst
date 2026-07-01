import uuid
from datetime import datetime, timezone

from starlette.testclient import TestClient

from app.db.db import Database
from app.models.oin import Oin
from app.services.hsm_key_version_service import HsmKeyVersionService

TEST_OIN = Oin("00000099000000001000")
TEST_OIN_VALUE = TEST_OIN.value


def test_create_first_version(client: TestClient, database: Database) -> None:

    response = client.post(
        "/administration/key-versions",
        json={},
        headers={"x-gf-oin": TEST_OIN_VALUE, "x-gf-audience": "prs.service"},
    )

    assert response.status_code == 201
    body = response.json()
    assert body["oin"] == TEST_OIN_VALUE
    assert body["version"] == 1
    assert body["removed"] is False
    assert body["until_dt"] is None
    assert body["from_dt"] is not None


def test_create_increments_version(client: TestClient, database: Database) -> None:

    first = client.post(
        "/administration/key-versions",
        json={},
        headers={"x-gf-oin": TEST_OIN_VALUE, "x-gf-audience": "prs.service"},
    )
    second = client.post(
        "/administration/key-versions",
        json={},
        headers={"x-gf-oin": TEST_OIN_VALUE, "x-gf-audience": "prs.service"},
    )

    assert first.json()["version"] == 1
    assert second.json()["version"] == 2


def test_create_with_explicit_window(client: TestClient, database: Database) -> None:

    from_dt = datetime(2026, 1, 1, tzinfo=timezone.utc)
    until_dt = datetime(2027, 1, 1, tzinfo=timezone.utc)
    response = client.post(
        "/administration/key-versions",
        json={
            "from_dt": from_dt.isoformat(),
            "until_dt": until_dt.isoformat(),
        },
        headers={"x-gf-oin": TEST_OIN_VALUE, "x-gf-audience": "prs.service"},
    )

    assert response.status_code == 201
    body = response.json()
    assert body["from_dt"] == from_dt.isoformat()
    assert body["until_dt"] == until_dt.isoformat()


def test_create_unknown_org_returns_201(client: TestClient, database: Database) -> None:
    response = client.post(
        "/administration/key-versions",
        json={},
        headers={"x-gf-oin": TEST_OIN_VALUE, "x-gf-audience": "prs.service"},
    )

    assert response.status_code == 201
    assert response.json()["oin"] == TEST_OIN_VALUE


def test_create_invalid_window_returns_422(
    client: TestClient, database: Database
) -> None:
    response = client.post(
        "/administration/key-versions",
        json={"from_dt": "not-a-date"},
        headers={"x-gf-oin": TEST_OIN_VALUE, "x-gf-audience": "prs.service"},
    )

    assert response.status_code == 422


def test_create_persists_version(client: TestClient, database: Database) -> None:

    client.post(
        "/administration/key-versions",
        json={},
        headers={"x-gf-oin": TEST_OIN_VALUE, "x-gf-audience": "prs.service"},
    )

    service = HsmKeyVersionService(database)
    active = service.get_active_versions(oin=TEST_OIN)
    assert [v.version for v in active] == [1]


def test_update_sets_until_dt(client: TestClient, database: Database) -> None:
    created = client.post(
        "/administration/key-versions",
        json={},
        headers={"x-gf-oin": TEST_OIN_VALUE, "x-gf-audience": "prs.service"},
    ).json()

    until_dt = datetime(2027, 1, 1, tzinfo=timezone.utc)
    response = client.put(
        f"/administration/key-versions/{created['id']}",
        json={"until_dt": until_dt.isoformat()},
        headers={"x-gf-oin": TEST_OIN_VALUE, "x-gf-audience": "prs.service"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == created["id"]
    assert body["removed"] is False
    assert body["until_dt"] == until_dt.isoformat()

    service = HsmKeyVersionService(database)
    active = service.get_active_versions(oin=TEST_OIN)
    assert len(active) == 1
    assert str(active[0].id) == created["id"]


def test_update_clears_until_dt(client: TestClient, database: Database) -> None:
    until_dt = datetime(2027, 1, 1, tzinfo=timezone.utc)
    created = client.post(
        "/administration/key-versions",
        json={"until_dt": until_dt.isoformat()},
        headers={"x-gf-oin": TEST_OIN_VALUE, "x-gf-audience": "prs.service"},
    ).json()

    response = client.put(
        f"/administration/key-versions/{created['id']}",
        json={},
        headers={"x-gf-oin": TEST_OIN_VALUE, "x-gf-audience": "prs.service"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["until_dt"] is None
    assert body["removed"] is False


def test_update_unknown_version_returns_404(
    client: TestClient, database: Database
) -> None:
    response = client.put(
        f"/administration/key-versions/{uuid.uuid4()}",
        json={},
        headers={"x-gf-oin": TEST_OIN_VALUE, "x-gf-audience": "prs.service"},
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "key version not found"}


def test_update_removed_version_returns_404(
    client: TestClient, database: Database
) -> None:
    created = client.post(
        "/administration/key-versions",
        json={},
        headers={"x-gf-oin": TEST_OIN_VALUE, "x-gf-audience": "prs.service"},
    ).json()

    HsmKeyVersionService(database).mark_removed(created["id"], TEST_OIN)

    response = client.put(
        f"/administration/key-versions/{created['id']}",
        json={},
        headers={"x-gf-oin": TEST_OIN_VALUE, "x-gf-audience": "prs.service"},
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "key version not found"}


def test_update_invalid_id_returns_422(client: TestClient, database: Database) -> None:
    # FastAPI validates the UUID path param, so a malformed id is a 422.
    response = client.put(
        "/administration/key-versions/not-a-uuid",
        json={},
        headers={"x-gf-oin": TEST_OIN_VALUE, "x-gf-audience": "prs.service"},
    )

    assert response.status_code == 422


def test_list_versions_returns_all_for_org(
    client: TestClient, database: Database
) -> None:
    client.post(
        "/administration/key-versions",
        json={},
        headers={"x-gf-oin": TEST_OIN_VALUE, "x-gf-audience": "prs.service"},
    )
    client.post(
        "/administration/key-versions",
        json={},
        headers={"x-gf-oin": TEST_OIN_VALUE, "x-gf-audience": "prs.service"},
    )

    response = client.get(
        "/administration/key-versions",
        headers={"x-gf-oin": TEST_OIN_VALUE, "x-gf-audience": "prs.service"},
    )

    assert response.status_code == 200
    body = response.json()
    assert [v["version"] for v in body] == [1, 2]
    assert {v["oin"] for v in body} == {TEST_OIN_VALUE}


def test_list_versions_includes_removed(client: TestClient, database: Database) -> None:
    created = client.post(
        "/administration/key-versions",
        json={},
        headers={"x-gf-oin": TEST_OIN_VALUE, "x-gf-audience": "prs.service"},
    ).json()
    HsmKeyVersionService(database).mark_removed(created["id"], TEST_OIN)

    response = client.get(
        "/administration/key-versions",
        headers={"x-gf-oin": TEST_OIN_VALUE, "x-gf-audience": "prs.service"},
    )

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["removed"] is True


def test_list_versions_empty_for_org_without_versions(
    client: TestClient, database: Database
) -> None:

    response = client.get(
        "/administration/key-versions",
        headers={"x-gf-oin": TEST_OIN_VALUE, "x-gf-audience": "prs.service"},
    )

    assert response.status_code == 200
    assert response.json() == []


def test_list_versions_unknown_org_returns_empty(
    client: TestClient, database: Database
) -> None:
    response = client.get(
        "/administration/key-versions",
        headers={"x-gf-oin": TEST_OIN_VALUE, "x-gf-audience": "prs.service"},
    )

    assert response.status_code == 200
    assert response.json() == []
