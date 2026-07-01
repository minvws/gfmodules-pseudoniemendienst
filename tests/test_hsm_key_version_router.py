import uuid
from datetime import datetime, timedelta, timezone

from starlette.testclient import TestClient

from app.db.db import Database
from app.models.oin import Oin
from app.services.hsm_key_version_service import HsmKeyVersionService
from tests.helpers import assert_key_version_payload


def _to_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def test_create_first_version(
    client: TestClient, database: Database, auth_headers: dict[str, str]
) -> None:

    response = client.post(
        "/administration/key-versions",
        json={},
        headers=auth_headers,
    )

    assert response.status_code == 201
    assert_key_version_payload(response.json(), 1)


def test_create_key_version_uses_authenticated_oin(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    response = client.post(
        "/administration/key-versions",
        json={},
        headers=auth_headers,
    )

    assert response.status_code == 201
    body = response.json()
    assert set(body.keys()) == {"id", "version", "from_dt", "until_dt", "removed"}
    assert isinstance(body["version"], int)
    assert body["version"] >= 1
    assert body["removed"] is False
    assert body["until_dt"] is None
    assert body["from_dt"] is not None


def test_create_increments_version(
    client: TestClient, database: Database, auth_headers: dict[str, str]
) -> None:

    first = client.post(
        "/administration/key-versions",
        json={},
        headers=auth_headers,
    )
    second = client.post(
        "/administration/key-versions",
        json={},
        headers=auth_headers,
    )

    assert first.json()["version"] == 1
    assert second.json()["version"] == 2


def test_key_versions_put_path_not_supported_for_get(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    response = client.get(
        f"/administration/key-versions/{uuid.uuid4()}",
        headers=auth_headers,
    )

    assert response.status_code == 405


def test_create_with_explicit_window(
    client: TestClient, database: Database, auth_headers: dict[str, str]
) -> None:

    from_dt = datetime.now(timezone.utc) + timedelta(days=1)
    until_dt = from_dt + timedelta(days=365)
    response = client.post(
        "/administration/key-versions",
        json={
            "from_dt": from_dt.isoformat(),
            "until_dt": until_dt.isoformat(),
        },
        headers=auth_headers,
    )

    assert response.status_code == 201
    body = response.json()
    assert body["from_dt"] == from_dt.isoformat()
    assert body["until_dt"] == until_dt.isoformat()


def test_create_with_timezone_aware_window_is_accepted(
    client: TestClient, database: Database, auth_headers: dict[str, str]
) -> None:
    from_dt = (datetime.now(timezone.utc) + timedelta(days=1)).astimezone(
        tz=timezone(offset=timedelta(hours=2))
    )
    until_dt = (datetime.now(timezone.utc) + timedelta(days=2)).astimezone(
        tz=timezone(offset=timedelta(hours=-3))
    )

    response = client.post(
        "/administration/key-versions",
        json={
            "from_dt": from_dt.isoformat(),
            "until_dt": until_dt.isoformat(),
        },
        headers=auth_headers,
    )

    assert response.status_code == 201
    body = response.json()
    assert body["from_dt"] is not None
    assert body["until_dt"] is not None


def test_create_with_timezone_aware_window_is_persisted_in_db(
    client: TestClient,
    database: Database,
    auth_headers: dict[str, str],
    test_oin: Oin,
) -> None:
    from_dt = datetime(2027, 1, 1, 10, tzinfo=timezone(offset=timedelta(hours=2)))
    until_dt = datetime(2027, 1, 2, 10, tzinfo=timezone(offset=timedelta(hours=-3)))

    response = client.post(
        "/administration/key-versions",
        json={
            "from_dt": from_dt.isoformat(),
            "until_dt": until_dt.isoformat(),
        },
        headers=auth_headers,
    )

    assert response.status_code == 201

    service = HsmKeyVersionService(database)
    versions = service.get_versions_for_oin(test_oin)

    assert len(versions) == 1
    stored = versions[0]
    assert stored.from_dt.tzinfo is not None
    assert stored.until_dt is not None
    assert stored.until_dt.tzinfo is not None
    assert stored.from_dt.astimezone(timezone.utc) == from_dt.astimezone(timezone.utc)
    assert stored.until_dt.astimezone(timezone.utc) == until_dt.astimezone(timezone.utc)


def test_update_with_timezone_aware_until_dt_is_accepted(
    client: TestClient, database: Database, auth_headers: dict[str, str]
) -> None:
    created = client.post(
        "/administration/key-versions",
        json={},
        headers=auth_headers,
    ).json()

    until_dt = (datetime.now(timezone.utc) + timedelta(days=7)).astimezone(
        tz=timezone(offset=timedelta(hours=9))
    )

    response = client.put(
        f"/administration/key-versions/{created['id']}",
        json={"until_dt": until_dt.isoformat()},
        headers=auth_headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["until_dt"] is not None


def test_update_with_timezone_aware_until_dt_is_persisted_in_db(
    client: TestClient,
    database: Database,
    auth_headers: dict[str, str],
    test_oin: Oin,
) -> None:
    created = client.post(
        "/administration/key-versions",
        json={},
        headers=auth_headers,
    ).json()

    until_dt = (
        datetime(2027, 1, 2, 10, tzinfo=timezone(offset=timedelta(hours=7)))
    ).astimezone(tz=timezone(offset=timedelta(hours=-4)))

    response = client.put(
        f"/administration/key-versions/{created['id']}",
        json={"until_dt": until_dt.isoformat()},
        headers=auth_headers,
    )

    assert response.status_code == 200

    service = HsmKeyVersionService(database)
    versions = service.get_versions_for_oin(test_oin)

    assert len(versions) == 1
    stored = versions[0]
    assert str(stored.id) == created["id"]
    assert stored.until_dt is not None
    assert stored.until_dt.tzinfo is not None
    assert stored.until_dt.astimezone(timezone.utc) == until_dt.astimezone(timezone.utc)


def test_create_treats_utc_zero_offset_and_z_equivalently(
    client: TestClient,
    database: Database,
    auth_headers: dict[str, str],
    test_oin: Oin,
) -> None:
    expected_from_dt = datetime(2027, 1, 1, 10, 0, tzinfo=timezone.utc)
    expected_until_dt = datetime(2027, 1, 2, 10, 0, tzinfo=timezone.utc)

    for offset in "+00:00", "Z":
        response = client.post(
            "/administration/key-versions",
            json={
                "from_dt": f"2027-01-01T10:00:00{offset}",
                "until_dt": f"2027-01-02T10:00:00{offset}",
            },
            headers=auth_headers,
        )

        assert response.status_code == 201
        body = response.json()
        assert body["from_dt"] is not None
        assert body["until_dt"] is not None
        assert _to_utc(body["from_dt"]) == expected_from_dt
        assert _to_utc(body["until_dt"]) == expected_until_dt

    service = HsmKeyVersionService(database)
    versions = service.get_versions_for_oin(test_oin)
    assert len(versions) == 2
    assert all(v.from_dt.astimezone(timezone.utc) == expected_from_dt for v in versions)
    assert all(
        v.until_dt is not None
        and v.until_dt.astimezone(timezone.utc) == expected_until_dt
        for v in versions
    )


def test_update_treats_utc_zero_offset_and_z_equivalently_in_db(
    client: TestClient,
    database: Database,
    auth_headers: dict[str, str],
    test_oin: Oin,
) -> None:
    created = client.post(
        "/administration/key-versions",
        json={},
        headers=auth_headers,
    ).json()

    expected_until_dt = datetime(2027, 1, 3, 12, 0, tzinfo=timezone.utc)

    for offset in "+00:00", "Z":
        response = client.put(
            f"/administration/key-versions/{created['id']}",
            json={"until_dt": f"2027-01-03T12:00:00{offset}"},
            headers=auth_headers,
        )

        assert response.status_code == 200
        body = response.json()
        assert body["until_dt"] is not None
        assert _to_utc(body["until_dt"]) == expected_until_dt

        service = HsmKeyVersionService(database)
        versions = service.get_versions_for_oin(test_oin)
        assert len(versions) == 1
        stored = versions[0]
        assert stored.until_dt is not None
        assert stored.until_dt.tzinfo is not None
        assert stored.until_dt.astimezone(timezone.utc) == expected_until_dt


def test_create_unknown_org_returns_201(
    client: TestClient, database: Database, auth_headers: dict[str, str]
) -> None:
    response = client.post(
        "/administration/key-versions",
        json={},
        headers=auth_headers,
    )

    assert response.status_code == 201
    assert_key_version_payload(response.json(), 1)


def test_create_invalid_window_returns_422(
    client: TestClient, database: Database, auth_headers: dict[str, str]
) -> None:
    response = client.post(
        "/administration/key-versions",
        json={"from_dt": "not-a-date"},
        headers=auth_headers,
    )

    assert response.status_code == 422


def test_create_persists_version(
    client: TestClient,
    database: Database,
    auth_headers: dict[str, str],
    test_oin: Oin,
) -> None:

    client.post(
        "/administration/key-versions",
        json={},
        headers=auth_headers,
    )

    service = HsmKeyVersionService(database)
    active = service.get_active_versions(oin=test_oin)
    assert [v.version for v in active] == [1]


def test_update_sets_until_dt(
    client: TestClient,
    database: Database,
    auth_headers: dict[str, str],
    test_oin: Oin,
) -> None:
    created = client.post(
        "/administration/key-versions",
        json={},
        headers=auth_headers,
    ).json()

    until_dt = datetime.now(timezone.utc) + timedelta(days=365)
    response = client.put(
        f"/administration/key-versions/{created['id']}",
        json={"until_dt": until_dt.isoformat()},
        headers=auth_headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == created["id"]
    assert body["removed"] is False
    assert body["until_dt"] == until_dt.isoformat()

    service = HsmKeyVersionService(database)
    active = service.get_active_versions(oin=test_oin)
    assert len(active) == 1
    assert str(active[0].id) == created["id"]


def test_update_other_org_key_version_returns_not_found(
    client: TestClient,
    database: Database,
    auth_headers: dict[str, str],
    test_other_oin: Oin,
) -> None:
    service = HsmKeyVersionService(database)
    entry = service.create_version(test_other_oin)

    response = client.put(
        f"/administration/key-versions/{entry.id}",
        json={},
        headers=auth_headers,
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "key version not found"}


def test_update_clears_until_dt(
    client: TestClient, database: Database, auth_headers: dict[str, str]
) -> None:
    until_dt = datetime.now(timezone.utc) + timedelta(days=365)
    created = client.post(
        "/administration/key-versions",
        json={"until_dt": until_dt.isoformat()},
        headers=auth_headers,
    ).json()

    response = client.put(
        f"/administration/key-versions/{created['id']}",
        json={},
        headers=auth_headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["until_dt"] is None
    assert body["removed"] is False


def test_update_unknown_version_returns_404(
    client: TestClient, database: Database, auth_headers: dict[str, str]
) -> None:
    response = client.put(
        f"/administration/key-versions/{uuid.uuid4()}",
        json={},
        headers=auth_headers,
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "key version not found"}


def test_update_removed_version_returns_404(
    client: TestClient, database: Database, auth_headers: dict[str, str], test_oin: Oin
) -> None:
    created = client.post(
        "/administration/key-versions",
        json={},
        headers=auth_headers,
    ).json()

    HsmKeyVersionService(database).mark_removed(created["id"], test_oin)

    response = client.put(
        f"/administration/key-versions/{created['id']}",
        json={},
        headers=auth_headers,
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "key version not found"}


def test_update_invalid_id_returns_422(
    client: TestClient, database: Database, auth_headers: dict[str, str]
) -> None:
    # FastAPI validates the UUID path param, so a malformed id is a 422.
    response = client.put(
        "/administration/key-versions/not-a-uuid",
        json={},
        headers=auth_headers,
    )

    assert response.status_code == 422


def test_list_versions_returns_all_for_org(
    client: TestClient, database: Database, auth_headers: dict[str, str]
) -> None:
    client.post(
        "/administration/key-versions",
        json={},
        headers=auth_headers,
    )
    client.post(
        "/administration/key-versions",
        json={},
        headers=auth_headers,
    )

    response = client.get(
        "/administration/key-versions",
        headers=auth_headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert [v["version"] for v in body] == [1, 2]
    assert all(
        set(v.keys()) == {"id", "version", "from_dt", "until_dt", "removed"}
        for v in body
    )
    assert all(v["removed"] is False for v in body)


def test_list_versions_includes_removed(
    client: TestClient, database: Database, auth_headers: dict[str, str], test_oin: Oin
) -> None:
    created = client.post(
        "/administration/key-versions",
        json={},
        headers=auth_headers,
    ).json()
    HsmKeyVersionService(database).mark_removed(created["id"], test_oin)

    response = client.get(
        "/administration/key-versions",
        headers=auth_headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["removed"] is True


def test_list_versions_empty_for_org_without_versions(
    client: TestClient, database: Database, auth_headers: dict[str, str]
) -> None:

    response = client.get(
        "/administration/key-versions",
        headers=auth_headers,
    )

    assert response.status_code == 200
    assert response.json() == []


def test_list_versions_unknown_org_returns_empty(
    client: TestClient, database: Database, auth_headers: dict[str, str]
) -> None:
    response = client.get(
        "/administration/key-versions",
        headers=auth_headers,
    )

    assert response.status_code == 200
    assert response.json() == []
