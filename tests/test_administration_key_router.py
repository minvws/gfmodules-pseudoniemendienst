from starlette.testclient import TestClient

from app.rid import RidUsage
from app.services.key_resolver import KeyResolver
from app.services.org_service import OrgService
from app.models.oin import Oin


def test_administration_key_list_returns_only_own_keys(
    client: TestClient,
    org_service: OrgService,
    key_resolver: KeyResolver,
    test_oin: Oin,
    test_other_oin: Oin,
    auth_headers: dict[str, str],
    test_public_key: str,
) -> None:
    caller_org = org_service.create(
        test_oin,
        f"Org {test_oin}",
        RidUsage.IrreversiblePseudonym,
    )
    other_org = org_service.create(
        test_other_oin,
        f"Org {test_other_oin}",
        RidUsage.IrreversiblePseudonym,
    )

    key_resolver.create(
        other_org.id,
        ["nvi"],
        "test-other-key",
        test_public_key,
    )

    caller_key = key_resolver.create(
        caller_org.id,
        ["nvi"],
        "test-key",
        test_public_key,
    )

    response = client.get("/administration/keys", headers=auth_headers)

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0] == {
        "id": str(caller_key.id),
        "scope": ["nvi"],
        "key_data": test_public_key,
        "key_id": caller_key.key_id,
    }


def test_administration_key_list_without_keys_returns_empty_list(
    client: TestClient,
    org_service: OrgService,
    test_oin: Oin,
    auth_headers: dict[str, str],
) -> None:
    org_service.create(
        test_oin,
        f"Org {test_oin}",
        RidUsage.IrreversiblePseudonym,
    )

    response = client.get("/administration/keys", headers=auth_headers)

    assert response.status_code == 200
    assert response.json() == []


def test_administration_key_list_returns_key_fields(
    client: TestClient,
    org_service: OrgService,
    key_resolver: KeyResolver,
    test_oin: Oin,
    auth_headers: dict[str, str],
    test_public_key: str,
) -> None:
    org = org_service.create(
        test_oin,
        f"Org {test_oin}",
        RidUsage.IrreversiblePseudonym,
    )
    key_entry = key_resolver.create(
        org.id,
        ["nvi"],
        "test-key",
        test_public_key,
    )

    response = client.get("/administration/keys", headers=auth_headers)

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0] == {
        "id": str(key_entry.id),
        "scope": ["nvi"],
        "key_data": test_public_key,
        "key_id": key_entry.key_id,
    }


def test_administration_key_update_blocks_other_org(
    client: TestClient,
    org_service: OrgService,
    key_resolver: KeyResolver,
    test_oin: Oin,
    test_other_oin: Oin,
    auth_headers: dict[str, str],
    test_public_key: str,
) -> None:
    owner = org_service.create(
        test_other_oin,
        f"Org {test_other_oin}",
        RidUsage.IrreversiblePseudonym,
    )
    org_service.create(
        test_oin,
        f"Org {test_oin}",
        RidUsage.IrreversiblePseudonym,
    )
    key_entry = key_resolver.create(
        owner.id,
        ["nvi"],
        "test-key",
        test_public_key,
    )

    response = client.put(
        f"/administration/keys/{key_entry.id}",
        json={
            "scope": ["nvi"],
            "pub_key": test_public_key,
        },
        headers=auth_headers,
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "key not found"}


def test_administration_key_delete_blocks_other_org(
    client: TestClient,
    org_service: OrgService,
    key_resolver: KeyResolver,
    test_oin: Oin,
    test_other_oin: Oin,
    auth_headers: dict[str, str],
    test_public_key: str,
) -> None:
    owner = org_service.create(
        test_other_oin,
        f"Org {test_other_oin}",
        RidUsage.IrreversiblePseudonym,
    )
    org_service.create(
        test_oin,
        f"Org {test_oin}",
        RidUsage.IrreversiblePseudonym,
    )
    key_entry = key_resolver.create(
        owner.id,
        ["nvi"],
        "test-key",
        test_public_key,
    )

    response = client.delete(
        f"/administration/keys/{key_entry.id}",
        headers=auth_headers,
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "key not found"}


def test_administration_key_update_rejects_invalid_key_id(
    client: TestClient,
    org_service: OrgService,
    test_oin: Oin,
    auth_headers: dict[str, str],
    test_public_key: str,
) -> None:
    org_service.create(
        test_oin,
        f"Org {test_oin}",
        RidUsage.IrreversiblePseudonym,
    )

    response = client.put(
        "/administration/keys/not-a-uuid",
        json={"scope": ["nvi"], "pub_key": test_public_key},
        headers=auth_headers,
    )

    assert response.status_code == 422


def test_administration_key_delete_rejects_invalid_key_id(
    client: TestClient,
    org_service: OrgService,
    test_oin: Oin,
    auth_headers: dict[str, str],
) -> None:
    org_service.create(
        test_oin,
        f"Org {test_oin}",
        RidUsage.IrreversiblePseudonym,
    )

    response = client.delete(
        "/administration/keys/not-a-uuid",
        headers=auth_headers,
    )

    assert response.status_code == 422


def test_administration_key_update_rejects_duplicate_scope(
    client: TestClient,
    org_service: OrgService,
    key_resolver: KeyResolver,
    test_oin: Oin,
    auth_headers: dict[str, str],
    test_public_key: str,
) -> None:
    owner = org_service.create(
        test_oin,
        f"Org {test_oin}",
        RidUsage.IrreversiblePseudonym,
    )

    key_resolver.create(
        owner.id,
        ["nvi"],
        "test-key-first",
        test_public_key,
    )
    second = key_resolver.create(
        owner.id,
        ["rp"],
        "test-key-second",
        test_public_key,
    )

    response = client.put(
        f"/administration/keys/{second.id}",
        json={
            "scope": ["nvi"],
            "pub_key": test_public_key,
        },
        headers=auth_headers,
    )

    assert response.status_code == 409
    assert response.json() == {"detail": "key for this org/scope already exists"}
