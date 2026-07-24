import uuid
from typing import Dict

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from starlette.testclient import TestClient

from app import container
from app.models.oin import Oin
from app.rid import RidUsage
from app.services.key_resolver import KeyResolver
from app.services.org_service import OrgService


def _generate_rsa_public_key() -> str:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return public_key.decode("ascii")


def _auth_headers(valid_headers: Dict[str, str], org_oin: Oin) -> Dict[str, str]:
    headers = dict(valid_headers)
    headers["x-gf-sub"] = org_oin.value
    return headers


def test_register_certificate_creates_key_for_authenticated_org(
    app: FastAPI,
    client: TestClient,
    org_service: OrgService,
    key_resolver: KeyResolver,
    valid_headers: Dict[str, str],
) -> None:
    auth_org = org_service.create(
        Oin("00000099000000001000"),
        "MyOrg A",
        RidUsage.IrreversiblePseudonym,
    )

    public_key = _generate_rsa_public_key()

    class _FakeMtlsService:
        def get_mtls_pub_key(self, _request: object) -> str:
            return public_key

    app.dependency_overrides[container.get_mtls_service] = lambda: _FakeMtlsService()

    try:
        response = client.post(
            "/administration/register/certificate",
            json={"scope": ["nvi"], "key_id": "k1"},
            headers=_auth_headers(valid_headers, auth_org.oin),
        )
    finally:
        app.dependency_overrides.pop(container.get_mtls_service, None)

    assert response.status_code == 201
    assert response.json() == {"message": "Key created successfully"}

    keys = key_resolver.get_by_org(auth_org.id)
    assert keys is not None and len(keys) == 1
    created = keys[0]
    assert created.scope == ["nvi"]
    assert created.key_id == "k1"
    assert created.key_data == public_key


def test_register_certificate_rejects_duplicate_scope_with_conflict(
    app: FastAPI,
    client: TestClient,
    org_service: OrgService,
    valid_headers: Dict[str, str],
) -> None:
    auth_org = org_service.create(
        Oin("00000099000000001000"),
        "MyOrg A",
        RidUsage.IrreversiblePseudonym,
    )

    public_key = _generate_rsa_public_key()

    class _FakeMtlsService:
        def get_mtls_pub_key(self, _request: object) -> str:
            return public_key

    app.dependency_overrides[container.get_mtls_service] = lambda: _FakeMtlsService()

    try:
        response = client.post(
            "/administration/register/certificate",
            json={"scope": ["nvi"], "key_id": "k1"},
            headers=_auth_headers(valid_headers, auth_org.oin),
        )
        duplicate = client.post(
            "/administration/register/certificate",
            json={"scope": ["nvi"], "key_id": "k1"},
            headers=_auth_headers(valid_headers, auth_org.oin),
        )
    finally:
        app.dependency_overrides.pop(container.get_mtls_service, None)

    assert response.status_code == 201
    assert response.json() == {"message": "Key created successfully"}
    assert duplicate.status_code == 409
    assert duplicate.json() == {"detail": "key for this org/scope already exists"}


def test_register_certificate_for_unknown_org_is_unauthorized(
    app: FastAPI,
    client: TestClient,
    valid_headers: Dict[str, str],
) -> None:
    class _FakeMtlsService:
        def get_mtls_pub_key(self, _request: object) -> str:
            return _generate_rsa_public_key()

    app.dependency_overrides[container.get_mtls_service] = lambda: _FakeMtlsService()
    try:
        response = client.post(
            "/administration/register/certificate",
            json={"scope": ["nvi"], "key_id": "k1"},
            headers=_auth_headers(valid_headers, Oin("00000099000000002000")),
        )
    finally:
        app.dependency_overrides.pop(container.get_mtls_service, None)

    assert response.status_code == 401
    assert response.json() == {"detail": "unauthorized"}


def test_list_keys_returns_entries_for_authenticated_org(
    client: TestClient,
    org_service: OrgService,
    key_resolver: KeyResolver,
    valid_headers: Dict[str, str],
) -> None:
    auth_org = org_service.create(
        Oin("00000099000000001000"),
        "MyOrg A",
        RidUsage.IrreversiblePseudonym,
    )
    key_a = key_resolver.create(auth_org.id, ["nvi"], None, _generate_rsa_public_key())
    key_b = key_resolver.create(auth_org.id, ["brp"], "k2", _generate_rsa_public_key())

    response = client.get(
        "/administration/keys", headers=_auth_headers(valid_headers, auth_org.oin)
    )

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 2
    key_ids = {entry["id"] for entry in body}
    assert key_ids == {str(key_a.id), str(key_b.id)}


def test_list_keys_for_unknown_org_is_unauthorized(
    client: TestClient,
    valid_headers: Dict[str, str],
) -> None:
    response = client.get(
        "/administration/keys",
        headers=_auth_headers(valid_headers, Oin("00000099000000002000")),
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "unauthorized"}


def test_list_keys_for_org_without_keys_returns_empty(
    client: TestClient,
    org_service: OrgService,
    valid_headers: Dict[str, str],
) -> None:
    auth_org = org_service.create(
        Oin("00000099000000001000"),
        "MyOrg A",
        RidUsage.IrreversiblePseudonym,
    )

    response = client.get(
        "/administration/keys", headers=_auth_headers(valid_headers, auth_org.oin)
    )

    assert response.status_code == 200
    assert response.json() == []


def test_update_key_updates_scope_and_data_for_authenticated_org(
    client: TestClient,
    org_service: OrgService,
    key_resolver: KeyResolver,
    valid_headers: Dict[str, str],
) -> None:
    auth_org = org_service.create(
        Oin("00000099000000001000"),
        "MyOrg A",
        RidUsage.IrreversiblePseudonym,
    )
    old_key_data = _generate_rsa_public_key()
    created = key_resolver.create(auth_org.id, ["nvi"], "old", old_key_data)

    new_key_data = _generate_rsa_public_key()

    response = client.put(
        f"/administration/keys/{created.id}",
        json={
            "scope": ["nvi", "brp"],
            "pub_key": new_key_data,
        },
        headers=_auth_headers(valid_headers, auth_org.oin),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == str(created.id)
    assert body["scope"] == ["brp", "nvi"]
    assert body["key_data"] == new_key_data
    assert body["key_id"] == "old"

    updated = key_resolver.get_by_id(created.id)
    assert updated is not None
    assert updated.key_data == new_key_data


def test_update_unknown_key_is_unauthorized(
    client: TestClient,
    org_service: OrgService,
    valid_headers: Dict[str, str],
) -> None:
    auth_org = org_service.create(
        Oin("00000099000000001000"),
        "MyOrg A",
        RidUsage.IrreversiblePseudonym,
    )

    response = client.put(
        f"/administration/keys/{uuid.uuid4()}",
        json={
            "scope": ["nvi"],
            "pub_key": _generate_rsa_public_key(),
        },
        headers=_auth_headers(valid_headers, auth_org.oin),
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "forbidden"}


def test_update_other_org_is_unauthorized(
    client: TestClient,
    org_service: OrgService,
    key_resolver: KeyResolver,
    valid_headers: Dict[str, str],
) -> None:
    owner_org = org_service.create(
        Oin("00000099000000001000"),
        "MyOrg A",
        RidUsage.IrreversiblePseudonym,
    )
    auth_org = org_service.create(
        Oin("00000099000000002000"),
        "MyOrg B",
        RidUsage.IrreversiblePseudonym,
    )
    created = key_resolver.create(
        owner_org.id, ["nvi"], None, _generate_rsa_public_key()
    )

    response = client.put(
        f"/administration/keys/{created.id}",
        json={
            "scope": ["nvi"],
            "pub_key": _generate_rsa_public_key(),
        },
        headers=_auth_headers(valid_headers, auth_org.oin),
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "forbidden"}

    existing = key_resolver.get_by_id(created.id)
    assert existing is not None
    assert existing.organization_id == owner_org.id


def test_delete_key_removes_key_for_authenticated_org(
    client: TestClient,
    org_service: OrgService,
    key_resolver: KeyResolver,
    valid_headers: Dict[str, str],
) -> None:
    auth_org = org_service.create(
        Oin("00000099000000001000"),
        "MyOrg A",
        RidUsage.IrreversiblePseudonym,
    )
    created = key_resolver.create(
        auth_org.id, ["nvi"], None, _generate_rsa_public_key()
    )

    response = client.delete(
        f"/administration/keys/{created.id}",
        headers=_auth_headers(valid_headers, auth_org.oin),
    )

    assert response.status_code == 200
    assert response.json() == {"message": "key deleted"}
    assert key_resolver.get_by_id(created.id) is None


def test_delete_key_not_found_is_unauthorized(
    client: TestClient,
    org_service: OrgService,
    valid_headers: Dict[str, str],
) -> None:
    auth_org = org_service.create(
        Oin("00000099000000001000"),
        "MyOrg A",
        RidUsage.IrreversiblePseudonym,
    )

    response = client.delete(
        f"/administration/keys/{uuid.uuid4()}",
        headers=_auth_headers(valid_headers, auth_org.oin),
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "forbidden"}


def test_delete_other_org_is_unauthorized(
    client: TestClient,
    org_service: OrgService,
    key_resolver: KeyResolver,
    valid_headers: Dict[str, str],
) -> None:
    owner_org = org_service.create(
        Oin("00000099000000001000"),
        "MyOrg A",
        RidUsage.IrreversiblePseudonym,
    )
    auth_org = org_service.create(
        Oin("00000099000000002000"),
        "MyOrg B",
        RidUsage.IrreversiblePseudonym,
    )
    created = key_resolver.create(
        owner_org.id, ["nvi"], None, _generate_rsa_public_key()
    )

    response = client.delete(
        f"/administration/keys/{created.id}",
        headers=_auth_headers(valid_headers, auth_org.oin),
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "forbidden"}
    assert key_resolver.get_by_id(created.id) is not None


def test_update_rejects_invalid_key_id_with_422(
    client: TestClient,
    org_service: OrgService,
    valid_headers: Dict[str, str],
) -> None:
    auth_org = org_service.create(
        Oin("00000099000000001000"),
        "MyOrg A",
        RidUsage.IrreversiblePseudonym,
    )

    response = client.put(
        "/administration/keys/not-a-uuid",
        json={
            "scope": ["nvi"],
            "pub_key": _generate_rsa_public_key(),
        },
        headers=_auth_headers(valid_headers, auth_org.oin),
    )

    assert response.status_code == 422


def test_update_rejects_extra_field_with_422(
    client: TestClient,
    org_service: OrgService,
    key_resolver: KeyResolver,
    valid_headers: Dict[str, str],
) -> None:
    auth_org = org_service.create(
        Oin("00000099000000001000"),
        "MyOrg A",
        RidUsage.IrreversiblePseudonym,
    )
    created = key_resolver.create(
        auth_org.id, ["nvi"], None, _generate_rsa_public_key()
    )

    response = client.put(
        f"/administration/keys/{created.id}",
        json={
            "scope": ["nvi"],
            "pub_key": _generate_rsa_public_key(),
            "organization": auth_org.oin.value,
        },
        headers=_auth_headers(valid_headers, auth_org.oin),
    )

    assert response.status_code == 422
    detail = response.json().get("detail", [])
    assert isinstance(detail, list)
    assert any(item.get("type") == "extra_forbidden" for item in detail)
