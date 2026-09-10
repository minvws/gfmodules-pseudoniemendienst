import uuid

from conftest import create_organization, create_signed_jws, generate_rsa_keypair
from jwcrypto.jwk import JWK
from starlette.testclient import TestClient

from app.db.models import OrganizationEntity
from app.db.repositories.personal_id_type_repository import PersonalIdTypeRepository
from app.db.session import DbSession
from app.models.oin import Oin
from app.services.organization_public_key_service import OrganizationPublicKeyService


def _auth_headers(valid_headers: dict[str, str], org_oin: Oin) -> dict[str, str]:
    headers = dict(valid_headers)
    headers["x-gf-sub"] = org_oin.value
    return headers


def test_register_certificate_creates_key_for_authenticated_org(
    client: TestClient,
    valid_headers: dict[str, str],
    persisted_organization: OrganizationEntity,
    organization_public_key_service: OrganizationPublicKeyService,
) -> None:
    private_key, public_key = generate_rsa_keypair()
    signed_jws = create_signed_jws(private_key, persisted_organization.external_id)
    pub_jwk = JWK.from_pem(public_key.encode())

    response = client.post(
        "/administration/keys",
        json={"domains": ["nvi"], "jws": signed_jws},
        headers=_auth_headers(valid_headers, persisted_organization.external_id),
    )

    assert response.status_code == 201
    json_reponse = response.json()
    assert json_reponse["domains"] == ["nvi"]
    assert json_reponse["jwk"] == pub_jwk.export(as_dict=True)

    keys = organization_public_key_service.get_by_org(
        persisted_organization.external_id
    )
    assert keys is not None and len(keys) == 1
    created = keys[0]
    assert created["domains"] == ["nvi"]
    assert created["jwk"] == pub_jwk.export(as_dict=True)


def test_register_certificate_rejects_duplicate_scope_with_conflict(
    client: TestClient,
    valid_headers: dict[str, str],
    persisted_organization: OrganizationEntity,
) -> None:
    private_key, public_key = generate_rsa_keypair()
    signed_jws = create_signed_jws(private_key, persisted_organization.external_id)
    pub_jwk = JWK.from_pem(public_key.encode())

    response = client.post(
        "/administration/keys",
        json={"domains": ["nvi"], "jws": signed_jws},
        headers=_auth_headers(valid_headers, persisted_organization.external_id),
    )
    duplicate = client.post(
        "/administration/keys",
        json={"domains": ["nvi"], "jws": signed_jws},
        headers=_auth_headers(valid_headers, persisted_organization.external_id),
    )

    assert response.status_code == 201
    json_reponse = response.json()
    assert json_reponse["domains"] == ["nvi"]
    assert json_reponse["jwk"] == pub_jwk.export(as_dict=True)
    assert duplicate.status_code == 409
    assert duplicate.json() == {"detail": "key for this org/scope already exists"}


def test_register_certificate_for_unknown_org_is_unauthorized(
    client: TestClient,
    valid_headers: dict[str, str],
) -> None:
    oin = Oin("00000099000000002000")

    private_key, _ = generate_rsa_keypair()
    signed_jws = create_signed_jws(private_key, oin)

    response = client.post(
        "/administration/keys",
        json={"domains": ["nvi"], "jws": signed_jws},
        headers=_auth_headers(valid_headers, oin),
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Organization does not exist"}


def test_list_keys_returns_entries_for_authenticated_org(
    client: TestClient,
    valid_headers: dict[str, str],
    persisted_organization: OrganizationEntity,
) -> None:
    private_key_1, _ = generate_rsa_keypair()
    signed_jws_1 = create_signed_jws(private_key_1, persisted_organization.external_id)

    private_key_2, _ = generate_rsa_keypair()
    signed_jws_2 = create_signed_jws(private_key_2, persisted_organization.external_id)
    client.post(
        "/administration/keys",
        json={"domains": ["domain-1"], "jws": signed_jws_1},
        headers=_auth_headers(valid_headers, persisted_organization.external_id),
    )
    client.post(
        "/administration/keys",
        json={"domains": ["domain-2"], "jws": signed_jws_2},
        headers=_auth_headers(valid_headers, persisted_organization.external_id),
    )
    response = client.get(
        "/administration/keys",
        headers=_auth_headers(valid_headers, persisted_organization.external_id),
    )

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 2
    key_ids = {entry["jwk"]["kid"] for entry in body}

    assert key_ids == {
        JWK.from_pem(private_key_1.encode()).export_public(as_dict=True)["kid"],
        JWK.from_pem(private_key_2.encode()).export_public(as_dict=True)["kid"],
    }


def test_list_keys_for_unknown_org_is_unauthorized(
    client: TestClient,
    valid_headers: dict[str, str],
) -> None:
    response = client.get(
        "/administration/keys",
        headers=_auth_headers(valid_headers, Oin("00000099000000002000")),
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "Organization does not exist"}


def test_list_keys_for_org_without_keys_returns_empty(
    client: TestClient,
    valid_headers: dict[str, str],
    persisted_organization: OrganizationEntity,
) -> None:

    response = client.get(
        "/administration/keys",
        headers=_auth_headers(valid_headers, persisted_organization.external_id),
    )

    assert response.status_code == 200
    assert response.json() == []


def test_delete_key_removes_key_for_authenticated_org(
    client: TestClient,
    valid_headers: dict[str, str],
    persisted_organization: OrganizationEntity,
    organization_public_key_service: OrganizationPublicKeyService,
) -> None:
    private_key, _ = generate_rsa_keypair()
    signed_jws = create_signed_jws(private_key, persisted_organization.external_id)

    create_response = client.post(
        "/administration/keys",
        json={"domains": ["nvi"], "jws": signed_jws},
        headers=_auth_headers(valid_headers, persisted_organization.external_id),
    )
    created = create_response.json()
    delete_response = client.delete(
        f"/administration/keys/{created['id']}",
        headers=_auth_headers(valid_headers, persisted_organization.external_id),
    )

    assert delete_response.status_code == 200
    assert delete_response.json() == {"message": "key deleted"}
    assert organization_public_key_service.get_by_id(created["id"]) is None


def test_delete_key_not_found_is_unauthorized(
    client: TestClient,
    valid_headers: dict[str, str],
    persisted_organization: OrganizationEntity,
) -> None:
    delete_response = client.delete(
        f"/administration/keys/{uuid.uuid4()}",
        headers=_auth_headers(valid_headers, persisted_organization.external_id),
    )

    assert delete_response.status_code == 403
    assert delete_response.json() == {"detail": "forbidden"}


def test_delete_other_org_is_unauthorized(
    client: TestClient,
    valid_headers: dict[str, str],
    persisted_organization: OrganizationEntity,
    db_session: DbSession,
    personal_id_type_repository: PersonalIdTypeRepository,
    organization_public_key_service: OrganizationPublicKeyService,
) -> None:
    other_org = create_organization(
        db_session,
        personal_id_type_repository,
        Oin("00000099000000001000"),
    )
    private_key, _ = generate_rsa_keypair()
    signed_jws = create_signed_jws(private_key, persisted_organization.external_id)

    create_response = client.post(
        "/administration/keys",
        json={"domains": ["nvi"], "jws": signed_jws},
        headers=_auth_headers(valid_headers, persisted_organization.external_id),
    )
    created = create_response.json()

    response = client.delete(
        f"/administration/keys/{created['id']}",
        headers=_auth_headers(valid_headers, other_org.external_id),
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "forbidden"}
    assert organization_public_key_service.get_by_id(created["id"]) is not None
