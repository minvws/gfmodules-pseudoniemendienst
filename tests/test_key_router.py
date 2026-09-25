import uuid

import pytest
from conftest import create_organization, create_signed_jws, generate_rsa_keypair
from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS
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


@pytest.mark.parametrize("algorithm", ["RS256", "PS256"])
def test_register_certificate_creates_key_for_authenticated_org(
    algorithm: str,
    client: TestClient,
    valid_headers: dict[str, str],
    persisted_organization: OrganizationEntity,
    organization_public_key_service: OrganizationPublicKeyService,
) -> None:
    private_key, public_key = generate_rsa_keypair()
    signed_jws = create_signed_jws(
        private_key,
        persisted_organization.external_id,
        algorithm=algorithm,
    )
    pub_jwk = JWK.from_pem(public_key.encode())

    assert JWS.from_jose_token(signed_jws).jose_header["alg"] == algorithm

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


def test_register_certificate_for_unknown_org_is_forbidden(
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

    assert response.status_code == 403
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


def test_list_keys_for_unknown_org_is_forbidden(
    client: TestClient,
    valid_headers: dict[str, str],
) -> None:
    response = client.get(
        "/administration/keys",
        headers=_auth_headers(valid_headers, Oin("00000099000000002000")),
    )

    assert response.status_code == 403
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


def test_delete_key_not_found_is_not_found(
    client: TestClient,
    valid_headers: dict[str, str],
    persisted_organization: OrganizationEntity,
) -> None:
    delete_response = client.delete(
        f"/administration/keys/{uuid.uuid4()}",
        headers=_auth_headers(valid_headers, persisted_organization.external_id),
    )

    assert delete_response.status_code == 404
    assert delete_response.json() == {"detail": "public key not found"}


def test_delete_other_org_key_is_not_found(
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

    assert response.status_code == 404
    assert response.json() == {"detail": "public key not found"}
    assert organization_public_key_service.get_by_id(created["id"]) is not None


def _create_key(
    client: TestClient,
    valid_headers: dict[str, str],
    organization: OrganizationEntity,
    domains: list[str],
) -> tuple[dict[str, str], str]:
    private_key, _ = generate_rsa_keypair()
    signed_jws = create_signed_jws(private_key, organization.external_id)
    response = client.post(
        "/administration/keys",
        json={"domains": domains, "jws": signed_jws},
        headers=_auth_headers(valid_headers, organization.external_id),
    )
    assert response.status_code == 201
    return response.json(), private_key


def test_update_key_replaces_domains_and_jwk(
    client: TestClient,
    valid_headers: dict[str, str],
    persisted_organization: OrganizationEntity,
    organization_public_key_service: OrganizationPublicKeyService,
) -> None:
    created, _ = _create_key(client, valid_headers, persisted_organization, ["nvi"])
    new_private_key, new_public_key = generate_rsa_keypair()

    response = client.put(
        f"/administration/keys/{created['id']}",
        json={
            "domains": ["nvi", "lmr"],
            "jws": create_signed_jws(
                new_private_key, persisted_organization.external_id
            ),
        },
        headers=_auth_headers(valid_headers, persisted_organization.external_id),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == created["id"]
    assert body["domains"] == ["nvi", "lmr"]
    assert body["jwk"] == JWK.from_pem(new_public_key.encode()).export(as_dict=True)
    stored = organization_public_key_service.get_by_id(uuid.UUID(created["id"]))
    assert stored is not None and stored.domains == ["nvi", "lmr"]


def test_update_unknown_key_is_not_found(
    client: TestClient,
    valid_headers: dict[str, str],
    persisted_organization: OrganizationEntity,
) -> None:
    private_key, _ = generate_rsa_keypair()

    response = client.put(
        f"/administration/keys/{uuid.uuid4()}",
        json={
            "domains": ["nvi"],
            "jws": create_signed_jws(private_key, persisted_organization.external_id),
        },
        headers=_auth_headers(valid_headers, persisted_organization.external_id),
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "public key not found"}


def test_update_other_org_key_is_not_found(
    client: TestClient,
    valid_headers: dict[str, str],
    persisted_organization: OrganizationEntity,
    db_session: DbSession,
    personal_id_type_repository: PersonalIdTypeRepository,
) -> None:
    other_org = create_organization(
        db_session, personal_id_type_repository, Oin("00000099000000001000")
    )
    created, _ = _create_key(client, valid_headers, persisted_organization, ["nvi"])
    private_key, _ = generate_rsa_keypair()

    response = client.put(
        f"/administration/keys/{created['id']}",
        json={
            "domains": ["nvi"],
            "jws": create_signed_jws(private_key, other_org.external_id),
        },
        headers=_auth_headers(valid_headers, other_org.external_id),
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "public key not found"}


def test_update_key_with_invalid_jws_is_unprocessable(
    client: TestClient,
    valid_headers: dict[str, str],
    persisted_organization: OrganizationEntity,
) -> None:
    created, _ = _create_key(client, valid_headers, persisted_organization, ["nvi"])

    response = client.put(
        f"/administration/keys/{created['id']}",
        json={"domains": ["nvi"], "jws": "x" * 64},
        headers=_auth_headers(valid_headers, persisted_organization.external_id),
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "JWS invalid"}


def test_update_key_to_domain_of_other_key_is_conflict(
    client: TestClient,
    valid_headers: dict[str, str],
    persisted_organization: OrganizationEntity,
) -> None:
    _create_key(client, valid_headers, persisted_organization, ["nvi"])
    second, _ = _create_key(client, valid_headers, persisted_organization, ["lmr"])
    private_key, _ = generate_rsa_keypair()

    response = client.put(
        f"/administration/keys/{second['id']}",
        json={
            "domains": ["nvi"],
            "jws": create_signed_jws(private_key, persisted_organization.external_id),
        },
        headers=_auth_headers(valid_headers, persisted_organization.external_id),
    )

    assert response.status_code == 409
