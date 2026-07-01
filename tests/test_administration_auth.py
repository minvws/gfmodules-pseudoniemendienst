from starlette.testclient import TestClient

from app.db.db import Database
from app.models.oin import Oin
from app.rid import RidUsage
from app.services.hsm_key_version_service import HsmKeyVersionService
from app.services.key_resolver import KeyResolver
from app.services.org_service import OrgService

TEST_CALLER_OIN = Oin("00000099000000001000")
TEST_OTHER_OIN = Oin("00000099000000002000")
TEST_AUDIENCE = "prs.service"
TEST_PUB_KEY = """-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgG04s6v5MQpqRk7QIUDnfrWqVO3N
K0X0Hx2xqTjbo6ufpk7CaAsSu4zjXylcfEIHPw+jr3OXcIxkdVz00FhXsf1v2rsB
hvOXiM1EeTB7me9x2P6t6SznJA7+SQMLHpvD8oKUzbflMjlyW8fs21og2eQ1YNPi
fRs2Wy5kQi1QlyTzAgMBAAE=
-----END PUBLIC KEY-----"""


def _headers(oin: Oin) -> dict[str, str]:
    return {"x-gf-oin": oin.value, "x-gf-audience": TEST_AUDIENCE}


def test_admin_key_version_create_uses_authenticated_oin(
    client: TestClient,
) -> None:
    response = client.post(
        "/administration/key-versions",
        json={},
        headers=_headers(TEST_CALLER_OIN),
    )

    assert response.status_code == 201
    assert response.json()["oin"] == TEST_CALLER_OIN.value


def test_admin_key_version_list_without_oin_path(
    client: TestClient,
) -> None:
    response = client.get(
        f"/administration/key-versions/{TEST_OTHER_OIN.value}",
        headers=_headers(TEST_CALLER_OIN),
    )

    assert response.status_code == 405


def test_admin_key_version_update_other_org_returns_not_found(
    client: TestClient, database: Database
) -> None:
    service = HsmKeyVersionService(database)
    entry = service.create_version(TEST_OTHER_OIN)

    response = client.put(
        f"/administration/key-versions/{entry.id}",
        json={},
        headers=_headers(TEST_CALLER_OIN),
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "key version not found"}


def test_admin_key_list_blocks_oin_mismatch(
    client: TestClient,
    org_service: OrgService,
) -> None:
    org_service.create(
        TEST_CALLER_OIN,
        f"Org {TEST_CALLER_OIN}",
        RidUsage.IrreversiblePseudonym,
    )
    org_service.create(
        TEST_OTHER_OIN,
        f"Org {TEST_OTHER_OIN}",
        RidUsage.IrreversiblePseudonym,
    )

    response = client.get("/administration/keys", headers=_headers(TEST_CALLER_OIN))

    assert response.status_code == 404
    assert response.json() == {"detail": "no keys found"}


def test_admin_key_list_returns_oin(
    client: TestClient,
    org_service: OrgService,
    key_resolver: KeyResolver,
) -> None:
    org = org_service.create(
        TEST_CALLER_OIN,
        f"Org {TEST_CALLER_OIN}",
        RidUsage.IrreversiblePseudonym,
    )
    key_entry = key_resolver.create(
        org.id,
        ["nvi"],
        "test-key",
        TEST_PUB_KEY,
    )

    response = client.get("/administration/keys", headers=_headers(TEST_CALLER_OIN))

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["id"] == str(key_entry.id)
    assert body[0]["oin"] == TEST_CALLER_OIN.value


def test_admin_key_update_blocks_other_org(
    client: TestClient,
    org_service: OrgService,
    key_resolver: KeyResolver,
) -> None:
    owner = org_service.create(
        TEST_OTHER_OIN,
        f"Org {TEST_OTHER_OIN}",
        RidUsage.IrreversiblePseudonym,
    )
    org_service.create(
        TEST_CALLER_OIN,
        f"Org {TEST_CALLER_OIN}",
        RidUsage.IrreversiblePseudonym,
    )
    key_entry = key_resolver.create(
        owner.id,
        ["nvi"],
        "test-key",
        TEST_PUB_KEY,
    )

    response = client.put(
        f"/administration/keys/{key_entry.id}",
        json={
            "scope": ["nvi"],
            "pub_key": TEST_PUB_KEY,
        },
        headers=_headers(TEST_CALLER_OIN),
    )

    assert response.status_code == 403


def test_admin_key_delete_blocks_other_org(
    client: TestClient,
    org_service: OrgService,
    key_resolver: KeyResolver,
) -> None:
    owner = org_service.create(
        TEST_OTHER_OIN,
        f"Org {TEST_OTHER_OIN}",
        RidUsage.IrreversiblePseudonym,
    )
    org_service.create(
        TEST_CALLER_OIN,
        f"Org {TEST_CALLER_OIN}",
        RidUsage.IrreversiblePseudonym,
    )
    key_entry = key_resolver.create(
        owner.id,
        ["nvi"],
        "test-key",
        TEST_PUB_KEY,
    )

    response = client.delete(
        f"/administration/keys/{key_entry.id}",
        headers=_headers(TEST_CALLER_OIN),
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "forbidden"}
