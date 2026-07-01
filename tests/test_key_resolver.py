from jwcrypto import jwk

from app.models.oin import Oin
from app.rid import RidUsage
from app.services.key_resolver import KeyResolver, KeyRequest
from app.services.org_service import OrgService

TEST_PUBKEY = """-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgG04s6v5MQpqRk7QIUDnfrWqVO3N
K0X0Hx2xqTjbo6ufpk7CaAsSu4zjXylcfEIHPw+jr3OXcIxkdVz00FhXsf1v2rsB
hvOXiM1EeTB7me9x2P6t6SznJA7+SQMLHpvD8oKUzbflMjlyW8fs21og2eQ1YNPi
fRs2Wy5kQi1QlyTzAgMBAAE=
-----END PUBLIC KEY-----"""

TEST_OIN = Oin("00000099000000001000")
TEST_OIN_WITH_PREFIX = f"oin:{TEST_OIN}"


def test_resolver_create_and_resolve_roundtrip(
    key_resolver: KeyResolver, org_service: OrgService
) -> None:
    org = org_service.create(
        oin=TEST_OIN,
        name="test org",
        max_key_usage=RidUsage.ReversiblePseudonym,
    )

    # create
    req = KeyRequest(
        organization=TEST_OIN_WITH_PREFIX,
        scope=["NVI", " lmr "],
        pub_key=TEST_PUBKEY,
    )
    entry = key_resolver.create(org.id, req.scope, "my-key-id", req.pub_key)

    assert entry.organization_id == org.id
    assert sorted(entry.scope) == ["lmr", "nvi"]

    key = key_resolver.resolve(org.id, "nvi")
    assert isinstance(key, jwk.JWK)
    assert not key.has_private

    data = key_resolver.get_by_id(entry.id)
    assert data is not None
    assert data.to_dict()["oin"] == TEST_OIN.value


def test_resolver_get_and_delete(
    key_resolver: KeyResolver, org_service: OrgService
) -> None:
    org = org_service.create(
        oin=TEST_OIN,
        name="test org",
        max_key_usage=RidUsage.ReversiblePseudonym,
    )

    e = key_resolver.create(org.id, ["*"], "my-key-id", TEST_PUBKEY)

    items = key_resolver.get_by_org(org.id) or []
    assert len(items) == 1
    assert items[0].id == e.id

    by_id = key_resolver.get_by_id(e.id)
    assert by_id is not None

    ok = key_resolver.delete(e.id)
    assert ok is True

    items2 = key_resolver.get_by_org(org.id)
    assert items2 == []


def test_resolver_create_persists_key_id(
    key_resolver: KeyResolver, org_service: OrgService
) -> None:
    org = org_service.create(
        oin=TEST_OIN,
        name="test org",
        max_key_usage=RidUsage.ReversiblePseudonym,
    )

    entry = key_resolver.create(org.id, ["nvi"], "kid-2024", TEST_PUBKEY)
    assert entry.key_id == "kid-2024"

    # key_id survives a round-trip through the database
    stored = key_resolver.get_by_id(entry.id)
    assert stored is not None
    assert stored.key_id == "kid-2024"
    assert stored.to_dict()["key_id"] == "kid-2024"


def test_resolver_create_without_key_id(
    key_resolver: KeyResolver, org_service: OrgService
) -> None:
    org = org_service.create(
        oin=TEST_OIN,
        name="test org",
        max_key_usage=RidUsage.ReversiblePseudonym,
    )

    entry = key_resolver.create(org.id, ["nvi"], None, TEST_PUBKEY)
    assert entry.key_id is None

    stored = key_resolver.get_by_id(entry.id)
    assert stored is not None
    assert stored.key_id is None
    # to_dict() represents a missing key_id as an empty string
    assert stored.to_dict()["key_id"] == ""
