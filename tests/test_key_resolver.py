import uuid

from jwcrypto import jwk

from app.services.key_resolver import KeyResolver, KeyRequest

TEST_PUBKEY = """-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgG04s6v5MQpqRk7QIUDnfrWqVO3N
K0X0Hx2xqTjbo6ufpk7CaAsSu4zjXylcfEIHPw+jr3OXcIxkdVz00FhXsf1v2rsB
hvOXiM1EeTB7me9x2P6t6SznJA7+SQMLHpvD8oKUzbflMjlyW8fs21og2eQ1YNPi
fRs2Wy5kQi1QlyTzAgMBAAE=
-----END PUBLIC KEY-----"""

def test_resolver_create_and_resolve_roundtrip(key_resolver: KeyResolver) -> None:
    org_id = uuid.uuid4()

    # create
    req = KeyRequest(organization="ura:94252", scope=["NVI", " lmr "], pub_key=TEST_PUBKEY)
    entry = key_resolver.create(org_id, req.scope, req.pub_key)

    assert entry.organization_id == org_id
    assert sorted(entry.scope) == ["lmr", "nvi"]

    key = key_resolver.resolve(org_id, "nvi")
    assert isinstance(key, jwk.JWK)
    assert not key.has_private

def test_resolver_get_and_delete(key_resolver: KeyResolver) -> None:
    org_id = uuid.uuid4()
    e = key_resolver.create(org_id, ["*"], TEST_PUBKEY)

    items = key_resolver.get_by_org(org_id) or []
    assert len(items) == 1
    assert items[0].id == e.id

    by_id = key_resolver.get_by_id(e.id)
    assert by_id is not None

    ok = key_resolver.delete(e.id)
    assert ok is True

    items2 = key_resolver.get_by_org(org_id)
    assert items2 == []
