from typing import Any

import pytest
from jwcrypto import jwk

from app.services.key_resolver import KeyResolver, KeyRequest

pytestmark = pytest.mark.postgres

TEST_PUBKEY = """-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgG04s6v5MQpqRk7QIUDnfrWqVO3N
K0X0Hx2xqTjbo6ufpk7CaAsSu4zjXylcfEIHPw+jr3OXcIxkdVz00FhXsf1v2rsB
hvOXiM1EeTB7me9x2P6t6SznJA7+SQMLHpvD8oKUzbflMjlyW8fs21og2eQ1YNPi
fRs2Wy5kQi1QlyTzAgMBAAE=
-----END PUBLIC KEY-----"""

def test_resolver_create_and_resolve_roundtrip(fake_db: Any) -> None:
    resolver = KeyResolver(fake_db)

    # create
    req = KeyRequest(organization="ura:94252", scope=["NVI", " lmr "], pub_key=TEST_PUBKEY)
    entry = resolver.create(req.organization, req.scope, req.pub_key)

    assert entry.organization == "ura:94252"
    assert sorted(entry.scope) == ["lmr", "nvi"]

    key = resolver.resolve("ura:94252", "nvi")
    assert isinstance(key, jwk.JWK)
    assert not key.has_private

def test_resolver_get_and_delete(fake_db: Any) -> None:
    resolver = KeyResolver(fake_db)
    e = resolver.create("ura:x", ["*"], TEST_PUBKEY)
    print(e.entry_id)

    items = resolver.get_by_org("ura:x") or []
    assert len(items) == 1
    assert items[0].entry_id == e.entry_id

    by_id = resolver.get_by_id(str(e.entry_id))
    assert by_id is not None

    ok = resolver.delete(str(e.entry_id))
    assert ok is True

    items2 = resolver.get_by_org("ura:x")
    assert items2 == []
