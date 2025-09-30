from typing import List, Any

import pytest

from app.db.entities.key_entry import KeyEntry

pytestmark = pytest.mark.postgres

TEST_PUBKEY = """-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgG04s6v5MQpqRk7QIUDnfrWqVO3N
K0X0Hx2xqTjbo6ufpk7CaAsSu4zjXylcfEIHPw+jr3OXcIxkdVz00FhXsf1v2rsB
hvOXiM1EeTB7me9x2P6t6SznJA7+SQMLHpvD8oKUzbflMjlyW8fs21og2eQ1YNPi
fRs2Wy5kQi1QlyTzAgMBAAE=
-----END PUBLIC KEY-----"""

def make_entry(org: str="ura:94252", scope: List[str]|None=None, key: str=TEST_PUBKEY) -> KeyEntry:
    if scope is None:
        scope = ["nvi", "lmr"]
    return KeyEntry(organization=org, scope=scope, key=key)

def test_create_and_get(repo: Any, db_wrap: Any) -> None:
    e = make_entry()
    db_wrap.session.add(e)
    db_wrap.session.commit()

    got = repo.get("ura:94252", "nvi")
    assert got is not None
    assert got.entry_id == e.entry_id

    got = repo.get("ura:94252", "prs")
    assert got is None


def test_star_matches_everything(repo: Any, db_wrap: Any) -> None:
    e = make_entry(scope=["*"], key=TEST_PUBKEY)
    db_wrap.session.add(e)
    db_wrap.session.commit()

    # Should match regardless of requested scopes
    for requested in (["anything"], ["nvi"], ["prs"], ["foo"], ["*"]):
        got = repo.get("ura:94252", requested)
        assert got is not None
        assert got.key == TEST_PUBKEY

def test_get_by_org_lists_all(repo: Any, db_wrap: Any) -> None:
    a = make_entry(org="ura:1", scope=["a"])
    b = make_entry(org="ura:1", scope=["b"])
    c = make_entry(org="ura:2", scope=["c"])
    db_wrap.session.add_all([a, b, c])
    db_wrap.session.commit()

    rows = repo.get_by_org("ura:1")
    scopes = sorted([tuple(r.scope) for r in rows])
    assert scopes == [("a",), ("b",)]

def test_update_changes_scope_and_key(repo: Any, db_wrap: Any) -> None:
    e = make_entry(scope=["nvi"], key="OLD")
    db_wrap.session.add(e)
    db_wrap.session.commit()

    updated = repo.update(str(e.entry_id), scope=["prs", "lmr"], pub_key="NEW", max_usage_level="irp")
    db_wrap.session.commit()

    assert updated is not None
    assert sorted(updated.scope) == ["lmr", "prs"]
    assert updated.key == "NEW"
