from jwcrypto import jwk

import pytest

from app.models.oin import Oin
from app.rid import RidUsage
from app.services.key_resolver import KeyResolver, KeyRequest, AlreadyExistsError
from app.services.org_service import OrgService


def test_resolver_create_and_resolve_roundtrip(
    key_resolver: KeyResolver,
    org_service: OrgService,
    test_public_key: str,
    test_oin: Oin,
) -> None:
    org = org_service.create(
        oin=test_oin,
        name="test org",
        max_key_usage=RidUsage.ReversiblePseudonym,
    )

    # create
    req = KeyRequest(
        scope=["NVI", " lmr "],
        pub_key=test_public_key,
    )
    entry = key_resolver.create(org.id, req.scope, "my-key-id", req.pub_key)

    assert entry.organization_id == org.id
    assert sorted(entry.scope) == ["lmr", "nvi"]

    key = key_resolver.resolve(org.id, "nvi")
    assert isinstance(key, jwk.JWK)
    assert not key.has_private


def test_resolver_get_and_delete(
    key_resolver: KeyResolver,
    org_service: OrgService,
    test_public_key: str,
    test_oin: Oin,
) -> None:
    org = org_service.create(
        oin=test_oin,
        name="test org",
        max_key_usage=RidUsage.ReversiblePseudonym,
    )

    e = key_resolver.create(org.id, ["*"], "my-key-id", test_public_key)

    items = key_resolver.get_by_org(org.id)
    assert len(items) == 1
    assert items[0].id == e.id

    ok = key_resolver.delete(e.id, org.id)
    assert ok is True

    items2 = key_resolver.get_by_org(org.id)
    assert items2 == []


def test_resolver_create_persists_key_id(
    key_resolver: KeyResolver,
    org_service: OrgService,
    test_public_key: str,
    test_oin: Oin,
) -> None:
    org = org_service.create(
        oin=test_oin,
        name="test org",
        max_key_usage=RidUsage.ReversiblePseudonym,
    )

    entry = key_resolver.create(org.id, ["nvi"], "kid-2024", test_public_key)
    assert entry.key_id == "kid-2024"

    items = key_resolver.get_by_org(org.id)
    assert len(items) == 1
    stored = items[0]

    # key_id survives a round-trip through the database
    assert stored is not None
    assert stored.key_id == "kid-2024"
    assert stored.to_dict()["key_id"] == "kid-2024"


def test_resolver_create_without_key_id(
    key_resolver: KeyResolver,
    org_service: OrgService,
    test_public_key: str,
    test_oin: Oin,
) -> None:
    org = org_service.create(
        oin=test_oin,
        name="test org",
        max_key_usage=RidUsage.ReversiblePseudonym,
    )

    entry = key_resolver.create(org.id, ["nvi"], None, test_public_key)
    assert entry.key_id is None

    items = key_resolver.get_by_org(org.id)
    assert len(items) == 1
    stored = items[0]

    assert stored is not None
    assert stored.key_id is None
    # to_dict() represents a missing key_id as an empty string
    assert stored.to_dict()["key_id"] == ""


def test_resolver_update_rejects_duplicate_scope(
    key_resolver: KeyResolver,
    org_service: OrgService,
    test_public_key: str,
    test_oin: Oin,
) -> None:
    org = org_service.create(
        oin=test_oin,
        name="test org",
        max_key_usage=RidUsage.ReversiblePseudonym,
    )

    key_resolver.create(org.id, ["nvi"], "test-key-nvi", test_public_key)
    other = key_resolver.create(org.id, ["rp"], "test-key-rp", test_public_key)

    with pytest.raises(AlreadyExistsError):
        key_resolver.update(other.id, ["nvi"], test_public_key, org.id)
