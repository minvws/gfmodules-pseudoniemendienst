import base64
import json
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from app.config import ConfigOprf
from app.db.db import Database
from app.db.entities.hsm_key_versions import HsmKeyVersion
from app.db.entities.organization import Organization
from app.db.repositories.hsm_key_version_repository import (
    HsmKeyVersionCreateConflictError,
)
from app.models.oin import Oin, RecipientOrganizationOin
from app.services.org_service import OrgService
from app.services.hsm_key_version_service import (
    HsmKeyVersionService,
    HsmKeyVersionNotFoundError,
)
from app.services.oprf.oprf_service import OprfService


TEST_OIN = Oin("00000099000000001000")
TEST_OIN_WITH_PREFIX = f"oin:{TEST_OIN}"
TEST_OIN_111 = Oin("00000099000000011000")
TEST_OIN_222 = Oin("00000099000000022000")
TEST_OIN_333 = Oin("00000099000000033000")
TEST_OIN_444 = Oin("00000099000000044000")
TEST_OIN_555 = Oin("00000099000000055000")
TEST_OIN_78000 = Oin("00000000012345678000")
TEST_OIN_79000 = Oin("00000000012345679000")
TEST_OIN_99999 = Oin("00000099000000099000")


@pytest.fixture(autouse=True)
def ensure_service_organizations(database: Database) -> None:
    """Ensure organizations required by this module are present."""
    with database.get_db_session() as session:
        oins = (
            TEST_OIN,
            TEST_OIN_111,
            TEST_OIN_222,
            TEST_OIN_333,
            TEST_OIN_444,
            TEST_OIN_555,
            TEST_OIN_78000,
            TEST_OIN_79000,
        )

        for oin in oins:
            if (
                session.query(Organization).filter(Organization.oin == oin).first()
                is not None
            ):
                continue

            session.add(Organization(oin=oin, name=f"Org {oin}", max_rid_usage="irp"))

        session.commit()


def _add(db: Database, oin: Oin, **kwargs: object) -> HsmKeyVersion:
    with db.get_db_session() as session:
        org = session.query(Organization).filter(Organization.oin == oin).one_or_none()
        if org is None:
            org = Organization(
                oin=oin,
                name=f"Org {oin}",
                max_rid_usage="irp",
            )
            session.add(org)
            session.flush()

        version = HsmKeyVersion(organization_id=org.id, **kwargs)
        session.add(version)
        session.commit()
        return version


def test_get_active_versions_filters_by_date_and_removed(database: Database) -> None:
    now = datetime.now(timezone.utc)
    # active: started, no end date
    versions = [
        _add(
            database,
            oin=TEST_OIN_111,
            version=1,
            from_dt=now - timedelta(days=1),
            until_dt=None,
        ),
        _add(
            database,
            oin=TEST_OIN_222,
            version=2,
            from_dt=now - timedelta(days=1),
            until_dt=now + timedelta(days=1),
        ),
        _add(
            database,
            oin=TEST_OIN_333,
            version=3,
            from_dt=now + timedelta(days=1),
            until_dt=None,
        ),
        _add(
            database,
            oin=TEST_OIN_444,
            version=4,
            from_dt=now - timedelta(days=2),
            until_dt=now - timedelta(days=1),
        ),
        _add(
            database,
            oin=TEST_OIN_555,
            version=5,
            from_dt=now - timedelta(days=1),
            until_dt=None,
            removed=True,
        ),
    ]

    service = HsmKeyVersionService(database)
    active = {
        v.organization.oin
        for version in versions
        for v in service.get_active_versions_by_organization_id(version.organization_id)
    }

    assert active == {TEST_OIN_111, TEST_OIN_222}


def test_get_active_or_create_versions_retries_after_create_conflict(
    database: Database,
) -> None:
    organization = OrgService(database).get_by_oin(TEST_OIN_111)
    assert organization is not None

    service = HsmKeyVersionService(database)
    original_create = service.create_version_by_organization_id

    call_count = 0

    def flaky_create(org_id: uuid.UUID) -> HsmKeyVersion:
        nonlocal call_count
        if call_count == 0:
            call_count += 1
            now = datetime.now(timezone.utc)
            _add(database, oin=TEST_OIN_111, version=1, from_dt=now)
            raise HsmKeyVersionCreateConflictError(organization.id)

        return original_create(org_id)

    with patch.object(
        service, "create_version_by_organization_id", side_effect=flaky_create
    ):
        active = service.get_active_or_create_versions_by_organization_id(
            organization.id
        )

    assert len(active) == 1
    assert active[0].organization_id == organization.id
    assert active[0].version == 1
    assert call_count == 1


def test_eval_via_hsm_returns_entry_per_active_version(database: Database) -> None:
    now = datetime.now(timezone.utc)
    _add(
        database,
        oin=TEST_OIN_78000,
        version=2,
        from_dt=now - timedelta(days=2),
    )
    _add(
        database,
        oin=TEST_OIN_78000,
        version=7,
        from_dt=now - timedelta(days=1),
    )
    # a removed version must be ignored
    _add(
        database,
        oin=TEST_OIN_78000,
        version=9,
        from_dt=now - timedelta(days=1),
        removed=True,
    )

    service = OprfService(
        server_key=None,
        hsm_config=ConfigOprf(hsm_url="https://hsm.local"),
        hsm_key_version_service=HsmKeyVersionService(database),
        org_service=OrgService(database),
    )

    with (
        patch.object(service, "_label_exists", return_value=True) as label_exists,
        patch.object(
            service, "_evaluate_label", return_value=b"evaluated"
        ) as evaluate_label,
    ):
        result = service._eval_via_hsm(TEST_OIN_78000, b"blinded")

    assert result == {2: b"evaluated", 7: b"evaluated"}

    assert [str(c.args[0]) for c in label_exists.call_args_list] == [
        "oin-00000000012345678000-v2",
        "oin-00000000012345678000-v7",
    ]

    assert [(str(c.args[0]), c.args[1]) for c in evaluate_label.call_args_list] == [
        ("oin-00000000012345678000-v2", b"blinded"),
        ("oin-00000000012345678000-v7", b"blinded"),
    ]

    assert label_exists.call_count == 2
    assert evaluate_label.call_count == 2


def test_eval_generates_keys_if_needed(database: Database) -> None:
    now = datetime.now(timezone.utc)
    _add(
        database,
        oin=TEST_OIN_79000,
        version=1,
        from_dt=now - timedelta(days=2),
    )

    service = OprfService(
        server_key=None,
        hsm_config=ConfigOprf(hsm_url="https://hsm.local"),
        hsm_key_version_service=HsmKeyVersionService(database),
        org_service=OrgService(database),
    )

    with (
        patch.object(service, "_label_exists", return_value=False) as label_exists,
        patch.object(service, "_generate_key") as generate_key,
        patch.object(
            service, "_evaluate_label", return_value=b"evaluated"
        ) as evaluate_label,
    ):
        result = service._eval_via_hsm(TEST_OIN_79000, b"blinded")

    assert result == {1: b"evaluated"}

    assert [str(c.args[0]) for c in label_exists.call_args_list] == [
        "oin-00000000012345679000-v1",
    ]

    assert [str(c.args[0]) for c in generate_key.call_args_list] == [
        "oin-00000000012345679000-v1",
    ]

    assert [(str(c.args[0]), c.args[1]) for c in evaluate_label.call_args_list] == [
        ("oin-00000000012345679000-v1", b"blinded"),
    ]

    assert label_exists.call_count == 1
    assert evaluate_label.call_count == 1
    assert generate_key.call_count == 1


def test_eval_blind_subject_is_latest_with_extra_versions(database: Database) -> None:
    from jwcrypto import jwe as jwelib
    from jwcrypto import jwk

    from app.models.requests import BlindRequest

    now = datetime.now(timezone.utc)
    _add(
        database,
        oin=TEST_OIN_78000,
        version=2,
        from_dt=now - timedelta(days=2),
    )
    _add(
        database,
        oin=TEST_OIN_78000,
        version=7,
        from_dt=now - timedelta(days=1),
    )

    service = OprfService(
        server_key=None,
        hsm_config=ConfigOprf(hsm_url="https://hsm.local"),
        hsm_key_version_service=HsmKeyVersionService(database),
        org_service=OrgService(database),
    )

    key = jwk.JWK.generate(kty="RSA", size=2048)
    pub = jwk.JWK.from_json(key.export_public())

    def fake_post(url: str, json: dict, **kwargs: object) -> MagicMock:  # type: ignore[type-arg]
        # Return slot info when asked
        if url == "https://hsm.local/hsm/softhsm/SoftHSMLabel":
            resp = MagicMock()
            resp.json.return_value = {
                "objects": ["foobar"],
            }
            return resp

        version = json["label"].rsplit("v", 1)[-1]
        resp = MagicMock()
        resp.json.return_value = {
            "result": base64.b64encode(f"eval-v{version}".encode()).decode()
        }
        return resp

    req = BlindRequest(
        encryptedPersonalId=base64.urlsafe_b64encode(b"blinded").decode(),
        recipientOrganization=RecipientOrganizationOin("oin:00000000012345678000"),
        recipientScope="scope",
    )

    with patch("app.services.oprf.oprf_service.requests.post", side_effect=fake_post):
        token_str = service.eval_blind(req, pub)

    token = jwelib.JWE()
    token.deserialize(token_str)
    token.decrypt(key)
    body = json.loads(token.payload.decode("utf-8"))

    # The subject holds the latest version (v7) in the original format.
    assert (
        body["subject"]
        == "pseudonym:eval:" + base64.urlsafe_b64encode(b"eval-v7").decode()
    )
    # Older versions are carried separately so newer clients can detect them.
    assert body["extra_versions"] == {
        "2": base64.urlsafe_b64encode(b"eval-v2").decode()
    }


def test_eval_blind_jwe_contains_only_versions_active_at_date(
    database: Database,
) -> None:
    from jwcrypto import jwe as jwelib
    from jwcrypto import jwk

    from app.models.requests import BlindRequest

    now = datetime.now(timezone.utc)
    # expired: ended yesterday -> excluded
    _add(
        database,
        oin=TEST_OIN,
        version=1,
        from_dt=now - timedelta(days=10),
        until_dt=now - timedelta(days=1),
    )
    # active: started, no end date
    _add(
        database,
        oin=TEST_OIN,
        version=3,
        from_dt=now - timedelta(days=5),
        until_dt=None,
    )
    # active: within window
    _add(
        database,
        oin=TEST_OIN,
        version=5,
        from_dt=now - timedelta(days=2),
        until_dt=now + timedelta(days=2),
    )
    # future: not started yet -> excluded
    _add(
        database,
        oin=TEST_OIN,
        version=8,
        from_dt=now + timedelta(days=1),
        until_dt=None,
    )

    service = OprfService(
        server_key=None,
        hsm_config=ConfigOprf(hsm_url="https://hsm.local"),
        hsm_key_version_service=HsmKeyVersionService(database),
        org_service=OrgService(database),
    )

    key = jwk.JWK.generate(kty="RSA", size=2048)
    pub = jwk.JWK.from_json(key.export_public())

    def fake_post(url: str, json: dict, **kwargs: object) -> MagicMock:  # type: ignore[type-arg]
        # Return slot info when asked
        if url == "https://hsm.local/hsm/softhsm/SoftHSMLabel":
            resp = MagicMock()
            resp.json.return_value = {
                "objects": ["foobar"],
            }
            return resp

        version = json["label"].rsplit("v", 1)[-1]
        resp = MagicMock()
        resp.json.return_value = {
            "result": base64.b64encode(f"eval-v{version}".encode()).decode()
        }
        return resp

    req = BlindRequest(
        encryptedPersonalId=base64.urlsafe_b64encode(b"blinded").decode(),
        recipientOrganization=RecipientOrganizationOin(TEST_OIN_WITH_PREFIX),
        recipientScope="scope",
    )

    with patch("app.services.oprf.oprf_service.requests.post", side_effect=fake_post):
        token_str = service.eval_blind(req, pub)

    token = jwelib.JWE()
    token.deserialize(token_str)
    token.decrypt(key)
    body = json.loads(token.payload.decode("utf-8"))

    # Only the versions active *now* are evaluated: v3 and v5. The expired (v1)
    # and not-yet-started (v8) versions are excluded by date. The latest active
    # version (v5) is the subject; older active versions are carried separately.
    assert (
        body["subject"]
        == "pseudonym:eval:" + base64.urlsafe_b64encode(b"eval-v5").decode()
    )
    assert body["extra_versions"] == {
        "3": base64.urlsafe_b64encode(b"eval-v3").decode()
    }


def test_eval_via_hsm_without_active_version_creates_first_version(
    database: Database,
) -> None:
    hsm_key_version_service = HsmKeyVersionService(database)
    service = OprfService(
        server_key=None,
        hsm_config=ConfigOprf(hsm_url="https://hsm.local"),
        hsm_key_version_service=hsm_key_version_service,
        org_service=OrgService(database),
    )

    with (
        patch.object(service, "_label_exists", return_value=False) as label_exists,
        patch.object(service, "_generate_key") as generate_key,
        patch.object(
            service, "_evaluate_label", return_value=b"evaluated"
        ) as evaluate_label,
    ):
        result = service._eval_via_hsm(TEST_OIN, b"blinded")

    assert result == {1: b"evaluated"}

    organization = OrgService(database).get_by_oin(TEST_OIN)
    assert organization is not None
    versions = hsm_key_version_service.get_versions_by_organization_id(organization.id)
    assert len(versions) == 1
    assert versions[0].version == 1

    assert [str(c.args[0]) for c in label_exists.call_args_list] == [
        "oin-00000099000000001000-v1"
    ]

    assert [str(c.args[0]) for c in generate_key.call_args_list] == [
        "oin-00000099000000001000-v1"
    ]

    assert [(str(c.args[0]), c.args[1]) for c in evaluate_label.call_args_list] == [
        ("oin-00000099000000001000-v1", b"blinded")
    ]


def test_eval_via_hsm_with_removed_versions_creates_new_version(
    database: Database,
) -> None:
    hsm_key_version_service = HsmKeyVersionService(database)
    now = datetime.now(timezone.utc)
    first = _add(
        database,
        oin=TEST_OIN,
        version=1,
        from_dt=now - timedelta(days=2),
        until_dt=None,
        removed=True,
    )
    _add(
        database,
        oin=TEST_OIN,
        version=2,
        from_dt=now - timedelta(days=1),
        until_dt=None,
        removed=True,
    )

    service = OprfService(
        server_key=None,
        hsm_config=ConfigOprf(hsm_url="https://hsm.local"),
        hsm_key_version_service=hsm_key_version_service,
        org_service=OrgService(database),
    )

    with (
        patch.object(service, "_label_exists", return_value=False) as label_exists,
        patch.object(service, "_generate_key") as generate_key,
        patch.object(
            service, "_evaluate_label", return_value=b"evaluated"
        ) as evaluate_label,
    ):
        result = service._eval_via_hsm(TEST_OIN, b"blinded")

    assert result == {3: b"evaluated"}

    versions = hsm_key_version_service.get_versions_by_organization_id(
        first.organization_id
    )
    assert len(versions) == 3
    assert versions[-1].version == 3
    assert all(version.removed for version in versions[:-1])
    assert versions[-1].removed is False

    assert [str(c.args[0]) for c in label_exists.call_args_list] == [
        "oin-00000099000000001000-v3"
    ]

    assert [str(c.args[0]) for c in generate_key.call_args_list] == [
        "oin-00000099000000001000-v3"
    ]

    assert [(str(c.args[0]), c.args[1]) for c in evaluate_label.call_args_list] == [
        ("oin-00000099000000001000-v3", b"blinded")
    ]


def test_eval_via_hsm_without_organization_raises(database: Database) -> None:
    service = OprfService(
        server_key=None,
        hsm_config=ConfigOprf(hsm_url="https://hsm.local"),
        hsm_key_version_service=HsmKeyVersionService(database),
        org_service=OrgService(database),
    )

    with pytest.raises(
        ValueError, match=f"organization not found for oin {TEST_OIN_99999}"
    ):
        service._eval_via_hsm(TEST_OIN_99999, b"blinded")


def test_eval_via_hsm_without_service_raises() -> None:
    service = OprfService(
        server_key=None, hsm_config=ConfigOprf(hsm_url="https://hsm.local")
    )

    with pytest.raises(ValueError, match="HSM key version service not configured"):
        service._eval_via_hsm(TEST_OIN_78000, b"blinded")


def test_constructor_requires_local_server_key_when_no_hsm() -> None:
    with pytest.raises(ValueError, match="server key not configured"):
        OprfService(server_key=None, hsm_config=ConfigOprf())


def test_mark_removed_keeps_row_for_wrong_oin(database: Database) -> None:
    now = datetime.now(timezone.utc)
    current_version = _add(
        database,
        oin=TEST_OIN,
        version=1,
        from_dt=now - timedelta(days=1),
    )

    service = HsmKeyVersionService(database)
    current = service.get_active_versions_by_organization_id(
        current_version.organization_id
    )[0]

    wrong_organization = OrgService(database).get_by_oin(TEST_OIN_222)
    assert wrong_organization is not None
    with pytest.raises(HsmKeyVersionNotFoundError):
        service.mark_removed_by_organization_id(current.id, wrong_organization.id)

    after = next(
        (
            version
            for version in service.get_versions_by_organization_id(
                current_version.organization_id
            )
            if version.id == current.id
        ),
        None,
    )
    assert after is not None
    assert after.removed is False


def test_update_version_rejects_removed(database: Database) -> None:
    now = datetime.now(timezone.utc)
    current_version = _add(
        database,
        oin=TEST_OIN,
        version=1,
        from_dt=now - timedelta(hours=1),
        removed=False,
    )

    service = HsmKeyVersionService(database)
    active = service.get_active_versions_by_organization_id(
        current_version.organization_id
    )
    assert len(active) == 1

    service.mark_removed_by_organization_id(
        active[0].id, current_version.organization_id
    )

    updated_until = now - timedelta(minutes=1)
    with pytest.raises(HsmKeyVersionNotFoundError):
        service.update_version_by_organization_id(
            active[0].id, current_version.organization_id, updated_until
        )


def test_create_version_preserves_timezone_in_storage(database: Database) -> None:
    from_dt = datetime(
        2027,
        1,
        1,
        8,
        tzinfo=timezone(offset=timedelta(hours=2)),
    )
    until_dt = datetime(
        2028,
        1,
        1,
        8,
        tzinfo=timezone(offset=timedelta(hours=-3)),
    )

    organization = OrgService(database).get_by_oin(TEST_OIN)
    assert organization is not None

    service = HsmKeyVersionService(database)
    created = service.create_version_by_organization_id(
        organization.id, from_dt=from_dt, until_dt=until_dt
    )
    versions = service.get_versions_by_organization_id(organization.id)

    assert len(versions) == 1
    stored = versions[0]
    assert created.id == stored.id
    assert stored.from_dt.tzinfo is not None
    assert stored.until_dt is not None
    assert stored.until_dt.tzinfo is not None
    assert stored.from_dt.astimezone(timezone.utc) == from_dt.astimezone(timezone.utc)
    assert stored.until_dt.astimezone(timezone.utc) == until_dt.astimezone(timezone.utc)


def test_update_version_preserves_timezone_in_storage(database: Database) -> None:
    from_dt = datetime(
        2027,
        2,
        1,
        12,
        tzinfo=timezone(offset=timedelta(hours=-7)),
    )
    until_dt = datetime(
        2027,
        2,
        15,
        12,
        tzinfo=timezone(offset=timedelta(hours=8, minutes=30)),
    )

    organization = OrgService(database).get_by_oin(TEST_OIN)
    assert organization is not None

    service = HsmKeyVersionService(database)
    created = service.create_version_by_organization_id(
        organization.id, from_dt=from_dt
    )
    updated = service.update_version_by_organization_id(
        created.id, organization.id, until_dt=until_dt
    )
    versions = service.get_versions_by_organization_id(organization.id)

    assert len(versions) == 1
    stored = versions[0]
    assert updated.id == stored.id
    assert stored.until_dt is not None
    assert stored.until_dt.tzinfo is not None
    assert stored.until_dt.astimezone(timezone.utc) == until_dt.astimezone(timezone.utc)
