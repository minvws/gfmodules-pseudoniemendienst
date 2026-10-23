import uuid
from datetime import datetime, timedelta, timezone

import pytest
from conftest import TEST_OIN_111, create_organization

from app.db.models import HsmKeyVersionEntity, OrganizationEntity
from app.db.session import DbSession
from app.exceptions import (
    KeyVersionNotFoundError,
    KeyVersionRemovedError,
    NoKeyVersionError,
    OrganizationNotRegisteredError,
    RecipientNotFoundError,
)
from app.models.oin import Oin
from app.services.hsm_key_version_service import HsmKeyVersionService

# TODO: this needs to be shared
# TEST_OIN_WITH_PREFIX = f"oin:{TEST_OIN}"
TEST_OIN_222 = Oin("00000099000000022000")
TEST_OIN_333 = Oin("00000099000000033000")
TEST_OIN_444 = Oin("00000099000000044000")
TEST_OIN_555 = Oin("00000099000000055000")
TEST_OIN_78000 = Oin("00000000012345678000")
TEST_OIN_79000 = Oin("00000000012345679000")


# TODO: this go to helpers
def add_hsm_key_version(
    db_session: DbSession,
    external_id: Oin,
    **kwargs: object,
) -> OrganizationEntity:
    org = create_organization(db_session, external_id)
    org.hsm_key_versions.append(HsmKeyVersionEntity(**kwargs))
    db_session.commit()
    return org


#
# def test_get_active_versions_filters_by_date_and_removed(
#     hsm_key_version_service: HsmKeyVersionService,
#     database: Database,
#     db_session: DbSession,
# ) -> None:
#     now = datetime.now(timezone.utc)
#     # active: started, no end date
#     add_hsm_key_version(
#         db_session,
#         external_id=TEST_OIN_111,
#         version=1,
#         from_dt=now - timedelta(days=1),
#         until_dt=None,
#     )
#     # active: within window
#     add_hsm_key_version(
#         db_session,
#         external_id=TEST_OIN_222,
#         version=2,
#         from_dt=now - timedelta(days=1),
#         until_dt=now + timedelta(days=1),
#     )
#     # inactive: not started yet
#     add_hsm_key_version(
#         db_session,
#         external_id=TEST_OIN_333,
#         version=3,
#         from_dt=now + timedelta(days=1),
#         until_dt=None,
#     )
#     # inactive: already ended
#     add_hsm_key_version(
#         db_session,
#         external_id=TEST_OIN_444,
#         version=4,
#         from_dt=now - timedelta(days=2),
#         until_dt=now - timedelta(days=1),
#     )
#     # inactive: removed
#     add_hsm_key_version(
#         db_session,
#         external_id=TEST_OIN_555,
#         version=5,
#         from_dt=now - timedelta(days=1),
#         until_dt=None,
#         removed_at=now,
#     )
#
#     test_oins = [TEST_OIN_111, TEST_OIN_222, TEST_OIN_333, TEST_OIN_444, TEST_OIN_555]
#
#     with database.get_db_session() as session:
#         org_ids = [
#             org.id
#             for org in session.query(OrganizationEntity)
#             .filter(
#                 OrganizationEntity.external_id.in_([oin.value for oin in test_oins])
#             )
#             .all()
#         ]
#
#     active_versions = {
#         v.version
#         for org_id in org_ids
#         for v in hsm_key_version_service.get_active_versions_by_organization_id(org_id)
#     }
#
#     assert active_versions == {1, 2}
#
#
# def test_get_active_versions_excludes_version_ending_now(
#     hsm_key_version_service: HsmKeyVersionService,
#     database: Database,
#     db_session: DbSession,
# ) -> None:
#     now = datetime.now(timezone.utc)
#     org = add_hsm_key_version(
#         db_session,
#         external_id=TEST_OIN_111,
#         version=1,
#         from_dt=now - timedelta(hours=1),
#         until_dt=now,
#     )
#
#     active = {
#         v.version
#         for v in hsm_key_version_service.get_active_versions_by_organization_id(
#             org.id, at=now
#         )
#     }
#
#     assert active == set()
#
#     # The same row is considered expired at this exact boundary.
#     expired = {v.version for v in hsm_key_version_service.get_expired_versions(at=now)}
#     assert expired == {1}
#
#
# def test_get_active_version_numbers(
#     hsm_key_version_service: HsmKeyVersionService,
#     database: Database,
#     db_session: DbSession,
#     persisted_organization: OrganizationEntity,
# ) -> None:
#     now = datetime.now(timezone.utc)
#     initial_version = [
#         v for v in persisted_organization.hsm_key_versions if v.version == 1
#     ]
#     initial_version[0].until_dt = now - timedelta(days=1)
#     db_session.commit()
#
#     # service = HsmKeyVersionService(database)
#     versions = hsm_key_version_service.get_active_version_numbers_by_organization_oin(
#         persisted_organization.external_id
#     )
#
#     assert versions == []
#
#     all_versions = hsm_key_version_service.get_versions_by_organization_id(
#         persisted_organization.external_id
#     )
#     assert [v.version for v in all_versions] == [1]


# =============================================================================
# New tests
# =============================================================================


def test_get_version_should_succeed(
    hsm_key_version_service: HsmKeyVersionService,
    persisted_organization: OrganizationEntity,
) -> None:
    expected_version = persisted_organization.hsm_key_versions[0]
    actual_version = hsm_key_version_service.get_version(expected_version.id)
    assert actual_version is not None
    assert actual_version.id == expected_version.id
    assert actual_version.organization_id == expected_version.organization_id
    assert actual_version.version == expected_version.version
    assert actual_version.from_dt == expected_version.from_dt
    assert actual_version.until_dt == expected_version.until_dt
    assert actual_version.removed_at == expected_version.removed_at


def test_get_version_should_return_none_when_key_version_does_not_exist(
    hsm_key_version_service: HsmKeyVersionService,
) -> None:
    non_existent_id = uuid.uuid4()
    result = hsm_key_version_service.get_version(non_existent_id)
    assert result is None


def test_get_versions_by_organization_id_should_succeed(
    hsm_key_version_service: HsmKeyVersionService,
    persisted_organization: OrganizationEntity,
) -> None:
    result = hsm_key_version_service.get_versions_by_organization_id(
        persisted_organization.external_id
    )
    expected_versions = persisted_organization.hsm_key_versions
    assert len(result) == len(expected_versions)
    for actual, expected in zip(result, expected_versions):
        assert actual.id == expected.id
        assert actual.organization_id == expected.organization_id
        assert actual.version == expected.version
        assert actual.from_dt == expected.from_dt
        assert actual.until_dt == expected.until_dt
        assert actual.removed_at == expected.removed_at


def test_get_versions_by_organization_id_should_raise_when_org_not_registered(
    hsm_key_version_service: HsmKeyVersionService,
) -> None:
    from app.exceptions import OrganizationNotRegisteredError

    with pytest.raises(OrganizationNotRegisteredError):
        hsm_key_version_service.get_versions_by_organization_id(TEST_OIN_111)


def test_get_active_version_numbers_by_organization_oin_should_succeed(
    hsm_key_version_service: HsmKeyVersionService,
    persisted_organization: OrganizationEntity,
) -> None:
    result = hsm_key_version_service.get_active_version_numbers_by_organization_oin(
        persisted_organization.external_id
    )
    assert result == [1]


def test_get_active_version_numbers_by_organization_oin_should_raise(
    hsm_key_version_service: HsmKeyVersionService,
) -> None:

    with pytest.raises(RecipientNotFoundError):
        hsm_key_version_service.get_active_version_numbers_by_organization_oin(
            TEST_OIN_111
        )


def test_get_expired_versions_should_succeed(
    hsm_key_version_service: HsmKeyVersionService,
    db_session: DbSession,
    persisted_organization: OrganizationEntity,
) -> None:
    expired_version = persisted_organization.hsm_key_versions[0]
    expired_version.until_dt = datetime.now(timezone.utc) - timedelta(days=1)
    db_session.commit()

    result = hsm_key_version_service.get_expired_versions()
    assert len(result) == 1
    actual = result[0]
    expected = persisted_organization.hsm_key_versions[0]
    assert actual.id == expected.id
    assert actual.organization_id == expected.organization_id
    assert actual.version == expected.version
    assert actual.from_dt == expected.from_dt
    assert actual.until_dt == expected.until_dt
    assert actual.removed_at == expected.removed_at


def test_get_expired_versions_should_return_empty_list(
    hsm_key_version_service: HsmKeyVersionService,
    persisted_organization: OrganizationEntity,
) -> None:
    result = hsm_key_version_service.get_expired_versions()
    assert result == []


def test_increase_version_for_org_should_succeed(
    hsm_key_version_service: HsmKeyVersionService,
    persisted_organization: OrganizationEntity,
) -> None:
    result = hsm_key_version_service.increase_version_for_org(
        persisted_organization.external_id
    )
    assert result.version == 2
    assert result.organization_id == persisted_organization.id
    assert result.from_dt is not None
    assert result.until_dt is None
    assert result.removed_at is None


def test_increase_version_for_org_should_raise_when_org_not_registered(
    hsm_key_version_service: HsmKeyVersionService,
) -> None:
    with pytest.raises(OrganizationNotRegisteredError):
        hsm_key_version_service.increase_version_for_org(TEST_OIN_111)


def test_increase_version_for_org_should_raise_when_no_versions_exist(
    hsm_key_version_service: HsmKeyVersionService,
    db_session: DbSession,
) -> None:
    org = OrganizationEntity(
        external_id=TEST_OIN_111,
        name="test_org_no_versions",
        hsm_key_versions=[],
    )
    db_session.add(org)
    db_session.commit()

    with pytest.raises(NoKeyVersionError):
        hsm_key_version_service.increase_version_for_org(TEST_OIN_111)


def test_update_version_by_organization_id_should_succeed(
    hsm_key_version_service: HsmKeyVersionService,
    db_session: DbSession,
    persisted_organization: OrganizationEntity,
) -> None:
    version = persisted_organization.hsm_key_versions[0]
    new_until_dt = datetime.now(timezone.utc) + timedelta(days=1)

    result = hsm_key_version_service.update_version_by_organization_id(
        version.id, persisted_organization.external_id, until_dt=new_until_dt
    )

    assert result["id"] == str(version.id)
    assert result["version"] == version.version
    assert result["until_dt"] == new_until_dt


def test_update_version_by_organization_id_should_raise_when_org_not_registered(
    hsm_key_version_service: HsmKeyVersionService,
) -> None:
    with pytest.raises(OrganizationNotRegisteredError):
        hsm_key_version_service.update_version_by_organization_id(
            uuid.uuid4(), TEST_OIN_111
        )


def test_update_version_by_organization_id_should_raise_when_version_not_found(
    hsm_key_version_service: HsmKeyVersionService,
    persisted_organization: OrganizationEntity,
) -> None:
    with pytest.raises(KeyVersionNotFoundError):
        hsm_key_version_service.update_version_by_organization_id(
            uuid.uuid4(), persisted_organization.external_id
        )


def test_update_version_by_organization_id_should_raise_when_version_removed(
    hsm_key_version_service: HsmKeyVersionService,
    db_session: DbSession,
    persisted_organization: OrganizationEntity,
) -> None:
    version = persisted_organization.hsm_key_versions[0]
    version.removed_at = datetime.now(timezone.utc)
    db_session.commit()

    with pytest.raises(KeyVersionRemovedError):
        hsm_key_version_service.update_version_by_organization_id(
            version.id, persisted_organization.external_id
        )


def test_mark_removed_should_succeed(
    hsm_key_version_service: HsmKeyVersionService,
    db_session: DbSession,
    persisted_organization: OrganizationEntity,
) -> None:
    version = persisted_organization.hsm_key_versions[0]

    result = hsm_key_version_service.mark_removed(version.id)

    assert result is not None
    assert result.id == version.id
    assert result.removed_at is not None


def test_mark_removed_should_return_none_when_version_not_found(
    hsm_key_version_service: HsmKeyVersionService,
) -> None:
    result = hsm_key_version_service.mark_removed(uuid.uuid4())
    assert result is None


def test_mark_removed_should_return_none_when_version_already_removed(
    hsm_key_version_service: HsmKeyVersionService,
    db_session: DbSession,
    persisted_organization: OrganizationEntity,
) -> None:
    version = persisted_organization.hsm_key_versions[0]
    version.removed_at = datetime.now(timezone.utc)
    db_session.commit()

    result = hsm_key_version_service.mark_removed(version.id)
    assert result is None


def test_get_active_versions_by_organization_id_should_succeed(
    hsm_key_version_service: HsmKeyVersionService,
    persisted_organization: OrganizationEntity,
) -> None:
    result = hsm_key_version_service.get_active_versions_by_organization_id(
        persisted_organization.id
    )
    assert len(result) == 1
    actual = result[0]
    expected = persisted_organization.hsm_key_versions[0]
    assert actual.id == expected.id
    assert actual.organization_id == expected.organization_id
    assert actual.version == expected.version
    assert actual.from_dt == expected.from_dt
    assert actual.until_dt == expected.until_dt
    assert actual.removed_at == expected.removed_at


def test_get_active_versions_by_organization_id_should_return_empty_list(
    hsm_key_version_service: HsmKeyVersionService,
    db_session: DbSession,
    persisted_organization: OrganizationEntity,
) -> None:
    version = persisted_organization.hsm_key_versions[0]
    version.until_dt = datetime.now(timezone.utc) - timedelta(days=1)
    db_session.commit()

    result = hsm_key_version_service.get_active_versions_by_organization_id(
        persisted_organization.id
    )
    assert result == []
