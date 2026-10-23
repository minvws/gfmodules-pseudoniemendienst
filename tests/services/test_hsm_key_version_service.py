import uuid
from datetime import datetime, timedelta, timezone

import pytest
from conftest import TEST_OIN_111, create_organization

from app.db.models import HsmKeyVersionEntity, OrganizationEntity
from app.db.session import DbSession
from app.exceptions.access import OrganizationNotRegisteredError, RecipientNotFoundError
from app.exceptions.registration import (
    KeyVersionNotFoundError,
    KeyVersionRemovedError,
    NoKeyVersionError,
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
