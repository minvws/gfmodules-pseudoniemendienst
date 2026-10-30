import uuid
from datetime import timedelta

from app.db.models.organization import OrganizationEntity
from app.db.repositories.hsm_key_version_repository import HsmKeyVersionRepository
from app.db.session import DbSession
from app.utils.datetime import now_utc


def test_get_active_versions_should_return_active_versions(
    hsm_key_version_repository: HsmKeyVersionRepository,
    persisted_organization: OrganizationEntity,
) -> None:
    at = now_utc()
    result = hsm_key_version_repository.get_active_versions(
        at, persisted_organization.id
    )

    # persisted_organization has one active version by default
    assert len(result) == 1
    assert result[0].organization_id == persisted_organization.id
    assert result[0].id == persisted_organization.hsm_key_versions[0].id


def test_get_active_versions_should_return_empty_list_when_none_active(
    hsm_key_version_repository: HsmKeyVersionRepository,
    persisted_organization: OrganizationEntity,
    db_session: DbSession,
) -> None:
    # Mark the existing version as expired
    version = persisted_organization.hsm_key_versions[0]
    version.until_dt = now_utc() - timedelta(days=1)
    db_session.commit()

    at = now_utc()
    result = hsm_key_version_repository.get_active_versions(
        at, persisted_organization.id
    )

    assert result == []


def test_get_expired_versions_should_return_expired_versions(
    hsm_key_version_repository: HsmKeyVersionRepository,
    persisted_organization: OrganizationEntity,
    db_session: DbSession,
) -> None:
    # Mark the existing version as expired
    version = persisted_organization.hsm_key_versions[0]
    version.until_dt = now_utc() - timedelta(days=1)
    db_session.commit()

    at = now_utc()
    result = hsm_key_version_repository.get_expired_versions(at)

    assert len(result) == 1
    assert result[0].id == version.id


def test_get_expired_versions_should_return_empty_list_when_none_expired(
    hsm_key_version_repository: HsmKeyVersionRepository,
    persisted_organization: OrganizationEntity,
) -> None:
    at = now_utc()
    result = hsm_key_version_repository.get_expired_versions(at)

    # persisted_organization has one active (not expired) version
    assert result == []


def test_get_by_id_should_return_version_when_exists(
    hsm_key_version_repository: HsmKeyVersionRepository,
    persisted_organization: OrganizationEntity,
) -> None:
    version = persisted_organization.hsm_key_versions[0]
    result = hsm_key_version_repository.get_by_id(version.id)

    assert result is not None
    assert result.id == version.id


def test_get_by_id_should_return_none_when_not_exists(
    hsm_key_version_repository: HsmKeyVersionRepository,
) -> None:
    non_existent_id = uuid.uuid4()
    result = hsm_key_version_repository.get_by_id(non_existent_id)

    assert result is None


def test_mark_removed_should_return_version_when_marked(
    hsm_key_version_repository: HsmKeyVersionRepository,
    persisted_organization: OrganizationEntity,
    db_session: DbSession,
) -> None:
    version = persisted_organization.hsm_key_versions[0]
    result = hsm_key_version_repository.mark_removed(version.id)

    assert result is not None
    assert result.id == version.id
    assert result.removed_at is not None

    # Refresh to verify it was actually updated in the database
    db_session.session.refresh(version)
    assert version.removed_at is not None


def test_mark_removed_should_return_none_when_not_exists(
    hsm_key_version_repository: HsmKeyVersionRepository,
) -> None:
    non_existent_id = uuid.uuid4()
    result = hsm_key_version_repository.mark_removed(non_existent_id)

    assert result is None


def test_mark_removed_should_return_none_when_already_removed(
    hsm_key_version_repository: HsmKeyVersionRepository,
    persisted_organization: OrganizationEntity,
    db_session: DbSession,
) -> None:
    version = persisted_organization.hsm_key_versions[0]
    # Mark it as removed first
    hsm_key_version_repository.mark_removed(version.id)
    db_session.commit()

    # Try to mark it again
    result = hsm_key_version_repository.mark_removed(version.id)

    assert result is None
