import uuid

import pytest

from app.db.models.organization import OrganizationEntity
from app.db.models.organization_public_key import OrganizationPublicKeyEntity
from app.db.repositories.organization_public_key_repository import (
    OrganizationPublicKeyRepository,
)
from app.db.session import DbSession


@pytest.fixture()
def organization_public_key(
    persisted_organization: OrganizationEntity,
) -> OrganizationPublicKeyEntity:
    return OrganizationPublicKeyEntity(
        organization_id=persisted_organization.id,
        domains=["test.example.com"],
        jwk={"kty": "RSA", "kid": "test-key"},
    )


def test_get_by_id_should_return_key_when_exists(
    organization_public_key_repository: OrganizationPublicKeyRepository,
    organization_public_key: OrganizationPublicKeyEntity,
    db_session: DbSession,
) -> None:
    db_session.add(organization_public_key)
    db_session.commit()

    result = organization_public_key_repository.get_by_id(organization_public_key.id)

    assert result is not None
    assert result.id == organization_public_key.id


def test_get_by_id_should_return_none_when_not_exists(
    organization_public_key_repository: OrganizationPublicKeyRepository,
) -> None:
    non_existent_id = uuid.uuid4()
    result = organization_public_key_repository.get_by_id(non_existent_id)

    assert result is None


def test_delete_should_return_true_when_deleted(
    organization_public_key_repository: OrganizationPublicKeyRepository,
    organization_public_key: OrganizationPublicKeyEntity,
    db_session: DbSession,
) -> None:
    db_session.add(organization_public_key)
    db_session.commit()

    result = organization_public_key_repository.delete(
        organization_public_key.id, organization_public_key.organization_id
    )

    assert result is True

    # Verify it was actually deleted
    deleted = organization_public_key_repository.get_by_id(organization_public_key.id)
    assert deleted is None


def test_delete_should_return_false_when_not_exists(
    organization_public_key_repository: OrganizationPublicKeyRepository,
) -> None:
    non_existent_id = uuid.uuid4()
    organization_id = uuid.uuid4()
    result = organization_public_key_repository.delete(non_existent_id, organization_id)

    assert result is False


def test_delete_should_return_false_when_organization_mismatch(
    organization_public_key_repository: OrganizationPublicKeyRepository,
    organization_public_key: OrganizationPublicKeyEntity,
    db_session: DbSession,
) -> None:
    db_session.add(organization_public_key)
    db_session.commit()

    # Try to delete with wrong organization_id
    wrong_organization_id = uuid.uuid4()
    result = organization_public_key_repository.delete(
        organization_public_key.id, wrong_organization_id
    )

    assert result is False

    # Verify the key still exists
    existing = organization_public_key_repository.get_by_id(organization_public_key.id)
    assert existing is not None
