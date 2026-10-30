import pytest

from app.db.models.organization import OrganizationEntity
from app.db.repositories.organization_repository import OrganizationRepository
from app.exceptions import OrganizationNotRegisteredError
from app.models.oin import Oin


def test_get_one_by_external_id_should_return_organization_when_exists(
    organization_repository: OrganizationRepository,
    persisted_organization: OrganizationEntity,
) -> None:
    result = organization_repository.get_one_by_external_id(
        persisted_organization.external_id
    )

    assert result is not None
    assert result.id == persisted_organization.id


def test_get_one_by_external_id_should_return_none_when_not_exists(
    organization_repository: OrganizationRepository,
    valid_organization_id: Oin,
) -> None:
    result = organization_repository.get_one_by_external_id(valid_organization_id)

    assert result is None


def test_get_registered_should_return_organization_when_exists(
    organization_repository: OrganizationRepository,
    persisted_organization: OrganizationEntity,
) -> None:
    result = organization_repository.get_registered(persisted_organization.external_id)

    assert result.id == persisted_organization.id


def test_get_registered_should_raise_error_when_not_exists(
    organization_repository: OrganizationRepository,
    valid_organization_id: Oin,
) -> None:
    with pytest.raises(OrganizationNotRegisteredError):
        organization_repository.get_registered(valid_organization_id)
