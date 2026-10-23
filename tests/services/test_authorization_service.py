import pytest

from app.db.models import OrganizationEntity
from app.enums.personal_id_type import PersonalIdType
from app.exceptions import (
    NotAllowedToRequestError,
    OrganizationNotRegisteredError,
    RecipientNotFoundError,
)
from app.models.oin import Oin
from app.services.authorization_service import AuthorizationService


def test_validate_allowed_to_request_should_succeed(
    authorization_service: AuthorizationService,
    persisted_organization: OrganizationEntity,
) -> None:
    authorization_service.validate_allowed_to_request(
        persisted_organization.external_id, PersonalIdType.OPRF
    )


def test_validate_allowed_to_request_should_raise_when_org_not_registered(
    authorization_service: AuthorizationService,
    valid_organization_id_2: Oin,
) -> None:
    with pytest.raises(OrganizationNotRegisteredError):
        authorization_service.validate_allowed_to_request(
            valid_organization_id_2, PersonalIdType.OPRF
        )


@pytest.mark.parametrize(
    "personal_id_type",
    [PersonalIdType.REVERSIBLE_PSEUDONYM, PersonalIdType.IRREVERSIBLE_PSEUDONYM],
)
def test_validate_allowed_to_request_should_raise_when_not_allowed(
    authorization_service: AuthorizationService,
    persisted_organization: OrganizationEntity,
    personal_id_type: PersonalIdType,
) -> None:
    with pytest.raises(NotAllowedToRequestError):
        authorization_service.validate_allowed_to_request(
            persisted_organization.external_id, personal_id_type
        )


def test_validate_allowed_to_receive_should_succeed(
    authorization_service: AuthorizationService,
    persisted_organization: OrganizationEntity,
) -> None:
    authorization_service.validate_allowed_to_receive(
        persisted_organization.external_id, PersonalIdType.OPRF
    )


def test_validate_allowed_to_receive_should_raise_when_org_not_found(
    authorization_service: AuthorizationService,
    valid_organization_id_2: Oin,
) -> None:
    with pytest.raises(RecipientNotFoundError):
        authorization_service.validate_allowed_to_receive(
            valid_organization_id_2, PersonalIdType.OPRF
        )


@pytest.mark.parametrize(
    "personal_id_type",
    [PersonalIdType.REVERSIBLE_PSEUDONYM, PersonalIdType.IRREVERSIBLE_PSEUDONYM],
)
def test_validate_allowed_to_receive_should_raise_when_not_allowed(
    authorization_service: AuthorizationService,
    persisted_organization: OrganizationEntity,
    personal_id_type: PersonalIdType,
) -> None:
    with pytest.raises(RecipientNotFoundError):
        authorization_service.validate_allowed_to_receive(
            persisted_organization.external_id, personal_id_type
        )
