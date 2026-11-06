import pytest
from pydantic import ValidationError

from app.models.oin import Oin, RecipientOrganizationOin
from app.models.personal_id import PersonalId
from app.models.requests.exchange import (
    PersonalIdInputRequest,
    PseudonymExchangeRequest,
    ReversiblePseudonymInputRequest,
)


def test_pseudonym_exchange_request_should_validate(
    valid_organization_id: Oin,
) -> None:
    request = PseudonymExchangeRequest(
        recipientOrganization=RecipientOrganizationOin(valid_organization_id),
        recipientScope="test_scope",
    )
    assert request.recipientOrganization.value == valid_organization_id.value
    assert request.recipientScope == "test_scope"


def test_pseudonym_exchange_request_should_raise_when_scope_contains_delimiter(
    valid_organization_id: Oin,
) -> None:
    with pytest.raises(ValidationError, match="recipientScope"):
        PseudonymExchangeRequest(
            recipientOrganization=RecipientOrganizationOin(valid_organization_id),
            recipientScope="test|scope",
        )


def test_reversible_pseudonym_input_request_should_strip_prefix(
    valid_organization_id: Oin,
) -> None:
    request = ReversiblePseudonymInputRequest(
        reversiblePseudonym="pseudonym:reversible:ABC123",
        recipientOrganization=RecipientOrganizationOin(valid_organization_id),
        recipientScope="test_scope",
    )
    assert request.reversiblePseudonym == "ABC123"


def test_reversible_pseudonym_input_request_should_not_strip_other_prefixes(
    valid_organization_id: Oin,
) -> None:
    request = ReversiblePseudonymInputRequest(
        reversiblePseudonym="other:prefix:ABC123",
        recipientOrganization=RecipientOrganizationOin(valid_organization_id),
        recipientScope="test_scope",
    )
    assert request.reversiblePseudonym == "other:prefix:ABC123"


def test_personal_id_input_request_should_validate_with_string(
    valid_organization_id: Oin,
    mock_personal_id: PersonalId,
) -> None:
    request = PersonalIdInputRequest(
        personalId=mock_personal_id.as_str(),
        recipientOrganization=RecipientOrganizationOin(valid_organization_id),
        recipientScope="test_scope",
    )
    assert request.personalId == mock_personal_id.as_str()


def test_personal_id_input_request_should_validate_with_dict(
    valid_organization_id: Oin,
    mock_personal_id: PersonalId,
) -> None:
    request = PersonalIdInputRequest(
        personalId=mock_personal_id.as_dict(),
        recipientOrganization=RecipientOrganizationOin(valid_organization_id),
        recipientScope="test_scope",
    )
    assert request.personalId == mock_personal_id.as_dict()
