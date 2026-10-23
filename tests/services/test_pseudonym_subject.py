import pytest

from app.models.oin import RECIPIENT_ORGANIZATION_PREFIX, Oin
from app.models.personal_id import PersonalId
from app.services.pseudonym_subject import pseudonym_subject, recipient_organization


def test_pseudonym_subject_should_return_correct_bytes(
    mock_personal_id: PersonalId,
    valid_organization_id: Oin,
) -> None:
    recipient_scope = "test_scope"

    result = pseudonym_subject(mock_personal_id, valid_organization_id, recipient_scope)

    expected = f"{mock_personal_id.as_str()}|{recipient_organization(valid_organization_id)}|{recipient_scope}".encode()
    assert result == expected


def test_pseudonym_subject_should_raise_value_error_when_scope_contains_delimiter(
    mock_personal_id: PersonalId,
    valid_organization_id: Oin,
) -> None:
    recipient_scope = "test|scope"

    with pytest.raises(ValueError, match="recipient scope must not contain"):
        pseudonym_subject(mock_personal_id, valid_organization_id, recipient_scope)


def test_recipient_organization_should_return_prefixed_string(
    valid_organization_id: Oin,
) -> None:
    result = recipient_organization(valid_organization_id)

    expected = RECIPIENT_ORGANIZATION_PREFIX + valid_organization_id.value
    assert result == expected
