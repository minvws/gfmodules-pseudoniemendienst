from datetime import timedelta
from unittest.mock import MagicMock

import pytest
from requests.exceptions import ConnectionError

from app.db.models.organization import OrganizationEntity
from app.db.session import DbSession
from app.enums.pseudonym_error_type import PseudonymErrorType
from app.exceptions.pseudonym import (
    CryptoFailureError,
    HsmUnreachableError,
    NoActiveKeyVersionError,
)
from app.models.personal_id import PersonalId
from app.services.irreversible.service import (
    IrreversiblePseudonym,
    IrreversiblePseudonymService,
    _encode,
)
from app.utils.datetime import now_utc


def test_generate_should_return_pseudonym_with_versions(
    irreversible_pseudonym_service: IrreversiblePseudonymService,
    persisted_organization: OrganizationEntity,
    mock_personal_id: PersonalId,
) -> None:
    irreversible_pseudonym_service._keys.hmac = MagicMock(return_value=b"test_digest")

    result = irreversible_pseudonym_service.generate(
        personal_id=mock_personal_id,
        recipient=persisted_organization.external_id,
        recipient_scope="test_scope",
    )

    assert isinstance(result, IrreversiblePseudonym)
    assert result.version == 1
    assert result.older == ()


def test_generate_should_return_expected_pseudonym(
    irreversible_pseudonym_service: IrreversiblePseudonymService,
    mock_personal_id: PersonalId,
    persisted_organization: OrganizationEntity,
) -> None:
    # Setup expected result
    expected_version = 1
    expected_digest = b"test_digest"
    expected_value = _encode(expected_digest)
    expected = IrreversiblePseudonym(
        value=expected_value,
        version=expected_version,
        older=(),
    )

    # Mock the service methods
    irreversible_pseudonym_service._keys.hmac = MagicMock(return_value=expected_digest)

    # Get actual result
    actual = irreversible_pseudonym_service.generate(
        personal_id=mock_personal_id,
        recipient=persisted_organization.external_id,
        recipient_scope="test_scope",
    )

    # Assert
    assert actual == expected


def test_generate_should_raise_when_no_active_versions(
    irreversible_pseudonym_service: IrreversiblePseudonymService,
    persisted_organization: OrganizationEntity,
    mock_personal_id: PersonalId,
    db_session: DbSession,
) -> None:
    # Expire all key versions for the organization
    now = now_utc()
    for version in persisted_organization.hsm_key_versions:
        version.until_dt = now - timedelta(days=1)
    db_session.commit()

    with pytest.raises(NoActiveKeyVersionError) as exc_info:
        irreversible_pseudonym_service.generate(
            personal_id=mock_personal_id,
            recipient=persisted_organization.external_id,
            recipient_scope="test_scope",
        )

    assert exc_info.value.error_type == PseudonymErrorType.NO_ACTIVE_KEY_VERSION


def test_generate_should_raise_when_hsm_unreachable(
    irreversible_pseudonym_service: IrreversiblePseudonymService,
    persisted_organization: OrganizationEntity,
    mock_personal_id: PersonalId,
) -> None:
    # Mock keys.hmac to raise ConnectionError
    irreversible_pseudonym_service._keys.hmac = MagicMock(
        side_effect=ConnectionError("Connection failed")
    )

    with pytest.raises(HsmUnreachableError) as exc_info:
        irreversible_pseudonym_service.generate(
            personal_id=mock_personal_id,
            recipient=persisted_organization.external_id,
            recipient_scope="test_scope",
        )

    assert exc_info.value.error_type == PseudonymErrorType.HSM_UNREACHABLE


def test_generate_should_raise_when_crypto_failure(
    irreversible_pseudonym_service: IrreversiblePseudonymService,
    persisted_organization: OrganizationEntity,
    mock_personal_id: PersonalId,
) -> None:
    # Mock keys.hmac to raise ValueError
    irreversible_pseudonym_service._keys.hmac = MagicMock(
        side_effect=ValueError("Crypto error")
    )

    with pytest.raises(CryptoFailureError) as exc_info:
        irreversible_pseudonym_service.generate(
            personal_id=mock_personal_id,
            recipient=persisted_organization.external_id,
            recipient_scope="test_scope",
        )

    assert exc_info.value.error_type == PseudonymErrorType.CRYPTO_FAILURE
