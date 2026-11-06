import base64
import hashlib
import hmac
from datetime import timedelta
from unittest.mock import MagicMock

import pytest
from requests.exceptions import ConnectionError

from app.db.models.hsm_key_versions import HsmKeyVersionEntity
from app.db.models.organization import OrganizationEntity
from app.db.session import DbSession
from app.enums.pseudonym_error_type import PseudonymErrorType
from app.exceptions.pseudonym import (
    CryptoFailureError,
    HsmUnreachableError,
    NoActiveKeyVersionError,
)
from app.models.oin import Oin, RecipientOrganizationOin
from app.models.personal_id import PersonalId
from app.services.hsm_key_version_service import HsmKeyVersionService
from app.services.irreversible.keys import LocalIrreversibleKeyOperations
from app.services.irreversible.service import (
    IrreversiblePseudonym,
    IrreversiblePseudonymService,
    _encode,
)
from app.services.pseudonym_subject import pseudonym_subject
from app.services.reversible.keys import LocalReversibleKeyOperations
from app.utils.datetime import now_utc


def test_generate_should_return_pseudonym_with_versions(
    irreversible_pseudonym_service: IrreversiblePseudonymService,
    persisted_organization: OrganizationEntity,
    mock_personal_id: PersonalId,
) -> None:
    irreversible_pseudonym_service._keys.hmac = MagicMock(  # type: ignore
        return_value=b"test_digest"
    )

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
    irreversible_pseudonym_service._keys.hmac = MagicMock(  # type: ignore
        return_value=expected_digest
    )

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
    irreversible_pseudonym_service._keys.hmac = MagicMock(  # type: ignore
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
    irreversible_pseudonym_service._keys.hmac = MagicMock(  # type: ignore
        side_effect=ValueError("Crypto error")
    )

    with pytest.raises(CryptoFailureError) as exc_info:
        irreversible_pseudonym_service.generate(
            personal_id=mock_personal_id,
            recipient=persisted_organization.external_id,
            recipient_scope="test_scope",
        )

    assert exc_info.value.error_type == PseudonymErrorType.CRYPTO_FAILURE


def test_generate_should_return_deterministic_pseudonym(
    local_irreversible_pseudonym_service: IrreversiblePseudonymService,
    persisted_organization: OrganizationEntity,
    mock_personal_id: PersonalId,
) -> None:
    """Tests that the same input always produces the same pseudonym."""
    first = local_irreversible_pseudonym_service.generate(
        personal_id=mock_personal_id,
        recipient=persisted_organization.external_id,
        recipient_scope="test_scope",
    )
    second = local_irreversible_pseudonym_service.generate(
        personal_id=mock_personal_id,
        recipient=persisted_organization.external_id,
        recipient_scope="test_scope",
    )
    assert first == second
    assert first.version == 1
    assert first.older == ()
    # Check it's a base64url-encoded SHA256 digest (32 bytes)
    assert len(base64.urlsafe_b64decode(first.value)) == 32  # SHA256 digest size


def test_generate_should_match_reference_computation(
    local_irreversible_pseudonym_service: IrreversiblePseudonymService,
    persisted_organization: OrganizationEntity,
    mock_personal_id: PersonalId,
    local_irreversible_key_operations: LocalIrreversibleKeyOperations,
) -> None:
    """Tests that the pseudonym matches a manually computed HMAC."""
    # Generate the pseudonym using the service
    result = local_irreversible_pseudonym_service.generate(
        personal_id=mock_personal_id,
        recipient=persisted_organization.external_id,
        recipient_scope="test_scope",
    )

    # Manually compute the expected pseudonym
    subject = pseudonym_subject(
        mock_personal_id, persisted_organization.external_id, "test_scope"
    )
    # Get the key for version 1
    key = local_irreversible_key_operations._key(persisted_organization.external_id, 1)
    expected_digest = hmac.new(key, subject, hashlib.sha256).digest()
    expected_value = base64.urlsafe_b64encode(expected_digest).decode("ascii")

    assert result.value == expected_value


@pytest.mark.parametrize(
    "pid,recipient,scope",
    [
        ("other_pid", "same_org", "same_scope"),  # Different PID
        ("same_pid", "other_org", "same_scope"),  # Different recipient
        ("same_pid", "same_org", "other_scope"),  # Different scope
    ],
)
def test_generate_should_return_unique_pseudonym_for_different_inputs(
    local_irreversible_pseudonym_service: IrreversiblePseudonymService,
    persisted_organization: OrganizationEntity,
    persisted_organization_2: OrganizationEntity,
    mock_personal_id: PersonalId,
    mock_personal_id_2: PersonalId,
    pid: str,
    recipient: str,
    scope: str,
) -> None:
    """Tests that different inputs produce different pseudonyms."""
    # Get base pseudonym
    base = local_irreversible_pseudonym_service.generate(
        personal_id=mock_personal_id,
        recipient=persisted_organization.external_id,
        recipient_scope="test_scope",
    )

    # Determine the actual inputs based on the parametrize values
    actual_pid = mock_personal_id_2 if pid == "other_pid" else mock_personal_id
    actual_recipient = (
        persisted_organization_2.external_id
        if recipient == "other_org"
        else persisted_organization.external_id
    )
    actual_scope = "other_scope" if scope == "other_scope" else "test_scope"

    # Get the different pseudonym
    different = local_irreversible_pseudonym_service.generate(
        personal_id=actual_pid,
        recipient=actual_recipient,
        recipient_scope=actual_scope,
    )

    assert base != different


def test_generate_should_handle_oin_prefix(
    local_irreversible_pseudonym_service: IrreversiblePseudonymService,
    persisted_organization: OrganizationEntity,
    mock_personal_id: PersonalId,
) -> None:
    """Tests that OIN with or without prefix gives the same pseudonym."""
    # Generate with plain Oin
    plain = local_irreversible_pseudonym_service.generate(
        personal_id=mock_personal_id,
        recipient=persisted_organization.external_id,
        recipient_scope="test_scope",
    )

    # Generate with RecipientOrganizationOin (has "oin:" prefix)
    prefixed = local_irreversible_pseudonym_service.generate(
        personal_id=mock_personal_id,
        recipient=RecipientOrganizationOin(
            f"oin:{persisted_organization.external_id.value}"
        ),
        recipient_scope="test_scope",
    )

    assert plain == prefixed


def test_generate_should_return_different_pseudonym_for_different_key_versions(
    local_irreversible_key_operations: LocalIrreversibleKeyOperations,
    persisted_organization: OrganizationEntity,
    mock_personal_id: PersonalId,
    hsm_key_version_service: HsmKeyVersionService,
    db_session: DbSession,
) -> None:
    """Tests that different key versions produce different pseudonyms."""
    # Create service with version 1 only
    service_v1 = IrreversiblePseudonymService(
        local_irreversible_key_operations,
        hsm_key_version_service,
    )
    v1 = service_v1.generate(
        personal_id=mock_personal_id,
        recipient=persisted_organization.external_id,
        recipient_scope="test_scope",
    )

    # Add version 2 to the organization
    version_2 = HsmKeyVersionEntity(
        organization=persisted_organization,
        version=2,
        from_dt=now_utc(),
        until_dt=now_utc() + timedelta(days=365),
    )
    db_session.add(version_2)
    db_session.commit()

    # Create service with the same key version service (now includes version 2)
    service_v2 = IrreversiblePseudonymService(
        local_irreversible_key_operations,
        hsm_key_version_service,
    )
    v2 = service_v2.generate(
        personal_id=mock_personal_id,
        recipient=persisted_organization.external_id,
        recipient_scope="test_scope",
    )

    assert v1.value != v2.value


def test_generate_should_include_older_pseudonyms_during_grace_period(
    local_irreversible_key_operations: LocalIrreversibleKeyOperations,
    persisted_organization: OrganizationEntity,
    mock_personal_id: PersonalId,
    hsm_key_version_service: HsmKeyVersionService,
    db_session: DbSession,
) -> None:
    """Tests that during grace period, pseudonym includes older versions."""
    # Add version 2 to the organization (overlapping with version 1)
    version_2 = HsmKeyVersionEntity(
        organization=persisted_organization,
        version=2,
        from_dt=now_utc() - timedelta(days=5),  # Overlaps with version 1
        until_dt=now_utc() + timedelta(days=365),
    )
    db_session.add(version_2)
    db_session.commit()

    # Create service with both versions active
    service = IrreversiblePseudonymService(
        local_irreversible_key_operations,
        hsm_key_version_service,
    )
    result = service.generate(
        personal_id=mock_personal_id,
        recipient=persisted_organization.external_id,
        recipient_scope="test_scope",
    )

    # The latest version should be 2
    assert result.version == 2
    # Should include older version (1) in the grace period
    assert len(result.older) == 1
    assert result.older[0][0] == 1  # Version 1 is older
    assert result.older[0][1] != result.value  # Different pseudonym


def test_irreversible_and_reversible_keys_are_separate(
    local_irreversible_key_operations: LocalIrreversibleKeyOperations,
    local_reversible_key_operations: LocalReversibleKeyOperations,
    valid_organization_id: Oin,
) -> None:
    """Tests that irreversible and reversible keys produce different HMACs."""
    data = b"same input"

    irreversible = local_irreversible_key_operations.hmac(
        valid_organization_id, 1, data
    )
    reversible = local_reversible_key_operations.hmac(valid_organization_id, 1, data)

    assert irreversible != reversible


def test_generate_should_raise_when_scope_has_delimiter(
    local_irreversible_pseudonym_service: IrreversiblePseudonymService,
    persisted_organization: OrganizationEntity,
    mock_personal_id: PersonalId,
) -> None:
    """Tests that a scope with delimiter raises CryptoFailureError."""
    with pytest.raises(CryptoFailureError):
        local_irreversible_pseudonym_service.generate(
            personal_id=mock_personal_id,
            recipient=persisted_organization.external_id,
            recipient_scope="a|b",  # Invalid scope with delimiter
        )
