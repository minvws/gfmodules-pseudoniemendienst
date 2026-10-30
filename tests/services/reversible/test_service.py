import base64
from unittest.mock import MagicMock

import pytest
from requests.exceptions import ConnectionError

from app.db.models.organization import OrganizationEntity
from app.db.session import DbSession
from app.enums.pseudonym_error_type import PseudonymErrorType
from app.exceptions.pseudonym import (
    HsmUnreachableError,
    InvalidPseudonymError,
    PseudonymVersionDestroyedError,
)
from app.models.oin import Oin
from app.models.personal_id import PersonalId
from app.services.reversible.service import (
    ReversiblePseudonym,
    ReversiblePseudonymService,
)
from app.utils.datetime import now_utc


@pytest.fixture
def version(persisted_organization: OrganizationEntity) -> int:
    return persisted_organization.hsm_key_versions[0].version


@pytest.fixture
def ciphertext() -> bytes:
    return b"01234567890123456789012345678901"  # 32 bytes


@pytest.fixture
def iv() -> bytes:
    return b"1234567890123456"  # 16 bytes


def test_generate_should_return_pseudonym(
    reversible_pseudonym_service: ReversiblePseudonymService,
    mock_personal_id: PersonalId,
    persisted_organization: OrganizationEntity,
) -> None:
    reversible_pseudonym_service._keys.encrypt = MagicMock(
        return_value=b"encrypted_subject"
    )
    reversible_pseudonym_service._keys.hmac = MagicMock(return_value=b"hashed_data")

    result = reversible_pseudonym_service.generate(
        personal_id=mock_personal_id,
        recipient=persisted_organization.external_id,
        recipient_scope="test_scope",
    )

    assert isinstance(result, ReversiblePseudonym)
    assert result.version == 1
    assert len(result.value) > 0


def test_generate_should_return_expected_pseudonym(
    reversible_pseudonym_service: ReversiblePseudonymService,
    mock_personal_id: PersonalId,
    persisted_organization: OrganizationEntity,
) -> None:
    # Setup expected result
    expected_version = 1
    expected_blob = (
        bytes([1])
        + expected_version.to_bytes(2, "big")
        + b"encrypted_subject"
        + b"iv_data"
    )
    expected_value = base64.urlsafe_b64encode(expected_blob).decode("ascii")
    expected = ReversiblePseudonym(value=expected_value, version=expected_version)

    # Mock the service methods to produce the expected blob
    reversible_pseudonym_service._keys.encrypt = MagicMock(
        return_value=b"encrypted_subject"
    )
    reversible_pseudonym_service._keys.hmac = MagicMock(return_value=b"iv_data")

    # Get actual result
    actual = reversible_pseudonym_service.generate(
        personal_id=mock_personal_id,
        recipient=persisted_organization.external_id,
        recipient_scope="test_scope",
    )

    # Assert
    assert actual == expected


def test_reverse_should_return_reversed_pseudonym(
    reversible_pseudonym_service: ReversiblePseudonymService,
    mock_personal_id: PersonalId,
    persisted_organization: OrganizationEntity,
    version: int,
    ciphertext: bytes,
    iv: bytes,
) -> None:
    # Create a valid pseudonym blob with ciphertext that's a multiple of 16 bytes
    blob = bytes([1]) + version.to_bytes(2, "big") + ciphertext + iv
    value = base64.urlsafe_b64encode(blob).decode("ascii")

    # Create the expected subject that will be decrypted
    subject = f"{mock_personal_id.as_str()}|oin:{persisted_organization.external_id.value}|test_scope"

    # Mock the service methods
    reversible_pseudonym_service._keys.decrypt = MagicMock(
        return_value=subject.encode("utf-8")
    )
    reversible_pseudonym_service._keys.hmac = MagicMock(
        return_value=iv  # IV should match what was used in the blob
    )

    result = reversible_pseudonym_service.reverse(
        value, persisted_organization.external_id
    )

    assert result.personal_id == mock_personal_id
    assert (
        result.recipient_organization
        == f"oin:{persisted_organization.external_id.value}"
    )
    assert result.recipient_scope == "test_scope"
    assert result.version == 1


def test_reverse_should_raise_when_invalid_base64(
    reversible_pseudonym_service: ReversiblePseudonymService,
    persisted_organization: OrganizationEntity,
) -> None:
    with pytest.raises(InvalidPseudonymError) as exc_info:
        reversible_pseudonym_service.reverse(
            "not-valid-base64!!!", persisted_organization.external_id
        )

    assert exc_info.value.error_type == PseudonymErrorType.INVALID_PSEUDONYM


def test_reverse_should_raise_when_version_does_not_exists_or_destroyed(
    reversible_pseudonym_service: ReversiblePseudonymService,
    persisted_organization: OrganizationEntity,
    version: int,
    ciphertext: bytes,
    iv: bytes,
    db_session: DbSession,
) -> None:
    # Mark the version as removed
    hsm_version = persisted_organization.hsm_key_versions[0]
    hsm_version.removed_at = now_utc()
    db_session.commit()

    # Create a blob with the version (which is now removed)
    blob = bytes([1]) + version.to_bytes(2, "big") + ciphertext + iv
    value = base64.urlsafe_b64encode(blob).decode("ascii")

    with pytest.raises(PseudonymVersionDestroyedError) as exc_info:
        reversible_pseudonym_service.reverse(value, persisted_organization.external_id)

    assert exc_info.value.error_type == PseudonymErrorType.VERSION_DESTROYED


def test_reverse_should_raise_when_hsm_unreachable(
    reversible_pseudonym_service: ReversiblePseudonymService,
    persisted_organization: OrganizationEntity,
    version: int,
    ciphertext: bytes,
    iv: bytes,
) -> None:
    # Create a valid blob
    blob = bytes([1]) + version.to_bytes(2, "big") + ciphertext + iv
    value = base64.urlsafe_b64encode(blob).decode("ascii")

    # Mock decrypt to raise ConnectionError
    reversible_pseudonym_service._keys.decrypt = MagicMock(
        side_effect=ConnectionError("Connection failed")
    )

    with pytest.raises(HsmUnreachableError) as exc_info:
        reversible_pseudonym_service.reverse(value, persisted_organization.external_id)

    assert exc_info.value.error_type == PseudonymErrorType.HSM_UNREACHABLE


def test_reverse_should_raise_when_invalid_pseudonym_decryption_failed(
    reversible_pseudonym_service: ReversiblePseudonymService,
    persisted_organization: OrganizationEntity,
    version: int,
    ciphertext: bytes,
    iv: bytes,
) -> None:
    # Create a valid blob
    blob = bytes([1]) + version.to_bytes(2, "big") + ciphertext + iv
    value = base64.urlsafe_b64encode(blob).decode("ascii")

    # Mock decrypt to raise a generic exception
    reversible_pseudonym_service._keys.decrypt = MagicMock(
        side_effect=ValueError("Decryption failed")
    )

    with pytest.raises(InvalidPseudonymError) as exc_info:
        reversible_pseudonym_service.reverse(value, persisted_organization.external_id)

    assert exc_info.value.error_type == PseudonymErrorType.INVALID_PSEUDONYM


def test_reverse_should_raise_when_iv_mismatch(
    reversible_pseudonym_service: ReversiblePseudonymService,
    persisted_organization: OrganizationEntity,
    version: int,
    ciphertext: bytes,
    iv: bytes,
    mock_personal_id: PersonalId,
) -> None:
    # Create a valid blob
    blob = bytes([1]) + version.to_bytes(2, "big") + ciphertext + iv
    value = base64.urlsafe_b64encode(blob).decode("ascii")

    # Create the subject that will be decrypted
    subject = f"{mock_personal_id.as_str()}|oin:{persisted_organization.external_id.value}|test_scope"

    # Mock decrypt to return subject
    reversible_pseudonym_service._keys.decrypt = MagicMock(
        return_value=subject.encode("utf-8")
    )
    # Mock hmac to return a DIFFERENT IV than what's in the blob
    reversible_pseudonym_service._keys.hmac = MagicMock(
        return_value=b"different_iv_data"
    )

    with pytest.raises(InvalidPseudonymError) as exc_info:
        reversible_pseudonym_service.reverse(value, persisted_organization.external_id)

    assert exc_info.value.error_type == PseudonymErrorType.INVALID_PSEUDONYM


def test_reverse_should_raise_when_wrong_organization(
    reversible_pseudonym_service: ReversiblePseudonymService,
    persisted_organization: OrganizationEntity,
    version: int,
    ciphertext: bytes,
    iv: bytes,
    mock_personal_id: PersonalId,
    valid_organization_id_2: Oin,
) -> None:
    # Create a valid blob
    blob = bytes([1]) + version.to_bytes(2, "big") + ciphertext + iv
    value = base64.urlsafe_b64encode(blob).decode("ascii")

    # Create a subject with a DIFFERENT organization
    subject = (
        f"{mock_personal_id.as_str()}|oin:{valid_organization_id_2.value}|test_scope"
    )

    # Mock decrypt to return subject with different org
    reversible_pseudonym_service._keys.decrypt = MagicMock(
        return_value=subject.encode("utf-8")
    )
    # Mock hmac to return the IV (so IV check passes)
    reversible_pseudonym_service._keys.hmac = MagicMock(return_value=iv)

    with pytest.raises(InvalidPseudonymError) as exc_info:
        reversible_pseudonym_service.reverse(value, persisted_organization.external_id)

    assert exc_info.value.error_type == PseudonymErrorType.INVALID_PSEUDONYM
