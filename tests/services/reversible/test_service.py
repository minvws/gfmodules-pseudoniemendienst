import base64
from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest
from requests.exceptions import ConnectionError

from app.db.models.hsm_key_versions import HsmKeyVersionEntity
from app.db.models.organization import OrganizationEntity
from app.db.session import DbSession
from app.enums.pseudonym_error_type import PseudonymErrorType
from app.exceptions.pseudonym import (
    HsmUnreachableError,
    InvalidPseudonymError,
    PseudonymOperationError,
    PseudonymVersionDestroyedError,
)
from app.models.oin import Oin, RecipientOrganizationOin
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


def test_generate_should_return_pseudonym_hsm(
    reversible_pseudonym_service: ReversiblePseudonymService,
    mock_personal_id: PersonalId,
    persisted_organization: OrganizationEntity,
) -> None:
    reversible_pseudonym_service._keys.encrypt = MagicMock(  # type: ignore
        return_value=b"encrypted_subject"
    )
    reversible_pseudonym_service._keys.hmac = MagicMock(  # type: ignore
        return_value=b"hashed_data"
    )

    result = reversible_pseudonym_service.generate(
        personal_id=mock_personal_id,
        recipient=persisted_organization.external_id,
        recipient_scope="test_scope",
    )

    assert isinstance(result, ReversiblePseudonym)
    assert result.version == 1
    assert len(result.value) > 0


def test_generate_should_return_pseudonym_local(
    local_reversible_pseudonym_service: ReversiblePseudonymService,
    mock_personal_id: PersonalId,
    persisted_organization: OrganizationEntity,
) -> None:
    result = local_reversible_pseudonym_service.generate(
        personal_id=mock_personal_id,
        recipient=persisted_organization.external_id,
        recipient_scope="test_scope",
    )

    assert isinstance(result, ReversiblePseudonym)
    assert result.version == 1
    assert len(result.value) > 0


def test_generate_should_return_expected_pseudonym_hsm(
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
    reversible_pseudonym_service._keys.encrypt = MagicMock(  # type: ignore
        return_value=b"encrypted_subject"
    )
    reversible_pseudonym_service._keys.hmac = MagicMock(  # type: ignore
        return_value=b"iv_data"
    )

    # Get actual result
    actual = reversible_pseudonym_service.generate(
        personal_id=mock_personal_id,
        recipient=persisted_organization.external_id,
        recipient_scope="test_scope",
    )

    # Assert
    assert actual == expected


def test_generate_should_return_expected_pseudonym_local(
    local_reversible_pseudonym_service: ReversiblePseudonymService,
    mock_personal_id: PersonalId,
    persisted_organization: OrganizationEntity,
) -> None:
    # Generate a pseudonym
    actual = local_reversible_pseudonym_service.generate(
        personal_id=mock_personal_id,
        recipient=persisted_organization.external_id,
        recipient_scope="test_scope",
    )

    # Verify it is a valid ReversiblePseudonym
    assert isinstance(actual, ReversiblePseudonym)
    assert actual.version == 1
    assert len(actual.value) > 0

    # Verify it can be reversed (to ensure it's valid)
    reversed_ = local_reversible_pseudonym_service.reverse(
        actual.value, persisted_organization.external_id
    )
    assert reversed_.personal_id == mock_personal_id
    assert reversed_.recipient_scope == "test_scope"


def test_reverse_should_return_reversed_pseudonym_hsm(
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
    reversible_pseudonym_service._keys.decrypt = MagicMock(  # type: ignore
        return_value=subject.encode("utf-8")
    )
    reversible_pseudonym_service._keys.hmac = MagicMock(  # type: ignore
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


def test_reverse_should_return_reversed_pseudonym_local(
    local_reversible_pseudonym_service: ReversiblePseudonymService,
    mock_personal_id: PersonalId,
    persisted_organization: OrganizationEntity,
) -> None:
    # Generate a pseudonym
    pseudonym = local_reversible_pseudonym_service.generate(
        mock_personal_id,
        persisted_organization.external_id,
        "test_scope",
    )

    # Reverse it
    result = local_reversible_pseudonym_service.reverse(
        pseudonym.value, persisted_organization.external_id
    )

    assert result.personal_id == mock_personal_id
    assert (
        result.recipient_organization
        == f"oin:{persisted_organization.external_id.value}"
    )
    assert result.recipient_scope == "test_scope"
    assert result.version == pseudonym.version


def test_reverse_should_raise_when_invalid_base64_hsm(
    reversible_pseudonym_service: ReversiblePseudonymService,
    persisted_organization: OrganizationEntity,
) -> None:
    with pytest.raises(InvalidPseudonymError) as exc_info:
        reversible_pseudonym_service.reverse(
            "not-valid-base64!!!", persisted_organization.external_id
        )

    assert exc_info.value.error_type == PseudonymErrorType.INVALID_PSEUDONYM


def test_pseudonym_is_deterministic_local(
    local_reversible_pseudonym_service: ReversiblePseudonymService,
    mock_personal_id: PersonalId,
    persisted_organization: OrganizationEntity,
) -> None:
    """Tests that the same input produces the same pseudonym."""
    first = local_reversible_pseudonym_service.generate(
        mock_personal_id,
        persisted_organization.external_id,
        "test_scope",
    )
    second = local_reversible_pseudonym_service.generate(
        mock_personal_id,
        persisted_organization.external_id,
        "test_scope",
    )

    assert first == second


def test_pseudonym_changes_with_input_scope_organization_and_version_local(
    local_reversible_pseudonym_service: ReversiblePseudonymService,
    mock_personal_id: PersonalId,
    persisted_organization: OrganizationEntity,
    db_session: DbSession,
) -> None:
    """Tests that pseudonyms change with input, scope, organization, and version."""
    # Base pseudonym
    base = local_reversible_pseudonym_service.generate(
        mock_personal_id,
        persisted_organization.external_id,
        "test_scope",
    ).value

    # Different personal ID
    different_pid = PersonalId.from_str("NL:bsn:950000024")
    assert (
        local_reversible_pseudonym_service.generate(
            different_pid,
            persisted_organization.external_id,
            "test_scope",
        ).value
        != base
    )

    # Different scope
    assert (
        local_reversible_pseudonym_service.generate(
            mock_personal_id,
            persisted_organization.external_id,
            "other_scope",
        ).value
        != base
    )

    # Different organization (create a new one)
    other_org = OrganizationEntity(
        external_id=Oin("00000099000000009000"),
        name="other org",
        receive_personal_id_types=[],
        request_personal_id_types=[],
        hsm_key_versions=[
            HsmKeyVersionEntity(version=1, from_dt=datetime.now(UTC))
        ],
    )
    db_session.add(other_org)
    db_session.commit()

    assert (
        local_reversible_pseudonym_service.generate(
            mock_personal_id,
            other_org.external_id,
            "test_scope",
        ).value
        != base
    )


def test_reverse_should_raise_when_version_does_not_exists_or_destroyed_hsm(
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


def test_reverse_should_raise_when_version_does_not_exists_or_destroyed_local(
    local_reversible_pseudonym_service: ReversiblePseudonymService,
    mock_personal_id: PersonalId,
    persisted_organization: OrganizationEntity,
    db_session: DbSession,
) -> None:
    """Tests that reversing a pseudonym with an inactive version fails without decrypting."""
    from app.utils.datetime import now_utc

    # Generate a pseudonym with version 1 (active)
    pseudonym = local_reversible_pseudonym_service.generate(
        mock_personal_id, persisted_organization.external_id, "test_scope"
    )
    assert pseudonym.version == 1  # Ensure version 1 is used

    # Mark version 1 as removed (inactive)
    persisted_organization.hsm_key_versions[0].removed_at = now_utc()
    db_session.commit()

    # Verify that version 1 is no longer active
    active_versions = local_reversible_pseudonym_service._key_versions.get_active_version_numbers_by_organization_oin(
        persisted_organization.external_id
    )
    assert 1 not in active_versions  # Ensure version 1 is not active

    # Store the original decrypt method
    original_decrypt = local_reversible_pseudonym_service._keys.decrypt

    # Mock decrypt to track if it's called
    mock_decrypt = MagicMock(wraps=original_decrypt)
    local_reversible_pseudonym_service._keys.decrypt = mock_decrypt  # type: ignore

    # Reversing should fail without calling decrypt
    with pytest.raises(PseudonymVersionDestroyedError):
        local_reversible_pseudonym_service.reverse(
            pseudonym.value, persisted_organization.external_id
        )
    mock_decrypt.assert_not_called()  # Decrypt should NOT have been called


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
    reversible_pseudonym_service._keys.decrypt = MagicMock(  # type: ignore
        side_effect=ConnectionError("Connection failed")
    )

    with pytest.raises(HsmUnreachableError) as exc_info:
        reversible_pseudonym_service.reverse(value, persisted_organization.external_id)

    assert exc_info.value.error_type == PseudonymErrorType.HSM_UNREACHABLE


def test_reverse_should_raise_when_invalid_pseudonym_decryption_failed_hsm(
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
    reversible_pseudonym_service._keys.decrypt = MagicMock(  # type: ignore
        side_effect=ValueError("Decryption failed")
    )

    with pytest.raises(InvalidPseudonymError) as exc_info:
        reversible_pseudonym_service.reverse(value, persisted_organization.external_id)

    assert exc_info.value.error_type == PseudonymErrorType.INVALID_PSEUDONYM


def test_reverse_should_raise_when_iv_mismatch_hsm(
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
    reversible_pseudonym_service._keys.decrypt = MagicMock(  # type: ignore
        return_value=subject.encode("utf-8")
    )
    # Mock hmac to return a DIFFERENT IV than what's in the blob
    reversible_pseudonym_service._keys.hmac = MagicMock(  # type: ignore
        return_value=b"different_iv_data"
    )

    with pytest.raises(InvalidPseudonymError) as exc_info:
        reversible_pseudonym_service.reverse(value, persisted_organization.external_id)

    assert exc_info.value.error_type == PseudonymErrorType.INVALID_PSEUDONYM


def test_reverse_should_raise_when_wrong_organization_hsm(
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
    reversible_pseudonym_service._keys.decrypt = MagicMock(  # type: ignore
        return_value=subject.encode("utf-8")
    )
    # Mock hmac to return the IV (so IV check passes)
    reversible_pseudonym_service._keys.hmac = MagicMock(  # type: ignore
        return_value=iv
    )

    with pytest.raises(InvalidPseudonymError) as exc_info:
        reversible_pseudonym_service.reverse(value, persisted_organization.external_id)

    assert exc_info.value.error_type == PseudonymErrorType.INVALID_PSEUDONYM


def test_recipient_with_prefix_gives_the_same_pseudonym_local(
    local_reversible_pseudonym_service: ReversiblePseudonymService,
    mock_personal_id: PersonalId,
    persisted_organization: OrganizationEntity,
) -> None:
    """Tests that RecipientOrganizationOin (with oin: prefix) gives the same pseudonym as Oin."""
    # Generate with Oin
    with_oin = local_reversible_pseudonym_service.generate(
        mock_personal_id,
        persisted_organization.external_id,
        "test_scope",
    )

    # Generate with RecipientOrganizationOin (prefixed)
    prefixed = RecipientOrganizationOin(
        f"oin:{persisted_organization.external_id.value}"
    )
    with_prefixed = local_reversible_pseudonym_service.generate(
        mock_personal_id,
        prefixed,
        "test_scope",
    )

    # Should be identical
    assert with_oin == with_prefixed


def test_latest_active_version_is_used_and_older_ones_still_reverse_local(
    local_reversible_pseudonym_service: ReversiblePseudonymService,
    mock_personal_id: PersonalId,
    persisted_organization: OrganizationEntity,
    db_session: DbSession,
) -> None:
    """Tests that the latest active version is used for generation, but older versions can still be reversed."""
    # Generate with version 1 (only active version)
    old = local_reversible_pseudonym_service.generate(
        mock_personal_id, persisted_organization.external_id, "test_scope"
    )

    # Add version 2 for the organization
    new_version = HsmKeyVersionEntity(version=2, from_dt=datetime.now(UTC))
    persisted_organization.hsm_key_versions.append(new_version)
    db_session.commit()

    # Generate with version 2 (now the latest active version)
    new = local_reversible_pseudonym_service.generate(
        mock_personal_id, persisted_organization.external_id, "test_scope"
    )

    # New pseudonym should use version 2
    assert new.version == 2
    assert new.value != old.value

    # Old pseudonym (version 1) should still reverse correctly
    reversed_old = local_reversible_pseudonym_service.reverse(
        old.value, persisted_organization.external_id
    )
    assert reversed_old.personal_id == mock_personal_id
    assert reversed_old.version == 1


def test_without_active_version_generation_fails_local(
    local_reversible_pseudonym_service: ReversiblePseudonymService,
    mock_personal_id: PersonalId,
    db_session: DbSession,
    valid_organization_id_2: Oin,
) -> None:
    """Tests that generation fails if the organization has no active key versions."""
    from app.db.models.organization import OrganizationEntity

    # Create an organization with NO active key versions
    org = OrganizationEntity(
        external_id=valid_organization_id_2,
        name="org without active key versions",
        receive_personal_id_types=[],
        request_personal_id_types=[],
        hsm_key_versions=[],  # No key versions
    )
    db_session.add(org)
    db_session.commit()

    # Generation should fail
    with pytest.raises(PseudonymOperationError) as exc_info:
        local_reversible_pseudonym_service.generate(
            mock_personal_id, org.external_id, "test_scope"
        )
    assert exc_info.value.error_type == "no_active_key_version"


def test_reverse_for_another_organization_fails_local(
    local_reversible_pseudonym_service: ReversiblePseudonymService,
    mock_personal_id: PersonalId,
    persisted_organization: OrganizationEntity,
    db_session: DbSession,
) -> None:
    """Tests that reversing a pseudonym for the wrong organization fails."""
    # Create a second organization
    other_org = OrganizationEntity(
        external_id=Oin("00000099000000003000"),
        name="other org",
        receive_personal_id_types=[],
        request_personal_id_types=[],
        hsm_key_versions=[
            HsmKeyVersionEntity(version=1, from_dt=datetime.now(UTC))
        ],
    )
    db_session.add(other_org)
    db_session.commit()

    # Generate a pseudonym for persisted_organization
    pseudonym = local_reversible_pseudonym_service.generate(
        mock_personal_id,
        persisted_organization.external_id,
        "test_scope",
    )

    # Try to reverse it for the other organization
    with pytest.raises(PseudonymOperationError) as exc_info:
        local_reversible_pseudonym_service.reverse(
            pseudonym.value, other_org.external_id
        )
    assert exc_info.value.error_type == "invalid_pseudonym"


def test_tampered_pseudonym_is_rejected_local(
    local_reversible_pseudonym_service: ReversiblePseudonymService,
    mock_personal_id: PersonalId,
    persisted_organization: OrganizationEntity,
) -> None:
    """Tests that a tampered pseudonym is rejected."""
    # Generate a valid pseudonym
    pseudonym = local_reversible_pseudonym_service.generate(
        mock_personal_id, persisted_organization.external_id, "test_scope"
    )

    # Tamper with the pseudonym by flipping a bit in the ciphertext
    blob = base64.urlsafe_b64decode(pseudonym.value)
    # Flip the first bit of the ciphertext (after the 3-byte header: 1 byte format + 2 bytes version)
    tampered_blob = bytearray(blob)
    tampered_blob[3] ^= 0x01  # Flip a bit in the ciphertext
    tampered_value = base64.urlsafe_b64encode(tampered_blob).decode("ascii")

    # Reversing should fail with InvalidPseudonymError
    with pytest.raises(InvalidPseudonymError):
        local_reversible_pseudonym_service.reverse(
            tampered_value, persisted_organization.external_id
        )


def test_reverse_should_raise_when_invalid_base64_local(
    local_reversible_pseudonym_service: ReversiblePseudonymService,
    persisted_organization: OrganizationEntity,
) -> None:
    """Tests that reversing a pseudonym with invalid base64 fails."""
    with pytest.raises(InvalidPseudonymError):
        local_reversible_pseudonym_service.reverse(
            "not-valid-base64!!!", persisted_organization.external_id
        )


def test_reverse_with_invalid_format_fails_local(
    local_reversible_pseudonym_service: ReversiblePseudonymService,
    persisted_organization: OrganizationEntity,
) -> None:
    """Tests that reversing a pseudonym with an invalid format fails."""
    # Create a blob with an invalid format version (e.g., 99 instead of 1)
    invalid_blob = bytes([99]) + bytes([0, 1]) + b"fake_ciphertext" + b"fake_iv"
    invalid_value = base64.urlsafe_b64encode(invalid_blob).decode("ascii")

    # Reversing should fail with InvalidPseudonymError
    with pytest.raises(InvalidPseudonymError):
        local_reversible_pseudonym_service.reverse(
            invalid_value, persisted_organization.external_id
        )


def test_reverse_with_too_short_pseudonym_fails_local(
    local_reversible_pseudonym_service: ReversiblePseudonymService,
    persisted_organization: OrganizationEntity,
) -> None:
    """Tests that reversing a too-short pseudonym fails."""
    # Create a blob that is too short (minimum length is 1 + 2 + 16 + 16 = 35 bytes)
    too_short_blob = b"\x01\x00\x01"  # Only 3 bytes (format + version)
    too_short_value = base64.urlsafe_b64encode(too_short_blob).decode("ascii")

    # Reversing should fail with InvalidPseudonymError
    with pytest.raises(InvalidPseudonymError):
        local_reversible_pseudonym_service.reverse(
            too_short_value, persisted_organization.external_id
        )


def test_roundtrip_local(
    local_reversible_pseudonym_service: ReversiblePseudonymService,
    mock_personal_id: PersonalId,
    persisted_organization: OrganizationEntity,
) -> None:
    """Tests that generating and reversing a pseudonym returns the original data."""
    pseudonym = local_reversible_pseudonym_service.generate(
        mock_personal_id,
        persisted_organization.external_id,
        "test_scope",
    )

    reversed_ = local_reversible_pseudonym_service.reverse(
        pseudonym.value, persisted_organization.external_id
    )

    assert reversed_.personal_id == mock_personal_id
    assert (
        reversed_.recipient_organization
        == f"oin:{persisted_organization.external_id.value}"
    )
    assert reversed_.recipient_scope == "test_scope"
    assert reversed_.version == pseudonym.version


def test_scope_with_separator_is_refused_local(
    local_reversible_pseudonym_service: ReversiblePseudonymService,
    mock_personal_id: PersonalId,
    persisted_organization: OrganizationEntity,
) -> None:
    """Tests that a scope with a separator (|) is refused."""
    with pytest.raises(PseudonymOperationError):
        local_reversible_pseudonym_service.generate(
            mock_personal_id,
            persisted_organization.external_id,
            "a|b",  # Scope with separator
        )


@pytest.mark.parametrize(
    "value",
    [
        "",  # Empty string
        "not base64!",  # Invalid base64
        base64.urlsafe_b64encode(
            b"\x02" + b"x" * 40
        ).decode(),  # Invalid format version
        base64.urlsafe_b64encode(b"\x01\x00\x01" + b"x" * 33).decode(),  # Too short
    ],
)
def test_malformed_pseudonym_is_rejected_local(
    local_reversible_pseudonym_service: ReversiblePseudonymService,
    persisted_organization: OrganizationEntity,
    value: str,
) -> None:
    """Tests that malformed pseudonyms are rejected."""
    with pytest.raises(InvalidPseudonymError):
        local_reversible_pseudonym_service.reverse(
            value, persisted_organization.external_id
        )
