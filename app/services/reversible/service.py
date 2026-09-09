"""
Reversible pseudonym, Double-HMAC-IV as in PRS-AK-F0XF:

    subject = "<personal_id>|oin:<recipient oin>|<recipient scope>"
    IV      = HMAC(k_hmac, HMAC(k_hmac, subject))[:16]
    ePS     = format(1 byte) || version(2 bytes) || AES-CBC(k_aes, IV, subject) || IV

Keys are per (recipient organization, key version). Reversing recomputes the IV
from the decrypted subject and checks it against the embedded one.
"""

import base64
import hmac
import logging
from dataclasses import dataclass

from app.models.oin import RECIPIENT_ORGANIZATION_PREFIX, Oin
from app.personal_id import PersonalId
from app.services.hsm.client import HSM_UNREACHABLE_ERRORS
from app.services.hsm_key_version_service import HsmKeyVersionService
from app.services.reversible.keys import ReversibleKeyOperations

logger = logging.getLogger(__name__)

FORMAT_VERSION = 1
IV_LENGTH = 16
AES_BLOCK = 16
_HEADER_LENGTH = 1 + 2
_MIN_LENGTH = _HEADER_LENGTH + AES_BLOCK + IV_LENGTH


class ReversiblePseudonymError(ValueError):
    """error_type is one of the PRS-PSE-004 values: hsm_unreachable,
    crypto_failure, version_destroyed, invalid_pseudonym; or
    no_active_key_version when the recipient has no active HSM key version."""

    def __init__(self, error_type: str, message: str) -> None:
        super().__init__(message)
        self.error_type = error_type


@dataclass(frozen=True)
class ReversiblePseudonym:
    # base64url encoded pseudonym, without the "pseudonym:reversible:" prefix
    value: str
    version: int


@dataclass(frozen=True)
class ReversedPseudonym:
    personal_id: PersonalId
    recipient_organization: str
    recipient_scope: str
    version: int


def _recipient_organization(recipient: Oin) -> str:
    return RECIPIENT_ORGANIZATION_PREFIX + recipient.value


class ReversiblePseudonymService:
    def __init__(
        self,
        keys: ReversibleKeyOperations,
        key_versions: HsmKeyVersionService,
    ) -> None:
        self._keys = keys
        self._key_versions = key_versions

    def generate(
        self,
        personal_id: PersonalId,
        recipient: Oin,
        recipient_scope: str,
    ) -> ReversiblePseudonym:
        subject = self._subject(personal_id, recipient, recipient_scope)
        active = self._key_versions.get_active_version_numbers_by_organization_oin(
            recipient
        )
        if not active:
            raise ReversiblePseudonymError(
                "no_active_key_version",
                f"organization '{recipient.value}' has no active HSM key version",
            )
        version = max(active)

        try:
            self._keys.ensure_keys(recipient, version)
            iv = self._derive_iv(recipient, version, subject)
            ciphertext = self._keys.encrypt(recipient, version, iv, subject)
        except HSM_UNREACHABLE_ERRORS as e:
            raise ReversiblePseudonymError("hsm_unreachable", "HSM unreachable") from e
        except Exception as e:
            logger.exception("reversible pseudonym encryption failed")
            raise ReversiblePseudonymError(
                "crypto_failure", "reversible pseudonym encryption failed"
            ) from e

        blob = bytes([FORMAT_VERSION]) + version.to_bytes(2, "big") + ciphertext + iv
        return ReversiblePseudonym(
            value=base64.urlsafe_b64encode(blob).decode("ascii"), version=version
        )

    def reverse(self, value: str, recipient: Oin) -> ReversedPseudonym:
        version, ciphertext, iv = self._unpack(value)

        if not self._version_available(recipient, version):
            raise ReversiblePseudonymError(
                "version_destroyed",
                f"key version {version} is not available for organization "
                f"'{recipient.value}'",
            )

        try:
            subject = self._keys.decrypt(recipient, version, iv, ciphertext)
            expected_iv = self._derive_iv(recipient, version, subject)
        except HSM_UNREACHABLE_ERRORS as e:
            raise ReversiblePseudonymError("hsm_unreachable", "HSM unreachable") from e
        except Exception as e:
            # wrong key, bad padding or corrupted data
            logger.warning(
                "reversible pseudonym decryption failed: %s", type(e).__name__
            )
            raise ReversiblePseudonymError(
                "invalid_pseudonym", "pseudonym could not be decrypted"
            ) from e

        if not hmac.compare_digest(iv, expected_iv):
            raise ReversiblePseudonymError(
                "invalid_pseudonym", "pseudonym integrity check failed"
            )

        parts = subject.decode("utf-8").split("|")
        if len(parts) != 3 or parts[1] != _recipient_organization(recipient):
            raise ReversiblePseudonymError(
                "invalid_pseudonym", "pseudonym was not issued for this organization"
            )

        return ReversedPseudonym(
            personal_id=PersonalId.from_str(parts[0]),
            recipient_organization=parts[1],
            recipient_scope=parts[2],
            version=version,
        )

    def _subject(
        self, personal_id: PersonalId, recipient: Oin, recipient_scope: str
    ) -> bytes:
        if "|" in recipient_scope:
            raise ReversiblePseudonymError(
                "crypto_failure", "recipient scope must not contain '|'"
            )
        return (
            f"{personal_id.as_str()}|{_recipient_organization(recipient)}|{recipient_scope}"
        ).encode()

    def _derive_iv(self, recipient: Oin, version: int, subject: bytes) -> bytes:
        inner = self._keys.hmac(recipient, version, subject)
        outer = self._keys.hmac(recipient, version, inner)
        return outer[:IV_LENGTH]

    def _version_available(self, recipient: Oin, version: int) -> bool:
        return any(
            v.version == version and v.removed_at is None
            for v in self._key_versions.get_versions_by_organization_id(recipient)
        )

    @staticmethod
    def _unpack(value: str) -> tuple[int, bytes, bytes]:
        try:
            blob = base64.urlsafe_b64decode(value)
        except Exception as e:
            raise ReversiblePseudonymError(
                "invalid_pseudonym", "pseudonym is not base64url"
            ) from e

        if len(blob) < _MIN_LENGTH or blob[0] != FORMAT_VERSION:
            raise ReversiblePseudonymError(
                "invalid_pseudonym", "pseudonym has an unknown format"
            )
        body = blob[_HEADER_LENGTH:]
        if (len(body) - IV_LENGTH) % AES_BLOCK != 0:
            raise ReversiblePseudonymError(
                "invalid_pseudonym", "pseudonym has an invalid length"
            )
        version = int.from_bytes(blob[1:_HEADER_LENGTH], "big")
        return version, body[:-IV_LENGTH], body[-IV_LENGTH:]
