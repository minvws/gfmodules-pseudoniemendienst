"""
Irreversible pseudonym, keyed one-way function as in PRS-AK-MLLF / PRS-FUNC-ONKE:
    subject   = "<personal_id>|oin:<recipient oin>|<recipient scope>"
    pseudonym = HMAC-SHA256(k_irp[recipient, version], subject)
Keys are per (recipient organization, key version) and live in their own
hierarchy.

During a key rotation's grace period more than one version is active; the
pseudonym is then computed for every active version so a receiver can
migrate its records (dual-version, PRS-PSE-003).
"""

import base64
import logging
from dataclasses import dataclass

from app.models.oin import Oin
from app.personal_id import PersonalId
from app.services.hsm.client import HSM_UNREACHABLE_ERRORS
from app.services.hsm_key_version_service import HsmKeyVersionService
from app.services.irreversible.keys import IrreversibleKeyOperations
from app.services.pseudonym_subject import pseudonym_subject

logger = logging.getLogger(__name__)


class IrreversiblePseudonymError(ValueError):
    """error_type is one of the PRS-PSE-004 values: hsm_unreachable or
    crypto_failure; or no_active_key_version when the recipient has no active
    HSM key version."""

    def __init__(self, error_type: str, message: str) -> None:
        super().__init__(message)
        self.error_type = error_type


def _encode(digest: bytes) -> str:
    return base64.urlsafe_b64encode(digest).decode("ascii")


@dataclass(frozen=True)
class IrreversiblePseudonym:
    # base64url encoded pseudonym for the latest active key version, without
    # the "pseudonym:irreversible:" prefix
    value: str
    version: int
    # pseudonyms for the older versions that are still active (grace period)
    older: tuple[tuple[int, str], ...]


class IrreversiblePseudonymService:
    def __init__(
        self,
        keys: IrreversibleKeyOperations,
        key_versions: HsmKeyVersionService,
    ) -> None:
        self._keys = keys
        self._key_versions = key_versions

    def generate(
        self,
        personal_id: PersonalId,
        recipient: Oin,
        recipient_scope: str,
    ) -> IrreversiblePseudonym:
        subject = self._subject(personal_id, recipient, recipient_scope)
        active = self._key_versions.get_active_version_numbers_by_organization_oin(
            recipient
        )
        if not active:
            raise IrreversiblePseudonymError(
                "no_active_key_version",
                f"organization '{recipient.value}' has no active HSM key version",
            )

        try:
            digests = {
                version: self._keys.hmac(recipient, version, subject)
                for version in sorted(active)
            }
        except HSM_UNREACHABLE_ERRORS as e:
            raise IrreversiblePseudonymError(
                "hsm_unreachable", "HSM unreachable"
            ) from e
        except Exception as e:
            logger.exception("irreversible pseudonym computation failed")
            raise IrreversiblePseudonymError(
                "crypto_failure", "irreversible pseudonym computation failed"
            ) from e

        # digests is ordered by version, so the last one is the latest
        *older, (latest, digest) = digests.items()
        return IrreversiblePseudonym(
            value=_encode(digest),
            version=latest,
            older=tuple((version, _encode(d)) for version, d in older),
        )

    @staticmethod
    def _subject(
        personal_id: PersonalId, recipient: Oin, recipient_scope: str
    ) -> bytes:
        try:
            return pseudonym_subject(personal_id, recipient, recipient_scope)
        except ValueError as e:
            raise IrreversiblePseudonymError("crypto_failure", str(e)) from e
