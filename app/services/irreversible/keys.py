"""
Key operations for irreversible pseudonyms.
"""

import hashlib
import hmac
import logging
from dataclasses import dataclass
from typing import Protocol

import gfmodules.logging as gflog

from app.logging.events import SLEUTELTYPE_IRREVERSIBLE_KEY, Log
from app.models.oin import Oin
from app.services.hkdf import hkdf_derive
from app.services.hsm.client import HsmClient, HsmKeyNotFound
from app.services.key_destroyer import KeyDestroyer

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class IrreversibleKeyLabel:
    oin: Oin
    version: int

    def __str__(self) -> str:
        # Always the bare 20-character OIN, also for a RecipientOrganizationOin
        # whose str() carries the "oin:" prefix, so that the label matches the
        # one the cleanup derives from the stored organization.
        return f"oin-{self.oin.value}-irp-v{self.version}-hmac"


class IrreversibleKeyOperations(KeyDestroyer, Protocol):
    """The secret is created on first use."""

    def hmac(self, oin: Oin, version: int, data: bytes) -> bytes:
        """HMAC-SHA256 with the organization/version irreversible secret."""
        ...


class LocalIrreversibleKeyOperations:
    """HKDF from the master key. Development and tests only."""

    def __init__(self, master_key: bytes) -> None:
        self._master_key = master_key

    def _key(self, oin: Oin, version: int) -> bytes:
        info = f"prs:irp:hmac:{oin.value}:v{version}".encode()
        return hkdf_derive(self._master_key, info, 32)

    def hmac(self, oin: Oin, version: int, data: bytes) -> bytes:
        return hmac.new(self._key(oin, version), data, hashlib.sha256).digest()

    def destroy(self, oin: Oin, version: int) -> bool:
        return False


class HsmIrreversibleKeyOperations:
    def __init__(self, client: HsmClient) -> None:
        self._client = client

    def hmac(self, oin: Oin, version: int, data: bytes) -> bytes:
        label = IrreversibleKeyLabel(oin, version)
        try:
            return self._client.hmac(str(label), data)
        except HsmKeyNotFound:
            # First use of this key version: create the secret and try again.
            self._create_key(label)
            return self._client.hmac(str(label), data)

    def destroy(self, oin: Oin, version: int) -> bool:
        return self._client.destroy_if_present(str(IrreversibleKeyLabel(oin, version)))

    def _create_key(self, label: IrreversibleKeyLabel) -> None:
        if not self._client.generate_secret_key(str(label)):
            # Another instance won the race; its key is the one we use.
            return
        # PRS-KEY-001: irreversible pseudonym secrets are generated lazily on first use.
        gflog.emit(
            logger,
            Log.KEY_GENERATED,
            "irreversible pseudonym secret generated in HSM",
            fields={
                "sleuteltype": SLEUTELTYPE_IRREVERSIBLE_KEY,
                "organisatie_oin": label.oin.value,
                "secret_id": str(label),
                "sleutel_versie": label.version,
            },
        )
