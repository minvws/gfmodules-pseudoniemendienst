import hashlib
import hmac
import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, Protocol

import gfmodules.logging as gflog
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from app.logging.events import SLEUTELTYPE_REVERSIBLE_KEY, Log
from app.models.oin import Oin
from app.services.hsm.client import HsmClient, HsmKeyNotFound
from app.services.pseudonym_service import hkdf_derive

logger = logging.getLogger(__name__)

KeyKind = Literal["aes", "hmac"]


# PKCS#11 can't use a generic secret as an AES key, so every version has two
# objects: oin-<oin>-rp-v<version>-hmac and oin-<oin>-rp-v<version>-aes.
@dataclass(frozen=True)
class ReversibleKeyLabel:
    oin: Oin
    version: int
    kind: KeyKind

    def __str__(self) -> str:
        # Always the bare 20-character OIN, also for a RecipientOrganizationOin
        # whose str() carries the "oin:" prefix, so that the label matches the
        # one the cleanup derives from the stored organization.
        return f"oin-{self.oin.value}-rp-v{self.version}-{self.kind}"


def reversible_key_labels(oin: Oin, version: int) -> tuple[ReversibleKeyLabel, ...]:
    return (
        ReversibleKeyLabel(oin, version, "aes"),
        ReversibleKeyLabel(oin, version, "hmac"),
    )


class ReversibleKeyOperations(Protocol):
    """Keys are created on first use by hmac/encrypt; decrypt never creates
    them, since a missing key there means the pseudonym cannot be genuine."""

    def hmac(self, oin: Oin, version: int, data: bytes) -> bytes:
        """HMAC-SHA256 with the organization/version HMAC key."""
        ...

    def encrypt(self, oin: Oin, version: int, iv: bytes, data: bytes) -> bytes:
        """AES-256-CBC with PKCS#7 padding under the organization/version AES key."""
        ...

    def decrypt(self, oin: Oin, version: int, iv: bytes, data: bytes) -> bytes: ...


class LocalReversibleKeyOperations:
    """HKDF from the master key. Development and tests only."""

    def __init__(self, master_key: bytes) -> None:
        self._master_key = master_key

    def _key(self, oin: Oin, version: int, kind: KeyKind) -> bytes:
        info = f"prs:rp:{kind}:{oin.value}:v{version}".encode()
        return hkdf_derive(self._master_key, info, 32)

    def hmac(self, oin: Oin, version: int, data: bytes) -> bytes:
        return hmac.new(self._key(oin, version, "hmac"), data, hashlib.sha256).digest()

    def encrypt(self, oin: Oin, version: int, iv: bytes, data: bytes) -> bytes:
        padder = padding.PKCS7(128).padder()
        padded = padder.update(data) + padder.finalize()
        encryptor = Cipher(
            algorithms.AES(self._key(oin, version, "aes")), modes.CBC(iv)
        ).encryptor()
        return encryptor.update(padded) + encryptor.finalize()

    def decrypt(self, oin: Oin, version: int, iv: bytes, data: bytes) -> bytes:
        decryptor = Cipher(
            algorithms.AES(self._key(oin, version, "aes")), modes.CBC(iv)
        ).decryptor()
        padded = decryptor.update(data) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()


class HsmReversibleKeyOperations:
    def __init__(self, client: HsmClient) -> None:
        self._client = client

    def _with_keys(
        self, oin: Oin, version: int, operation: Callable[[], bytes]
    ) -> bytes:
        """Run the operation; on the first use of a key version create the keys
        and run it once more. Saves a lookup round trip on every other call."""
        try:
            return operation()
        except HsmKeyNotFound:
            self._create_keys(oin, version)
            return operation()

    def _create_keys(self, oin: Oin, version: int) -> None:
        for label in reversible_key_labels(oin, version):
            if label.kind == "aes":
                created = self._client.generate_aes_key(str(label))
            else:
                created = self._client.generate_secret_key(str(label))
            if not created:
                # Another instance won the race; its key is the one we use.
                continue
            # PRS-KEY-001: reversible pseudonym keys are generated lazily on first use.
            gflog.emit(
                logger,
                Log.KEY_GENERATED,
                "reversible pseudonym key generated in HSM",
                fields={
                    "sleuteltype": SLEUTELTYPE_REVERSIBLE_KEY,
                    "organisatie_oin": oin.value,
                    "secret_id": str(label),
                    "sleutel_versie": version,
                },
            )

    def hmac(self, oin: Oin, version: int, data: bytes) -> bytes:
        label = str(ReversibleKeyLabel(oin, version, "hmac"))
        return self._with_keys(oin, version, lambda: self._client.hmac(label, data))

    def encrypt(self, oin: Oin, version: int, iv: bytes, data: bytes) -> bytes:
        label = str(ReversibleKeyLabel(oin, version, "aes"))
        return self._with_keys(
            oin, version, lambda: self._client.encrypt(label, iv, data)
        )

    def decrypt(self, oin: Oin, version: int, iv: bytes, data: bytes) -> bytes:
        return self._client.decrypt(
            str(ReversibleKeyLabel(oin, version, "aes")), iv, data
        )
