import hashlib
import hmac
from dataclasses import dataclass
from typing import Literal, Protocol

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from app.models.oin import Oin
from app.services.hsm.client import HsmClient
from app.services.pseudonym_service import hkdf_derive

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
    def ensure_keys(self, oin: Oin, version: int) -> None:
        """Make sure the keys for this organization/version exist."""
        ...

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

    def ensure_keys(self, oin: Oin, version: int) -> None:
        return None

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

    def ensure_keys(self, oin: Oin, version: int) -> None:
        for label in reversible_key_labels(oin, version):
            if self._client.label_exists(str(label)):
                continue
            if label.kind == "aes":
                self._client.generate_aes_key(str(label))
            else:
                self._client.generate_secret_key(str(label))

    def hmac(self, oin: Oin, version: int, data: bytes) -> bytes:
        return self._client.hmac(str(ReversibleKeyLabel(oin, version, "hmac")), data)

    def encrypt(self, oin: Oin, version: int, iv: bytes, data: bytes) -> bytes:
        return self._client.encrypt(
            str(ReversibleKeyLabel(oin, version, "aes")), iv, data
        )

    def decrypt(self, oin: Oin, version: int, iv: bytes, data: bytes) -> bytes:
        return self._client.decrypt(
            str(ReversibleKeyLabel(oin, version, "aes")), iv, data
        )
