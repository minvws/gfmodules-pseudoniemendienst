from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def hkdf_derive(master_key: bytes, info: bytes, length: int = 32) -> bytes:
    """This function is only for local development and tests without HSM.
    Used by `LocalReversibleKeyOperations` and `LocalIrreversibleKeyOperations`"""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    )
    return hkdf.derive(master_key)
