import base64
from typing import Any, Protocol, Self

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from jwcrypto.jwk import JWK

from app.config import ConfigJkws
from app.utils.certs import load_cert


def _from_pem(data: bytes, use: str, alg: str) -> JWK:
    obj = JWK.from_pem(data)
    cert = x509.load_pem_x509_certificate(data)
    der = cert.public_bytes(Encoding.DER)
    x5c = base64.b64encode(der).decode()
    obj.update(use=use, alg=alg, x5c=[x5c])

    return obj


class JwksKeyService(Protocol):
    def get_jwks(self) -> dict[str, Any]: ...

    @staticmethod
    def from_pem(data: bytes, use: str, alg: str) -> JWK: ...


class JwksLocalKeyService:
    def __init__(
        self,
        signing_cert_path: str,
        decryption_cert_path: str,
    ) -> None:
        self.signing_cert = load_cert(signing_cert_path)
        self.decryption_cert = load_cert(decryption_cert_path)

    def get_jwks(self) -> Any:
        jwks = []
        signing_jwk = self.from_pem(self.signing_cert, "sig", "RSA256")
        jwks.append(signing_jwk)

        decryption_jwk = self.from_pem(self.decryption_cert, "enc", "RSA256")
        jwks.append(decryption_jwk)

        return {"keys": jwks}

    @staticmethod
    def from_pem(data: bytes, use: str, alg: str) -> JWK:
        return _from_pem(data, use, alg)

    @classmethod
    def from_config(cls, config: ConfigJkws) -> Self:
        if config.signing_cert_path is None or config.decryption_cert_path is None:
            raise RuntimeError(
                "`signing_cert_path` or `decryption_cert_path` cannot be empty when using local key setting for JWKS"
            )

        return cls(
            signing_cert_path=config.signing_cert_path,
            decryption_cert_path=config.decryption_cert_path,
        )
