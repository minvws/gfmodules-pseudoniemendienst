import base64
from typing import Any, Protocol, Self, cast

from cryptography import x509
from cryptography.hazmat.bindings._rust import PublicFormat
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, load_pem_public_key
from jwcrypto.jwk import JWK

from app.config import ConfigJwks
from app.services.hsm.client import HsmClient
from app.services.http_service import HttpService
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
    def make_jwk(data: list[x509.Certificate], use: str, alg: str) -> JWK: ...


class JwksLocalKeyService:
    def __init__(self, active_key_file: str) -> None:
        self.active_key_files = active_key_file

    def get_jwks(self) -> Any:
        cert_file = self.active_key_files
        cert = load_cert(cert_file)
        jwk = self.make_jwk(cert, "sig", "RSA-PSS")

        return {"keys": [jwk]}

    @staticmethod
    def make_jwk(cert: list[x509.Certificate], use: str, alg: str) -> JWK:
        leaf, *intermediate = cert
        pub_key = leaf.public_key()
        jwk = JWK.from_pyca(cast(RSAPrivateKey, pub_key))
        jwk.update(use=use)
        jwk.update(alg=alg)
        x5c = [
            base64.b64encode(c.public_bytes(Encoding.DER)).decode()
            for c in [leaf, *intermediate]
        ]
        jwk.update(x5c=x5c)

        return jwk

    @classmethod
    def from_config(cls, config: ConfigJwks) -> Self:
        if not config.key_files and not config.active_key_file:
            raise RuntimeError(
                "JwksLocalKeyService cannot be instantianted without at key_files available"
            )

        return cls(active_key_file=config.active_key_file)


class JwksHsmKeyService:
    def __init__(self, http_service: HttpService, active_hsm_label: str) -> None:
        self.hsm_client = HsmClient(http=http_service)
        self.active_hsm_label = active_hsm_label

    def get_jwks(self) -> Any:
        signing_key = self.hsm_client.get_public_key_pem(self.active_hsm_label)

        signing_jwk = self.make_jwk(signing_key.encode(), "sig", "RSA-PSS")

        return {"keys": [signing_jwk]}

    @staticmethod
    def make_jwk(data: bytes, use: str, alg: str) -> JWK:
        obj = JWK.from_pem(data)
        key = load_pem_public_key(data)
        der = key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        x5c = base64.b64encode(der).decode()
        obj.update(use=use, alg=alg, x5c=[x5c])
        return obj
