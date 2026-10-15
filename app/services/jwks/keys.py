import base64
from typing import Any, Protocol, Self

from cryptography import x509
from cryptography.hazmat.bindings._rust import PublicFormat
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
from cryptography.hazmat.primitives.serialization import Encoding
from jwcrypto.jwk import JWK

from app.config import Config, ConfigJwks
from app.services.hsm.client import HsmClient
from app.services.http_service import HttpService
from app.utils.certs import load_cert


class JwksKeyService(Protocol):
    def get_jwks(self) -> dict[str, Any]: ...


class JwksLocalKeysService:
    def __init__(
        self,
        active_signing_key_file: list[str],
    ) -> None:
        self.active_signing_key_files = active_signing_key_file

    def get_jwks(self) -> dict[str, Any]:
        jwks = []
        for cert_file in self.active_signing_key_files:
            cert = load_cert(cert_file)
            jwk = self.make_jwk(cert, "sig", "PS256")
            jwks.append(jwk.export_public())

        return {"keys": jwks}

    @staticmethod
    def make_jwk(cert: list[x509.Certificate], use: str, alg: str) -> JWK:
        leaf, *intermediate = cert
        pub_key = leaf.public_key()
        if not isinstance(pub_key, RSAPublicKey):
            raise TypeError("Only RSAPublicKey type is supported")

        jwk = JWK.from_pyca(pub_key)
        kid = jwk.thumbprint()
        x5c = [
            base64.b64encode(c.public_bytes(Encoding.DER)).decode()
            for c in [leaf, *intermediate]
        ]
        jwk.update(use=use, alg=alg, kid=kid, x5c=x5c)

        return jwk

    @classmethod
    def from_config(cls, config: ConfigJwks) -> Self:
        if config.active_signing_key_files is None:
            raise ValueError("`active_signing_key_files` is missing from config [jwks]")

        return cls(
            active_signing_key_file=config.active_signing_key_files,
        )


class JwksHsmKeysService:
    def __init__(self, http_service: HttpService, active_hsm_label: list[str]) -> None:
        self.hsm_client = HsmClient(http=http_service)
        self.active_hsm_label = active_hsm_label

    def get_jwks(self) -> dict[str, Any]:
        jwks = []
        for label in self.active_hsm_label:
            signing_key = self.hsm_client.get_public_key_pem(label)

            signing_jwk = self.make_jwk(signing_key, "sig", "PS256")
            jwks.append(signing_jwk.export_public())

        return {"keys": jwks}

    @staticmethod
    def make_jwk(data: PublicKeyTypes, use: str, alg: str) -> JWK:
        obj = JWK.from_pem(
            data.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        )
        kid = obj.thumbprint()
        obj.update(kid=kid, alg=alg, use=use)

        return obj

    @classmethod
    def from_config(cls, config: Config) -> Self:
        hsm_config = config.hsm
        jwks_config = config.jwks
        if hsm_config.url is None:
            raise ValueError("Missing `url` in [hsm] config")

        if jwks_config.active_hsm_key_labels is None:
            raise ValueError("Missing `active_hsm_key_labels` in [jwks] config")

        http_service = HttpService(
            endpoint=hsm_config.url,
            timeout=hsm_config.timeout,
            mtls_cert=hsm_config.cert_file,
            mtls_key=hsm_config.key_file,
        )

        return cls(
            http_service=http_service,
            active_hsm_label=jwks_config.active_hsm_key_labels,
        )


class JwksKeysServiceFactory:
    @staticmethod
    def create(config: Config) -> JwksKeyService:
        jwks_config = config.jwks
        both_options_enabled = (
            jwks_config.active_hsm_key_labels and jwks_config.active_signing_key_files
        )
        if both_options_enabled:
            raise ValueError(
                "Cannot use both hsm and local options, only one can be used. Keep values only for config you wish to use."
            )

        if jwks_config.active_hsm_key_labels:
            return JwksHsmKeysService.from_config(config)

        return JwksLocalKeysService.from_config(jwks_config)
