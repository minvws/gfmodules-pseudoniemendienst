import base64
from typing import Any, Protocol, Self

from cryptography import x509
from cryptography.hazmat.bindings._rust import PublicFormat
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
from cryptography.hazmat.primitives.serialization import Encoding
from jwcrypto.jwk import JWK

from app.config import ConfigHsm, ConfigJwks
from app.services.hsm.client import HsmClient
from app.services.http_service import HttpService
from app.utils.certs import load_cert


class JwksKeyService(Protocol):
    def get_jwks(self) -> dict[str, Any]: ...


class JwksLocalKeysService:
    def __init__(
        self,
        active_signing_key_file: list[list[x509.Certificate]],
    ) -> None:
        self.active_signing_keys = active_signing_key_file

    def get_jwks(self) -> dict[str, Any]:
        jwks = [
            self.make_jwk(certs, "sig", "PS256").export_public(as_dict=True)
            for certs in self.active_signing_keys
        ]
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
        if not config.active_signing_key_files:
            raise ValueError("`active_signing_key_files` is missing from config [jwks]")

        active_keys = [load_cert(file) for file in config.active_signing_key_files]
        return cls(
            active_signing_key_file=active_keys,
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
            jwks.append(signing_jwk.export_public(as_dict=True))

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
    def from_config(cls, hsm_config: ConfigHsm, jwks_config: ConfigJwks) -> Self:
        if hsm_config.url is None:
            raise ValueError("Missing `url` in [hsm] config")

        if not jwks_config.active_hsm_key_labels:
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
    def create(jwks_config: ConfigJwks, hsm_config: ConfigHsm) -> JwksKeyService:
        both_options_enabled = (
            len(jwks_config.active_hsm_key_labels) > 0
            and len(jwks_config.active_signing_key_files) > 0
        )
        if both_options_enabled:
            raise ValueError(
                "Cannot use both hsm and local options, only one can be used. Keep values only for config you wish to use."
            )

        if jwks_config.active_hsm_key_labels:
            return JwksHsmKeysService.from_config(hsm_config, jwks_config)

        return JwksLocalKeysService.from_config(jwks_config)
