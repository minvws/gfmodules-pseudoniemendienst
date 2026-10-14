import hashlib
import logging
from dataclasses import dataclass
from typing import Any, Protocol, Self

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from jwcrypto import jwk

from app.config import ConfigJwtSigning
from app.services.hsm.client import HsmClient

logger = logging.getLogger(__name__)

ALG_PS256 = "PS256"
MIN_RSA_KEY_BITS = 3072
PSS_SALT_BYTES = 32


class JwtSigner(Protocol):
    """Signs the JWS signing input (``b64url(header).b64url(payload)``)."""

    @property
    def kid(self) -> str: ...

    @property
    def alg(self) -> str: ...

    def sign(self, signing_input: bytes) -> bytes: ...

    def public_jwk(self) -> dict[str, Any]:
        """The public key as a JWK, for publishing in the JWKS."""
        ...


class _Ps256Signer:
    """The public half shared by the PS256 signers: key checks, kid and JWK."""

    def __init__(self, public_key: rsa.RSAPublicKey, name: str) -> None:
        if public_key.key_size < MIN_RSA_KEY_BITS:
            raise ValueError(
                f"RSA signing key {name} is {public_key.key_size} bits; at least "
                f"{MIN_RSA_KEY_BITS} bits are required."
            )
        self._public_jwk = jwk.JWK.from_pyca(public_key)
        self._kid: str = self._public_jwk.thumbprint()

    @property
    def kid(self) -> str:
        return self._kid

    @property
    def alg(self) -> str:
        return ALG_PS256

    def public_jwk(self) -> dict[str, Any]:
        return {
            **self._public_jwk.export_public(as_dict=True),
            "kid": self._kid,
            "alg": ALG_PS256,
            "use": "sig",
        }


class LocalJwtSigner(_Ps256Signer):
    """PS256 signer with an RSA private key held in process memory."""

    def __init__(self, private_key: rsa.RSAPrivateKey, name: str = "") -> None:
        super().__init__(private_key.public_key(), name)
        self._private_key = private_key

    @classmethod
    def from_pem_file(cls, path: str) -> Self:
        try:
            with open(path, "rb") as f:
                pem = f.read()
        except FileNotFoundError:
            raise FileNotFoundError(f"JWT signing key file not found: {path}")
        private_key = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise TypeError(f"JWT signing key {path} is not an RSA private key.")
        return cls(private_key, path)

    def sign(self, signing_input: bytes) -> bytes:
        return self._private_key.sign(
            signing_input,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=PSS_SALT_BYTES,
            ),
            hashes.SHA256(),
        )


class HsmJwtSigner(_Ps256Signer):
    """PS256 signer with the private key in the HSM, addressed by label."""

    def __init__(self, hsm: HsmClient, label: str) -> None:
        public_key = serialization.load_pem_public_key(
            hsm.public_key_pem(label).encode("ascii")
        )
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise TypeError(f"JWT signing key {label!r} in the HSM is not an RSA key.")
        super().__init__(public_key, repr(label))
        self._hsm = hsm
        self._label = label

    def sign(self, signing_input: bytes) -> bytes:
        digest = hashlib.sha256(signing_input).digest()
        return self._hsm.sign_rsa_pss_sha256(self._label, digest)


@dataclass(frozen=True)
class JwtSigningKeys:
    """
    All configured signing keys. Only ``active`` signs; the others stay
    published so tokens they signed can still be verified during rotation.
    """

    issuer: str
    active: JwtSigner
    signers: tuple[JwtSigner, ...]

    @classmethod
    def from_config(cls, config: ConfigJwtSigning, hsm: HsmClient | None) -> Self:
        if not config.issuer:
            raise ValueError(
                "jwt_signing.issuer is not configured. It is required when "
                "enable_jwt_signing is set."
            )
        if not config.key_files and not config.hsm_key_labels:
            raise ValueError(
                "jwt_signing.key_files or jwt_signing.hsm_key_labels is not "
                "configured. It is required when enable_jwt_signing is set."
            )
        if bool(config.active_key_file) == bool(config.active_key_label):
            raise ValueError(
                "Set exactly one of jwt_signing.active_key_file and "
                "jwt_signing.active_key_label."
            )
        if config.active_key_file and config.active_key_file not in config.key_files:
            raise ValueError(
                "jwt_signing.active_key_file must be one of jwt_signing.key_files."
            )
        if (
            config.active_key_label
            and config.active_key_label not in config.hsm_key_labels
        ):
            raise ValueError(
                "jwt_signing.active_key_label must be one of "
                "jwt_signing.hsm_key_labels."
            )

        signers: dict[str, JwtSigner] = {}

        def add(name: str, signer: JwtSigner) -> None:
            if any(s.kid == signer.kid for s in signers.values()):
                raise ValueError(
                    f"JWT signing key {name} is configured more than once."
                )
            signers[name] = signer

        for path in config.key_files:
            add(path, LocalJwtSigner.from_pem_file(path))
        if config.hsm_key_labels:
            if hsm is None:
                raise ValueError(
                    "jwt_signing.hsm_key_labels needs the HSM to be configured."
                )
            for label in config.hsm_key_labels:
                add(label, HsmJwtSigner(hsm, label))

        active = signers[config.active_key_file or config.active_key_label]
        logger.info(
            "JWT signing enabled with %d key(s), active kid %s",
            len(signers),
            active.kid,
        )
        return cls(issuer=config.issuer, active=active, signers=tuple(signers.values()))

    def public_jwks(self) -> list[dict[str, Any]]:
        return [signer.public_jwk() for signer in self.signers]
