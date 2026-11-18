"""Provision RSA-4096 JWT-signing pairs without database access or app startup.

JWT_SIGNING_ENABLED must be true/false; false needs no other configuration.
When enabled, require JWT_SIGNING_HSM_KEY_LABELS (comma-separated) and
JWT_SIGNING_HSM_ACTIVE_KEY_LABEL (must appear in the list), plus HSMAPI_URL
(HTTPS), HSMAPI_MODULE, HSMAPI_SLOT, HSM_CERT, HSM_KEY and HSM_CA.
The mTLS identity needs HSM lookup/create rights for the configured labels.

Existing keys are reused, never replaced; organization keys are not provisioned.
After an uncertain generation outcome, rerun with the same labels, one run at a time.
Exit 0 on success/disabled signing, 1 with a fixed redacted diagnostic code.
"""

import os
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import quote, urlsplit

import requests
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class ProvisioningError(Exception):
    """Configuration or HSM state is unsafe for provisioning."""


class ConfigurationError(ProvisioningError):
    """Required configuration is invalid."""


class HsmRequestError(ProvisioningError):
    """An HSM request failed or has an uncertain outcome."""


class HsmObjectError(ProvisioningError):
    """Returned HSM objects cannot safely be used."""


@dataclass(frozen=True, repr=False)
class Config:
    url: str
    module: str
    slot: str
    cert: str
    key: str
    ca: str
    labels: tuple[str, ...]
    active_label: str

    @classmethod
    def from_env(cls, environ: Mapping[str, str]) -> "Config | None":
        enabled = environ.get("JWT_SIGNING_ENABLED", "").strip().lower()
        if enabled not in {"true", "false"}:
            raise ConfigurationError(
                "JWT_SIGNING_ENABLED must be explicitly true or false"
            )
        if enabled == "false":
            return None

        def required(name: str) -> str:
            value = environ.get(name, "").strip()
            if not value:
                raise ConfigurationError(f"Missing required setting: {name}")
            return value

        labels = tuple(
            label.strip() for label in required("JWT_SIGNING_HSM_KEY_LABELS").split(",")
        )
        if not all(labels) or len(set(labels)) != len(labels):
            raise ConfigurationError("Signing labels must be nonempty and unique")
        active_label = required("JWT_SIGNING_HSM_ACTIVE_KEY_LABEL")
        if active_label not in labels:
            raise ConfigurationError(
                "The active signing label must be in the label list"
            )

        url = required("HSMAPI_URL")
        try:
            parsed = urlsplit(url)
            valid_url = (
                parsed.scheme == "https"
                and bool(parsed.hostname)
                and parsed.username is None
                and parsed.password is None
                and parsed.port != 0
                and "?" not in url
                and "#" not in url
                and not any(char.isspace() or ord(char) < 32 for char in url)
            )
        except ValueError:
            valid_url = False
        if not valid_url:
            raise ConfigurationError(
                "HSMAPI_URL must be HTTPS without credentials or query"
            )

        module = required("HSMAPI_MODULE")
        slot = required("HSMAPI_SLOT")
        if module in {".", ".."} or slot in {".", ".."}:
            raise ConfigurationError(
                "HSM module and slot must not be dot path segments"
            )
        return cls(
            url=url,
            module=module,
            slot=slot,
            cert=required("HSM_CERT"),
            key=required("HSM_KEY"),
            ca=required("HSM_CA"),
            labels=labels,
            active_label=active_label,
        )


def _post(
    session: requests.Session,
    config: Config,
    url: str,
    payload: dict[str, str | int],
) -> dict[str, object]:
    try:
        response = session.post(
            url,
            json=payload,
            cert=(config.cert, config.key),
            verify=config.ca,
            timeout=(10, 30),
            allow_redirects=False,
        )
        # raise_for_status alone would accept redirects.
        if not 200 <= response.status_code < 300:
            raise HsmRequestError("HSM request returned an unsuccessful status")
        data: object = response.json()
    except (requests.RequestException, OSError, ValueError):
        raise HsmRequestError("HSM request or JSON decoding failed") from None
    if not isinstance(data, dict) or any(
        field in data for field in ("error", "error_description", "detail")
    ):
        raise HsmRequestError("HSM returned an invalid response or API error")
    return data


def _rsa_pair(objects: object, label: str, *, allow_absent: bool = False) -> bool:
    if not isinstance(objects, list):
        raise HsmObjectError("HSM object list is missing or malformed")
    if not objects and allow_absent:
        return False
    if len(objects) != 2:
        raise HsmObjectError("Expected exactly one complete RSA key pair")

    classes: set[str] = set()
    identities: set[str] = set()
    moduli: set[int] = set()
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("LABEL") != label:
            raise HsmObjectError("HSM object does not match the exact label")
        obj_class = obj.get("CLASS")
        if (
            not isinstance(obj_class, str)
            or obj_class not in {"PUBLIC_KEY", "PRIVATE_KEY"}
            or obj.get("KEY_TYPE") != "RSA"
        ):
            raise HsmObjectError("HSM object is not an RSA public or private key")
        classes.add(obj_class)
        identity = obj.get("ID")
        # CKA_ID is hex-encoded by the API; the default empty ID is valid.
        if (
            not isinstance(identity, str)
            or re.fullmatch(r"(?:[0-9a-fA-F]{2})*", identity) is None
        ):
            raise HsmObjectError("HSM key identity is missing or malformed")
        identities.add(identity.lower())
        if "MODULUS_BITS" in obj and (
            type(obj["MODULUS_BITS"]) is not int or obj["MODULUS_BITS"] != 4096
        ):
            raise HsmObjectError("HSM key size must be RSA-4096")
        if "MODULUS" in obj:
            modulus = obj["MODULUS"]
            if (
                not isinstance(modulus, str)
                or re.fullmatch(r"(?:[0-9a-fA-F]{2})+", modulus) is None
            ):
                raise HsmObjectError("HSM RSA modulus is malformed")
            number = int(modulus, 16)
            if number.bit_length() != 4096:
                raise HsmObjectError("HSM key size must be RSA-4096")
            moduli.add(number)
        if "publickey" in obj:
            pem = obj["publickey"]
            if not isinstance(pem, str):
                raise HsmObjectError("HSM public key is malformed")
            try:
                public_key = serialization.load_pem_public_key(pem.encode("ascii"))
            except (ValueError, UnsupportedAlgorithm):
                raise HsmObjectError("HSM public key is malformed") from None
            if (
                not isinstance(public_key, rsa.RSAPublicKey)
                or public_key.key_size != 4096
            ):
                raise HsmObjectError("HSM public key must be RSA-4096")
            moduli.add(public_key.public_numbers().n)
    if (
        classes != {"PUBLIC_KEY", "PRIVATE_KEY"}
        or len(identities) != 1
        or len(moduli) > 1
    ):
        raise HsmObjectError("HSM key pair is ambiguous or has conflicting identities")
    return True


def provision(config: Config) -> None:
    endpoint = (
        f"{config.url.rstrip('/')}/hsm/"
        f"{quote(config.module, safe='')}/{quote(config.slot, safe='')}"
    )
    with requests.Session() as session:
        # Explicit mTLS/CA settings must not be replaced by proxy, netrc, or
        # CA-bundle environment defaults.
        session.trust_env = False
        missing = []
        # Check every label before making any changes.
        for label in config.labels:
            data = _post(session, config, endpoint, {"label": label})
            if not _rsa_pair(data.get("objects"), label, allow_absent=True):
                missing.append(label)
        for label in missing:
            data = _post(
                session,
                config,
                f"{endpoint}/generate/rsa",
                {"label": label, "bits": 4096},
            )
            _rsa_pair(data.get("result"), label)


def main(environ: Mapping[str, str] | None = None) -> int:
    try:
        config = Config.from_env(os.environ if environ is None else environ)
        if config is not None:
            provision(config)
    except Exception as error:  # noqa: BLE001 - redact unexpected failures at the CLI boundary
        # Classify by trusted exception types, never their messages or attributes.
        codes: dict[type[Exception], str] = {
            ConfigurationError: "CONFIG_INVALID",
            HsmRequestError: "HSM_REQUEST_FAILED",
            HsmObjectError: "HSM_OBJECT_INVALID",
        }
        code = codes.get(type(error), "UNEXPECTED_ERROR")
        print(f"PRS JWT-signing key provisioning failed [{code}].", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
